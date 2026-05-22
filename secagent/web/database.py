"""SQLite database setup with SQLAlchemy."""

from __future__ import annotations

import os
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

DB_PATH = Path(os.environ.get("SECAGENT_DB", "secagent.db"))
DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
    echo=False,
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


def get_db():
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create all tables and seed default data."""
    from secagent.web import models  # noqa: F401 — registers models
    Base.metadata.create_all(bind=engine)
    # ── Migrate existing DBs: add columns that may not exist yet ──────────────
    from sqlalchemy import inspect as _inspect, text as _text
    inspector = _inspect(engine)
    existing_project_cols = {c["name"] for c in inspector.get_columns("projects")}
    _migrations = {
        "conversation_snapshot": "ALTER TABLE projects ADD COLUMN conversation_snapshot TEXT DEFAULT ''",
    }
    with engine.connect() as _conn:
        for col, stmt in _migrations.items():
            if col not in existing_project_cols:
                _conn.execute(_text(stmt))
        _conn.commit()
    _seed_defaults()


def _seed_defaults() -> None:
    """Insert default settings and built-in agents/tools/MCPs if the DB is freshly created."""
    from secagent.web.models import AgentModel, MCPServer, Setting, ToolDef

    db: Session = SessionLocal()
    try:
        # ── Settings ──────────────────────────────────────────────────────────
        _DEFAULT_SETTINGS = {
            "theme": "light",
            "provider": "anthropic",
            "model": "claude-opus-4-5-20250929",
            "api_key": "",
            "base_url": "",
            "strategy_guard_enabled": "true",
            "strategy_repeat_call_limit": "5",
            "strategy_no_progress_limit": "12",
            "strategy_browser_cooldown_rounds": "6",
            "strategy_browser_ratio_limit_pct": "80",
        }
        existing_keys = {r.key for r in db.query(Setting).all()}
        for _k, _v in _DEFAULT_SETTINGS.items():
            if _k not in existing_keys:
                db.add(Setting(key=_k, value=_v))

        # ── Built-in Agents ───────────────────────────────────────────────────
        if not db.query(AgentModel).first():
            from secagent.prompts.sigma_single import SIGMA_SINGLE_AGENT_PROMPT

            db.add_all([
                AgentModel(
                    name="sigmaAI",
                    description="专业网络安全渗透测试专家 (单智能体模式) — 集成全部安全工具",
                    mode="single",
                    system_prompt=SIGMA_SINGLE_AGENT_PROMPT,
                    tools_json='["dns_lookup","port_scan","whois_lookup","fetch_http_headers",'
                               '"http_request","detect_waf","crawl_links","check_common_vulns",'
                               '"scan_xss","scan_sqli","scan_ssrf","fuzz_paths","extract_js_endpoints","test_idor"]',
                    mcps_json="[]",
                ),
                AgentModel(
                    name="ReconAgent",
                    description="侦察专用智能体 — DNS/WHOIS/端口扫描/WAF 检测/链接爬取",
                    mode="single",
                    system_prompt=(
                        "你是一名专业的渗透测试侦察专家。你的任务是对目标进行全面的信息收集，"
                        "包括 DNS 查询、WHOIS 查询、端口扫描、WAF 检测和链接爬取。"
                        "请用中文输出结构化的侦察报告。"
                    ),
                    tools_json='["dns_lookup","port_scan","whois_lookup","detect_waf","crawl_links"]',
                    mcps_json="[]",
                ),
                AgentModel(
                    name="VulnAgent",
                    description="漏洞评估专用智能体 — HTTP 头检测/路径探测/版本披露/常见漏洞扫描",
                    mode="single",
                    system_prompt=(
                        "你是一名专业的 Web 漏洞评估专家。你的任务是对目标进行全面的漏洞扫描，"
                        "重点关注安全头配置、暴露路径、版本信息泄露和常见漏洞。"
                        "请用中文输出结构化的漏洞报告，包含风险等级和修复建议。"
                    ),
                    tools_json='["fetch_http_headers","http_request","detect_waf","check_common_vulns","port_scan"]',
                    mcps_json="[]",
                ),
                AgentModel(
                    name="BrowserAgent",
                    description="浏览器自动化智能体 — 通过 Browser MCP 控制 Chrome 浏览器",
                    mode="single",
                    system_prompt=(
                        "你是一名专业的 Web 浏览器自动化专家。"
                        "你可以控制 Chrome 浏览器进行导航、截图、表单填写、JS 执行等操作。"
                        "请仔细分析用户的需求，安全地完成浏览器自动化任务。"
                    ),
                    tools_json="[]",
                    mcps_json='["browser-mcp"]',
                ),
                AgentModel(
                    name="WebHackAgent",
                    description="Web 漏洞挑战专用智能体 — XSS/SQLi/SSRF/越权/路径模糊/JS分析",
                    mode="single",
                    system_prompt=(
                        "你是一名专业的 Web 漏洞挖掘专家，擅长发现 XSS、SQL 注入、SSRF、"
                        "越权（IDOR）、路径遭历、JS 文件信息泄露等 Web 安全漏洞。"
                        "请先使用信息收集工具了解目标，再逐一测试各类漏洞。用中文输出详细的漏洞报告。"
                    ),
                    tools_json='["fetch_http_headers","http_request","crawl_links","detect_waf",'
                               '"scan_xss","scan_sqli","scan_ssrf","fuzz_paths",'
                               '"extract_js_endpoints","test_idor","check_common_vulns"]',
                    mcps_json="[]",
                ),
            ])

        # ── Built-in Tools ────────────────────────────────────────────────────
        if not db.query(ToolDef).first():
            _BUILTIN_TOOLS = [
                {
                    "name": "dns_lookup",
                    "description": "DNS 查询 — 支持 A/MX/TXT/NS/CNAME 等记录类型",
                    "code": (
                        "from secagent.tools.network_tools import dns_lookup\n"
                        "# 用法: dns_lookup(hostname='example.com', record_types=['A','MX','TXT'])"
                    ),
                    "enabled": True,
                },
                {
                    "name": "port_scan",
                    "description": "TCP 端口扫描 — 探测目标主机开放端口",
                    "code": (
                        "from secagent.tools.network_tools import port_scan\n"
                        "# 用法: port_scan(host='192.168.1.1', ports=[80,443,22,8080])"
                    ),
                    "enabled": True,
                },
                {
                    "name": "whois_lookup",
                    "description": "WHOIS 查询 — 获取域名注册信息",
                    "code": (
                        "from secagent.tools.network_tools import whois_lookup\n"
                        "# 用法: whois_lookup(target='example.com')"
                    ),
                    "enabled": True,
                },
                {
                    "name": "fetch_http_headers",
                    "description": "获取 HTTP 响应头 — 检测安全头配置缺失",
                    "code": (
                        "from secagent.tools.web_tools import fetch_http_headers\n"
                        "# 用法: fetch_http_headers(url='https://example.com')"
                    ),
                    "enabled": True,
                },
                {
                    "name": "http_request",
                    "description": "通用 HTTP 请求 — 支持 GET/POST/PUT/DELETE 等方法",
                    "code": (
                        "from secagent.tools.web_tools import http_request\n"
                        "# 用法: http_request(url='https://example.com/api', method='POST', body='{...}')"
                    ),
                    "enabled": True,
                },
                {
                    "name": "detect_waf",
                    "description": "WAF 检测 — 识别 Cloudflare/AWS WAF/Akamai 等防护",
                    "code": (
                        "from secagent.tools.web_tools import detect_waf\n"
                        "# 用法: detect_waf(url='https://example.com')"
                    ),
                    "enabled": True,
                },
                {
                    "name": "crawl_links",
                    "description": "链接爬取 — 抓取页面所有内/外部链接",
                    "code": (
                        "from secagent.tools.web_tools import crawl_links\n"
                        "# 用法: crawl_links(url='https://example.com', max_links=50)"
                    ),
                    "enabled": True,
                },
                {
                    "name": "check_common_vulns",
                    "description": "常见漏洞检测 — 探测敏感路径/版本泄露/常见配置错误",
                    "code": (
                        "from secagent.tools.web_tools import check_common_vulns\n"
                        "# 用法: check_common_vulns(target_url='https://example.com')"
                    ),
                    "enabled": True,
                },
                {
                    "name": "scan_xss",
                    "description": "XSS 扫描 — 测试 URL 参数是否存在反射型 XSS 漏洞",
                    "code": "from secagent.tools.pentest_tools import scan_xss",
                    "enabled": True,
                },
                {
                    "name": "scan_sqli",
                    "description": "SQL 注入扫描 — 错误回显和时间瘦2种检测方式",
                    "code": "from secagent.tools.pentest_tools import scan_sqli",
                    "enabled": True,
                },
                {
                    "name": "scan_ssrf",
                    "description": "SSRF 扫描 — 探测服务端请求伪造漏洞，包括 AWS/GCP/阿里云内网元数据路径",
                    "code": "from secagent.tools.pentest_tools import scan_ssrf",
                    "enabled": True,
                },
                {
                    "name": "fuzz_paths",
                    "description": "路径模糊 — 对目标常见目录/文件/API 路径进行探测",
                    "code": "from secagent.tools.pentest_tools import fuzz_paths",
                    "enabled": True,
                },
                {
                    "name": "extract_js_endpoints",
                    "description": "JS 端点提取 — 分析 JS 文件中的 API 路径、密钥和外部链接",
                    "code": "from secagent.tools.pentest_tools import extract_js_endpoints",
                    "enabled": True,
                },
                {
                    "name": "test_idor",
                    "description": "IDOR/越权测试 — 通过切换资源 ID 检测越权访问漏洞",
                    "code": "from secagent.tools.pentest_tools import test_idor",
                    "enabled": True,
                },
            ]
            db.add_all([ToolDef(**t) for t in _BUILTIN_TOOLS])

        # ── Built-in MCP Servers ──────────────────────────────────────────────
        if not db.query(MCPServer).first():
            db.add(MCPServer(
                name="browser-mcp",
                description="Chrome 浏览器控制 MCP — 提供 16 个 Playwright 浏览器工具，"
                            "支持导航/截图/点击/表单填写/JS 执行/请求拦截等",
                command="python3",
                args_json='["-m", "secagent.mcp_servers.browser_server"]',
                env_json="{}",
                enabled=True,
            ))
            db.add(MCPServer(
                name="recon-mcp",
                description="Recon/扫描 MCP — 提供 httpx、katana、nuclei、ffuf、sqlmap 工具封装",
                command="python3",
                args_json='["-m", "secagent.mcp_servers.recon_server"]',
                env_json="{}",
                enabled=False,
            ))

        db.commit()
    finally:
        db.close()


def reseed_builtin() -> dict:
    """Force re-insert built-in tools, agents, and MCPs (idempotent by name)."""
    from secagent.web.models import AgentModel, MCPServer, ToolDef
    from secagent.prompts.sigma_single import SIGMA_SINGLE_AGENT_PROMPT

    db: Session = SessionLocal()
    counts = {"tools": 0, "agents": 0, "mcps": 0}
    try:
        # Tools — insert if name not exists
        _BUILTIN_TOOLS = [
            ("dns_lookup",        "DNS 查询 — 支持 A/MX/TXT/NS/CNAME 等记录类型",
             "from secagent.tools.network_tools import dns_lookup"),
            ("port_scan",         "TCP 端口扫描 — 探测目标主机开放端口",
             "from secagent.tools.network_tools import port_scan"),
            ("whois_lookup",      "WHOIS 查询 — 获取域名注册信息",
             "from secagent.tools.network_tools import whois_lookup"),
            ("fetch_http_headers","获取 HTTP 响应头 — 检测安全头配置缺失",
             "from secagent.tools.web_tools import fetch_http_headers"),
            ("http_request",      "通用 HTTP 请求 — 支持 GET/POST/PUT/DELETE 等方法",
             "from secagent.tools.web_tools import http_request"),
            ("detect_waf",        "WAF 检测 — 识别 Cloudflare/AWS WAF/Akamai 等防护",
             "from secagent.tools.web_tools import detect_waf"),
            ("crawl_links",       "链接爬取 — 抓取页面所有内/外部链接",
             "from secagent.tools.web_tools import crawl_links"),
            ("check_common_vulns","常见漏洞检测 — 探测敏感路径/版本泄露/常见配置错误",
             "from secagent.tools.web_tools import check_common_vulns"),
            ("scan_xss",          "XSS 扫描 — 测试 URL 参数是否存在反射型 XSS 漏洞",
             "from secagent.tools.pentest_tools import scan_xss"),
            ("scan_sqli",         "SQL 注入扫描 — 错误回显和时间盲注两种检测方式",
             "from secagent.tools.pentest_tools import scan_sqli"),
            ("scan_ssrf",         "SSRF 扫描 — 探测服务端请求伪造漏洞，包括云服务元数据路径",
             "from secagent.tools.pentest_tools import scan_ssrf"),
            ("fuzz_paths",        "路径模糊 — 对目标常见目录/文件/API 路径进行探测",
             "from secagent.tools.pentest_tools import fuzz_paths"),
            ("extract_js_endpoints", "JS 端点提取 — 分析 JS 文件中的 API 路径、密钥和外部链接",
             "from secagent.tools.pentest_tools import extract_js_endpoints"),
            ("test_idor",         "IDOR/越权测试 — 通过切换资源 ID 检测越权访问漏洞",
             "from secagent.tools.pentest_tools import test_idor"),
        ]
        existing_tools = {t.name for t in db.query(ToolDef).all()}
        for name, desc, code in _BUILTIN_TOOLS:
            if name not in existing_tools:
                db.add(ToolDef(name=name, description=desc, code=code, enabled=True))
                counts["tools"] += 1

        # Agents — insert if name not exists
        _BUILTIN_AGENTS = [
            ("sigmaAI", "专业网络安全渗透测试专家 (单智能体模式) — 集成全部安全工具",
             SIGMA_SINGLE_AGENT_PROMPT, "single",
             '["dns_lookup","port_scan","whois_lookup","fetch_http_headers","http_request","detect_waf","crawl_links","check_common_vulns","scan_xss","scan_sqli","scan_ssrf","fuzz_paths","extract_js_endpoints","test_idor"]'),
            ("ReconAgent", "侦察专用智能体 — DNS/WHOIS/端口扫描/WAF 检测/链接爬取",
             "你是一名专业的渗透测试侦察专家，负责信息收集。请用中文输出结构化侦察报告。",
             "single", '["dns_lookup","port_scan","whois_lookup","detect_waf","crawl_links"]'),
            ("VulnAgent", "漏洞评估专用智能体 — HTTP 头检测/路径探测/常见漏洞扫描",
             "你是一名专业的 Web 漏洞评估专家，负责漏洞扫描与报告。请用中文输出含风险等级的漏洞报告。",
             "single", '["fetch_http_headers","http_request","detect_waf","check_common_vulns","port_scan"]'),
            ("BrowserAgent", "浏览器自动化智能体 — 通过 Browser MCP 控制 Chrome 浏览器",
             "你是一名专业的 Web 浏览器自动化专家，可控制 Chrome 完成导航/截图/表单/JS 等操作。",
             "single", "[]"),
            ("WebHackAgent", "Web 漏洞挖掘专用智能体 — XSS/SQLi/SSRF/越权/路径模糊/JS分析",
             "你是一名专业的 Web 漏洞挖掘专家，擅长发现 XSS、SQL 注入、SSRF、越权（IDOR）、路径遍历、JS 文件信息泄露等 Web 安全漏洞。请先使用信息收集工具了解目标，再逐一测试各类漏洞。用中文输出详细的漏洞报告。",
             "single", '["fetch_http_headers","http_request","crawl_links","detect_waf","scan_xss","scan_sqli","scan_ssrf","fuzz_paths","extract_js_endpoints","test_idor","check_common_vulns"]'),
        ]
        existing_agents = {a.name for a in db.query(AgentModel).all()}
        for name, desc, prompt, mode, tools in _BUILTIN_AGENTS:
            if name not in existing_agents:
                db.add(AgentModel(name=name, description=desc, system_prompt=prompt, mode=mode,
                                  tools_json=tools, mcps_json="[]"))
                counts["agents"] += 1

        # MCPs — insert if name not exists
        existing_mcps = {m.name for m in db.query(MCPServer).all()}
        if "browser-mcp" not in existing_mcps:
            db.add(MCPServer(
                name="browser-mcp",
                description="Chrome 浏览器控制 MCP — 提供 16 个 Playwright 浏览器工具",
                command="python3",
                args_json='["-m", "secagent.mcp_servers.browser_server"]',
                env_json="{}",
                enabled=True,
            ))
            counts["mcps"] += 1
        if "recon-mcp" not in existing_mcps:
            db.add(MCPServer(
                name="recon-mcp",
                description="Recon/扫描 MCP — 提供 httpx、katana、nuclei、ffuf、sqlmap 工具封装",
                command="python3",
                args_json='["-m", "secagent.mcp_servers.recon_server"]',
                env_json="{}",
                enabled=False,
            ))
            counts["mcps"] += 1

        db.commit()
    finally:
        db.close()
    return counts
