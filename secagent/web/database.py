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
        "skills_json": "ALTER TABLE projects ADD COLUMN skills_json TEXT DEFAULT '[]'",
    }
    with engine.connect() as _conn:
        for col, stmt in _migrations.items():
            if col not in existing_project_cols:
                _conn.execute(_text(stmt))
        _conn.commit()
    # ── agents table migrations ───────────────────────────────────────────────
    existing_agent_cols = {c["name"] for c in inspector.get_columns("agents")}
    _agent_migrations = {
        "sub_agents_json": "ALTER TABLE agents ADD COLUMN sub_agents_json TEXT DEFAULT '[]'",
    }
    with engine.connect() as _conn:
        for col, stmt in _agent_migrations.items():
            if col not in existing_agent_cols:
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
            "llm_request_timeout_sec": "180",
            "llm_request_retry": "2",
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

        # ── Built-in Tools removed — builtin tools are now registered via
        #    code in _ALL_TOOLS dict (app.py) and /api/tools/all endpoint.
        #    tool_defs table is only for user-created custom tools.

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
        # Tools — no longer seeded into tool_defs.
        # Builtin tools are registered via code in _ALL_TOOLS (app.py)
        # and exposed through /api/tools/all. tool_defs is for custom tools only.

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
