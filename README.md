# secAgent

> 基于 Claude / OpenAI 兼容接口的 AI 驱动渗透测试平台，提供完整 Web UI 与 MCP 工具集成。

![Python](https://img.shields.io/badge/Python-3.9+-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## 功能特性

- **Web UI**：基于 FastAPI + Alpine.js + Tailwind CSS，端口 8888，支持深色模式
- **AI Agent 循环**：支持 Anthropic Claude 原生 SDK 与 OpenAI 兼容接口（代理网关）
- **MCP 工具集成**：通过 [MCP 协议](https://modelcontextprotocol.io) 连接任意工具服务器，内置 Playwright 浏览器 MCP
- **项目管理**：多项目并行、漏洞记录、运行历史、文件管理
- **Artifact 系统**：大工具结果自动转存为 artifact，LLM 通过 `query_execution_result` 分页查询，彻底解决 context 爆炸
- **Token 统计**：实时显示每次运行消耗的 prompt / completion token
- **暂停 / 续跑 / 终止**：随时暂停并保存对话快照，可携带补充指令续跑，或强制终止
- **上下文管理**：可配置工具结果大小上限、定期 LLM 压缩历史消息
- **漏洞管理**：创建、审核、确认/误报漏洞报告
- **多 Agent / Skill**：可自定义 Agent 与 Skill，支持按项目绑定

---

## 项目结构

```
secAgent/
├── secagent/
│   ├── core/
│   │   ├── config.py          # AgentConfig（支持 env / OpenAI compat）
│   │   └── agent_runner.py    # Agent 执行循环
│   ├── tools/
│   │   ├── network_tools.py   # dns_lookup / port_scan / whois_lookup
│   │   ├── web_tools.py       # http_request / detect_waf / crawl_links / ...
│   │   └── pentest_tools.py   # scan_xss / scan_sqli / fuzz_paths / ...
│   ├── mcp_servers/
│   │   └── browser_server.py  # 内置 Playwright 浏览器 MCP 服务器
│   ├── prompts/
│   │   └── sigma_single.py    # 默认渗透测试 System Prompt
│   └── web/
│       ├── app.py             # FastAPI 主应用 + WebSocket Agent 循环
│       ├── models.py          # SQLAlchemy 数据模型
│       ├── database.py        # SQLite 初始化与迁移
│       ├── schemas.py         # Pydantic schemas
│       ├── routers/           # REST API 路由
│       └── static/
│           └── index.html     # 单页前端（Alpine.js + Tailwind CDN）
└── pyproject.toml
```

---

## 快速开始

### 环境要求

- Python 3.9+
- macOS / Linux（Windows 未测试）

### 安装

```bash
git clone https://github.com/notstarr/secAgent.git
cd secAgent

python3.11 -m venv .venv-311
source .venv-311/bin/activate

pip install -e ".[dev]"

# 安装 Playwright 浏览器（用于浏览器 MCP）
playwright install chromium
```

### 启动 Web UI

```bash
secagent web --port 8888
# 或
uvicorn secagent.web.app:app --port 8888 --reload
```

浏览器访问 **http://localhost:8888**

---

## 配置

在 Web UI → **系统设置** 中填写：

| 参数 | 说明 |
|------|------|
| API Provider | `anthropic` 或 `openai_compat` |
| API Key | Anthropic / OpenAI 兼容网关的密钥 |
| Base URL | OpenAI 兼容接口地址（如代理网关） |
| Model | 模型名称（如 `claude-opus-4-5-20250929`） |
| 最大迭代次数 | Agent 单次运行最大轮数（默认 100） |
| 工具结果上限 | 超过此大小的结果转为 artifact（默认 8000 字符） |
| 上下文压缩 | 每 N 轮自动 LLM 压缩历史消息 |

---

## 内置工具

### 网络侦察

| 工具 | 说明 |
|------|------|
| `dns_lookup` | DNS 记录查询（A / MX / NS / TXT） |
| `port_scan` | TCP 端口扫描 |
| `whois_lookup` | WHOIS 信息查询 |

### Web 测试

| 工具 | 说明 |
|------|------|
| `http_request` | 自定义 HTTP 请求 |
| `fetch_http_headers` | 获取响应头 |
| `detect_waf` | WAF 检测 |
| `crawl_links` | 页面链接爬取 |
| `check_common_vulns` | 常见漏洞快速检测 |

### 渗透测试

| 工具 | 说明 |
|------|------|
| `scan_xss` | XSS 扫描 |
| `scan_sqli` | SQL 注入扫描 |
| `scan_ssrf` | SSRF 扫描 |
| `fuzz_paths` | 路径爆破 |
| `extract_js_endpoints` | JS 端点提取 |
| `test_idor` | IDOR 测试 |

### 浏览器 MCP（内置）

通过 Playwright 驱动真实浏览器，工具包括：`browser_launch` / `browser_navigate` / `browser_click` / `browser_type` / `browser_screenshot` / `browser_get_html` / `browser_execute_js` 等。

---

## MCP 服务器

在 Web UI → **MCP** 中添加任意 MCP 服务器（stdio 协议），Agent 运行时自动连接并注入工具。

示例：连接内置浏览器 MCP：

| 字段 | 值 |
|------|----|
| 名称 | `browser-mcp` |
| 命令 | `python` |
| 参数（JSON） | `["-m", "secagent.mcp_servers.browser_server"]` |

---

## Artifact 系统

当工具返回超大结果时（如完整页面源码、扫描报告），系统自动将其存为 artifact 并告知 LLM：

```json
{
  "type": "artifact",
  "artifact_id": "a3f9c12b88",
  "total_chars": 45231,
  "total_pages": 16,
  "message": "结果较大，已存为 artifact。请调用 query_execution_result(artifact_id='a3f9c12b88', page=1) 查看。"
}
```

LLM 通过内置的 `query_execution_result` 工具按需翻页，彻底避免 context 窗口爆炸。

---

## 使用流程

1. **创建项目**：填写目标 URL、任务描述，绑定 Agent
2. **启动 Agent**：点击"启动 Agent"，实时查看思考过程与工具调用
3. **暂停 / 续跑**：随时暂停，对话历史自动保存；续跑时可添加补充指引
4. **终止**：强制停止所有工具调用与 Agent 线程（红色"终止"按钮）
5. **漏洞记录**：发现漏洞后记录到漏洞库，支持审核确认 / 标记误报

---

## 免责声明

本工具仅用于**经过授权的安全测试**。  
在对任何目标进行测试前，请确保已获得书面授权。  
未经授权的测试可能违反法律法规，使用者须自行承担相应法律责任。

---

## License

MIT
