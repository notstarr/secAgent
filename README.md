# secAgent

> 基于 Claude / OpenAI 兼容接口的 AI 驱动渗透测试平台，提供完整 Web UI 与 MCP 工具集成。

![Python](https://img.shields.io/badge/Python-3.11+-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## 功能特性

- **Web UI**：基于 FastAPI + Alpine.js + Tailwind CSS，端口 8888，支持深色模式
- **AI Agent 循环**：支持 Anthropic Claude 原生 SDK 与 OpenAI 兼容接口（代理网关）
- **脚本执行**：内置 `execute_python_script` 与 `exec_command`，Agent 可自由编写 Python 脚本或执行 Shell 命令
- **MCP 工具集成**：通过 [MCP 协议](https://modelcontextprotocol.io) 连接任意工具服务器，内置 Playwright 浏览器 MCP
- **项目管理**：多项目并行、漏洞记录、运行历史、文件管理
- **项目记忆**：Agent 可通过 `memory_store` / `memory_recall` 在项目维度持久化关键发现，跨运行保留
- **Artifact 系统**：大工具结果自动转存为 artifact，LLM 通过 `query_execution_result` 分页查询，彻底解决 context 爆炸
- **Token 统计**：实时显示每次运行消耗的 prompt / completion token
- **暂停 / 续跑 / 终止**：随时暂停并保存对话快照，可携带补充指令续跑，或强制终止
- **执行策略保护**：重复调用熔断、无进展触发策略切换、浏览器工具冷却与占比保护，防止空转
- **异常结束保护**：`finish_reason=length` 自动续跑、过短回复自动续跑，防止模型意外中断任务
- **上下文管理**：可配置 max_tokens、工具结果大小上限、压缩保留消息数、artifact 分页大小、定期 LLM 压缩历史
- **LLM 超时重试**：主循环与摘要压缩支持超时自动重试，提升长任务稳定性
- **工具幻觉防护**：当模型调用不存在的工具时，返回完整可用工具列表引导修正
- **自动漏洞入库**：可从工具结果与最终报告中结构化提取漏洞并自动入库
- **漏洞管理**：创建、审核、确认/误报漏洞报告
- **多 Agent / Skill**：可自定义 Agent 与 Skill，支持按项目绑定
- **多 Agent 编排**（实验性）：Orchestrator 模式，可协调多个专业子 Agent 协同工作

---

## 项目结构

```
secAgent/
├── secagent/
│   ├── core/
│   │   ├── config.py          # AgentConfig（支持 env / OpenAI compat）
│   │   ├── agent_runner.py    # Agent 执行循环
│   │   └── multi_agent.py     # 多 Agent 编排引擎（Orchestrator）
│   ├── tools/
│   │   ├── network_tools.py   # dns_lookup / port_scan / whois_lookup
│   │   ├── web_tools.py       # advanced_http_request / crawl_links / ...
│   │   ├── pentest_tools.py   # fuzz_paths / extract_js_endpoints / ...
│   │   ├── script_tools.py    # execute_python_script / exec_command
│   │   └── memory_tools.py    # memory_store / memory_recall / memory_list / memory_delete
│   ├── mcp_servers/
│   │   ├── browser_server.py  # 内置 Playwright 浏览器 MCP 服务器
│   │   └── recon_server.py    # recon CLI MCP（httpx/katana/nuclei/ffuf/sqlmap）
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

- Python 3.11+
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

### 模型配置

| 参数 | 说明 | 默认值 |
|------|------|--------|
| API Provider | `anthropic` 或 `openai_compat` | `anthropic` |
| API Key | Anthropic / OpenAI 兼容网关的密钥 | — |
| Base URL | OpenAI 兼容接口地址（如代理网关） | — |
| Model | 模型名称（如 `claude-sonnet-4-20250514`） | — |
| Max Tokens | 模型单次回复最大 token 数 | `16384` |
| 最大迭代次数 | Agent 单次运行最大轮数 | `100` |

### 上下文管理

| 参数 | 说明 | 默认值 |
|------|------|--------|
| 工具结果上限 | 超过此大小的结果转为 artifact | `8000` 字符 |
| 页面源码上限 | 页面源码截取上限 | `5000` 字符 |
| 上下文压缩 | 每 N 轮自动 LLM 压缩历史消息 | `30` |
| 压缩保留消息数 | 压缩时保留最近不压缩的消息条数 | `10` |
| Artifact 每页字符数 | 大结果分页展示的页大小 | `3000` |
| 过短回复保护阈值 | 回复短于此字符数时自动续跑，设 `0` 关闭 | `10` |

### 执行策略保护

| 参数 | 说明 | 默认值 |
|------|------|--------|
| 重复调用限制 | 连续相同调用 N 次后熔断 | `5` |
| 无进展限制 | 连续无实质输出 N 轮后触发策略切换 | `12` |
| 浏览器冷却轮数 | 连续浏览器操作后强制冷却 | `6` |
| 浏览器占比上限 | 浏览器工具在总调用中的最大比例 | `80%` |

### 稳定性

| 参数 | 说明 | 默认值 |
|------|------|--------|
| LLM 超时 | 单次 API 请求超时秒数 | `180` |
| LLM 重试 | 超时后重试次数 | `2` |

---

## 内置工具

### 核心工具

| 工具 | 说明 |
|------|------|
| `advanced_http_request` | 高级 HTTP 请求，支持自定义方法/头/体/代理/重定向控制 |
| `crawl_links` | 页面链接爬取与分析 |
| `fuzz_paths` | 路径爆破（基于 httpx） |
| `extract_js_endpoints` | 从 JavaScript 中提取 API 端点 |
| `execute_python_script` | 执行任意 Python 脚本，支持自动安装依赖 |
| `exec_command` | 执行 Shell 命令（通过 /bin/bash） |

### 记忆工具

| 工具 | 说明 |
|------|------|
| `memory_store` | 存储键值对到项目记忆 |
| `memory_recall` | 按关键词搜索项目记忆 |
| `memory_list` | 列出项目所有记忆条目 |
| `memory_delete` | 删除指定记忆条目 |

### 浏览器 MCP（内置）

通过 Playwright 驱动真实浏览器，工具包括：`browser_launch` / `browser_navigate` / `browser_click` / `browser_type` / `browser_screenshot` / `browser_get_html` / `browser_execute_js` / `browser_intercept_requests` / `browser_get_requests` 等。

### 运行时动态工具

| 工具 | 说明 |
|------|------|
| `query_execution_result` | 按 artifact_id 分页查询大结果（会话级，自动注入） |

---

## MCP 服务器

在 Web UI → **MCP** 中添加任意 MCP 服务器（stdio 协议），Agent 运行时自动连接并注入工具。

示例：连接内置浏览器 MCP：

| 字段 | 值 |
|------|----|
| 名称 | `browser-mcp` |
| 命令 | `python` |
| 参数（JSON） | `["-m", "secagent.mcp_servers.browser_server"]` |

示例：连接内置 recon CLI MCP：

| 字段 | 值 |
|------|----|
| 名称 | `recon-mcp` |
| 命令 | `python3` |
| 参数（JSON） | `["-m", "secagent.mcp_servers.recon_server"]` |

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

LLM 通过运行时注入的 `query_execution_result` 工具按需翻页，彻底避免 context 窗口爆炸。

---

## 稳定性机制

### finish_reason 保护

当模型因 `max_tokens` 限制输出被截断（`finish_reason=length`）时，系统自动追加提示并续跑，无需人工干预。

### 过短回复保护

当模型异常返回极短内容（如单个 `.`）时，系统自动检测并请求模型继续，防止任务意外终止。阈值可在设置中配置（默认 10 字符，设 0 关闭）。

### 工具幻觉修正

当模型调用不存在的工具（如 `Bash`、`WebFetch`）时，系统返回完整可用工具列表和正确工具名映射，引导模型自动修正。

---

## 使用流程

1. **创建项目**：填写目标 URL、任务描述，绑定 Agent
2. **启动 Agent**：点击"启动 Agent"，实时查看思考过程与工具调用
3. **暂停 / 续跑**：随时暂停，对话历史自动保存；续跑时可添加补充指引
4. **终止**：强制停止所有工具调用与 Agent 线程（红色"终止"按钮）
5. **漏洞记录**：发现漏洞后记录到漏洞库，支持审核确认 / 标记误报

---

## 自动漏洞入库说明

- 工具层：`check_common_vulns`、`scan_xss`、`scan_sqli`、`scan_ssrf`、`test_idor` 返回结构化结果时，后端会自动提取关键字段写入漏洞库。
- 报告层：当最终报告采用约定 Markdown 结构（如 `## [HIGH] 标题` + `### 描述/POC/请求包/响应包`）时，也会自动解析并入库。
- 去重策略：按 `project_id + title + target + vuln_type` 去重，避免重复插入。

---

## 免责声明

本工具仅用于**经过授权的安全测试**。
在对任何目标进行测试前，请确保已获得书面授权。
未经授权的测试可能违反法律法规，使用者须自行承担相应法律责任。

---

## License

MIT
