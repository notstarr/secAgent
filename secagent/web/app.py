"""
FastAPI application entry point.

Mounts:
  - REST API routers
  - WebSocket /ws/run/{project_id}  ← real-time agent output
  - Static files served from /static/
  - GET / → redirects to index.html
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from secagent.web.database import init_db, reseed_builtin
from secagent.web.routers.projects import router as projects_router
from secagent.web.routers.vulns import router as vulns_router
from secagent.web.routers.mcps import router as mcps_router
from secagent.web.routers.files import router as files_router
from secagent.web.routers.crud import (
    tools_router,
    agents_router,
    skills_router,
    settings_router,
)

logger = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).parent / "static"


# ── MCP Bridge ────────────────────────────────────────────────────────────────

class _MCPBridge:
    """Start MCP subprocess servers in a background thread and expose tools as sync callables."""

    def __init__(self) -> None:
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True)
        self._thread.start()
        self._cleanups: list = []

    def connect(self, command: str, args: list, env: dict, name: str) -> list:
        """Connect to one MCP server, return list of callable tool wrappers."""
        import sys
        import shlex

        cmd_parts = shlex.split(command) if command else ["python"]
        actual_cmd = cmd_parts[0]
        # Always resolve python/python3 to the current venv executable
        if actual_cmd in ("python", "python3", "python3.11", "python3.12"):
            actual_cmd = sys.executable
        all_args = cmd_parts[1:] + (args or [])

        fut = asyncio.run_coroutine_threadsafe(
            self._async_connect(actual_cmd, all_args, env or {}),
            self._loop,
        )
        session, tools_info, cleanup = fut.result(timeout=30)
        self._cleanups.append(cleanup)
        return [self._make_wrapper(session, t) for t in tools_info]

    async def _async_connect(self, command: str, args: list, env: dict):
        from mcp import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client

        params = StdioServerParameters(command=command, args=args, env=env)
        stdio_cm = stdio_client(params)
        read, write = await stdio_cm.__aenter__()
        session_cm = ClientSession(read, write)
        session = await session_cm.__aenter__()
        await session.initialize()
        tools_result = await session.list_tools()

        async def cleanup() -> None:
            try:
                await session_cm.__aexit__(None, None, None)
                await stdio_cm.__aexit__(None, None, None)
            except Exception:
                pass

        return session, tools_result.tools, cleanup

    def _make_wrapper(self, session: Any, tool_info: Any) -> Any:
        loop = self._loop

        class MCPTool:
            def __init__(self) -> None:
                self.name: str = tool_info.name
                self.description: str = tool_info.description or ""
                raw_schema = getattr(tool_info, "inputSchema", None)
                self.input_schema: dict = (
                    raw_schema if isinstance(raw_schema, dict)
                    else {"type": "object", "properties": {}}
                )

            def __call__(self, **kwargs: Any) -> str:
                fut = asyncio.run_coroutine_threadsafe(
                    session.call_tool(tool_info.name, kwargs), loop
                )
                try:
                    result = fut.result(timeout=60)
                    content = result.content
                    if isinstance(content, list):
                        parts = []
                        for item in content:
                            if hasattr(item, "text"):
                                parts.append(item.text)
                            else:
                                parts.append(str(item))
                        return "\n".join(parts)
                    return str(content)
                except Exception as exc:
                    return f"MCP tool error: {exc}"

        return MCPTool()

    def shutdown(self) -> None:
        for cleanup in self._cleanups:
            try:
                asyncio.run_coroutine_threadsafe(cleanup(), self._loop).result(timeout=5)
            except Exception:
                pass
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=5)


app = FastAPI(title="secAgent UI", version="0.1.0")

# Per-project cancel events — keyed by project_id, set when user pauses/disconnects
_cancel_events: dict[int, threading.Event] = {}
# Per-project agent threads — so new connections can wait for the old one to die
_agent_threads: dict[int, threading.Thread] = {}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── API routers ───────────────────────────────────────────────────────────────

for r in (projects_router, vulns_router, mcps_router, files_router, tools_router, agents_router, skills_router, settings_router):
    app.include_router(r)

# ── Static files + SPA ────────────────────────────────────────────────────────

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
def index():
    return FileResponse(str(STATIC_DIR / "index.html"))


# ── WebSocket: real-time agent run ────────────────────────────────────────────

@app.websocket("/ws/run/{project_id}")
async def ws_run(websocket: WebSocket, project_id: int):
    """
    Stream agent output to the frontend in real time.
    Expects a JSON message: { "task": "...", "extra": "..." }
    """
    from sqlalchemy.orm import Session
    from secagent.web.database import SessionLocal
    from secagent.web.models import Project, AgentModel, Setting, TaskLog
    from secagent.core.config import AgentConfig
    from secagent.core.agent_runner import AgentRunner

    await websocket.accept()
    db: Session = SessionLocal()

    # ── 停止同一项目的旧 agent（防止多线程并发打开浏览器） ─────
    if project_id in _cancel_events:
        _cancel_events[project_id].set()  # 通知旧线程尽快退出
    old_thread = _agent_threads.get(project_id)
    if old_thread and old_thread.is_alive():
        # 异步等待旧线程退出，最多 10 秒
        for _ in range(50):
            if not old_thread.is_alive():
                break
            await asyncio.sleep(0.2)

    cancel_event = threading.Event()
    messages_ref: dict[str, list] = {"data": []}  # 共享消息快照，供暂停时持久化

    try:
        raw = await websocket.receive_text()
        payload = json.loads(raw)
        task_text = payload.get("task", "")
        extra = payload.get("extra", "")
        supplement = payload.get("supplement", "")  # 暂停后的补充指引

        project = db.get(Project, project_id)
        if not project:
            await websocket.send_json({"type": "error", "message": "Project not found"})
            return

        project.status = "running"
        db.commit()

        # ── Build AgentConfig from saved settings ──────────────────────
        settings = {r.key: r.value for r in db.query(Setting).all()}
        api_key = settings.get("api_key", "")
        base_url = settings.get("base_url", "")
        model = settings.get("model", "claude-opus-4-5-20250929")

        if not api_key:
            await websocket.send_json({"type": "error",
                                       "message": "请先在系统设置中填写 API Key"})
            project.status = "idle"
            db.commit()
            return

        cfg = AgentConfig(api_key=api_key, model=model)
        if base_url:
            cfg.openai_compat_base_url = base_url
            cfg.openai_compat_api_key = api_key
            cfg.openai_compat_model = model

        # ── 从设置中应用迭代上限 ────────────────────────────────────────
        _max_iter = int(settings.get("max_iterations") or "100")
        if _max_iter > 0:
            cfg.max_iterations = _max_iter

        # ── Load agent by project.agent_id ─────────────────────────────
        agent_row: AgentModel | None = None
        if project.agent_id:
            agent_row = db.get(AgentModel, project.agent_id)

        system_prompt = ""
        tool_names: list[str] = []
        if agent_row:
            system_prompt = agent_row.system_prompt or ""
            try:
                tool_names = json.loads(agent_row.tools_json or "[]")
            except Exception:
                tool_names = []
        else:
            # fallback: use sigmaAI prompt + all tools
            from secagent.prompts.sigma_single import SIGMA_SINGLE_AGENT_PROMPT
            system_prompt = SIGMA_SINGLE_AGENT_PROMPT

        # ── Resolve tool functions ─────────────────────────────────────
        from secagent.tools.network_tools import dns_lookup, port_scan, whois_lookup
        from secagent.tools.web_tools import (
            fetch_http_headers, http_request, detect_waf, crawl_links, check_common_vulns
        )
        from secagent.tools.pentest_tools import (
            scan_xss, scan_sqli, scan_ssrf, fuzz_paths, extract_js_endpoints, test_idor
        )
        _ALL_TOOLS = {
            "dns_lookup": dns_lookup, "port_scan": port_scan, "whois_lookup": whois_lookup,
            "fetch_http_headers": fetch_http_headers, "http_request": http_request,
            "detect_waf": detect_waf, "crawl_links": crawl_links,
            "check_common_vulns": check_common_vulns,
            "scan_xss": scan_xss, "scan_sqli": scan_sqli, "scan_ssrf": scan_ssrf,
            "fuzz_paths": fuzz_paths, "extract_js_endpoints": extract_js_endpoints,
            "test_idor": test_idor,
        }
        tools = [_ALL_TOOLS[n] for n in tool_names if n in _ALL_TOOLS] or list(_ALL_TOOLS.values())

        # ── Load MCP server configs — always include ALL enabled MCPs ─────────
        from secagent.web.models import MCPServer as MCPServerModel
        if agent_row:
            try:
                agent_mcp_names: list[str] = json.loads(agent_row.mcps_json or "[]")
            except Exception:
                agent_mcp_names = []
        else:
            agent_mcp_names = []
        # Merge agent MCPs with all enabled MCPs (dedup, preserve agent order)
        all_enabled = [m.name for m in db.query(MCPServerModel).filter_by(enabled=True).all()]
        mcp_names = list(dict.fromkeys(agent_mcp_names + all_enabled))  # ordered dedup
        mcp_server_configs: list[dict] = []
        for mcp_name in mcp_names:
            mcp_row = db.query(MCPServerModel).filter_by(name=mcp_name, enabled=True).first()
            if mcp_row:
                mcp_server_configs.append({
                    "name": mcp_row.name,
                    "command": mcp_row.command or "python",
                    "args": json.loads(mcp_row.args_json or "[]"),
                    "env": json.loads(mcp_row.env_json or "{}"),
                })

        runner = AgentRunner(config=cfg, system_prompt=system_prompt, tools=tools)

        # ── 暂停/续跑 状态初始化 ─────────────────────────────────────────
        _cancel_events[project_id] = cancel_event

        initial_messages: list[dict] | None = None
        if project.conversation_snapshot:
            try:
                _saved = json.loads(project.conversation_snapshot)
                if _saved:
                    initial_messages = list(_saved)
                    project.conversation_snapshot = ""
                    db.commit()
            except Exception:
                pass

        if initial_messages is not None:
            _resume_hint = supplement.strip() if supplement.strip() else "请继续之前的任务。"
            initial_messages.append({"role": "user", "content": f"[续跑] {_resume_hint}"})

        # ── Helper: strip base64 image data before sending to LLM ────────────
        def _strip_image_b64(result_str: str) -> str:
            """Remove image_base64 / screenshot_base64 fields from JSON tool results.

            Replaces the binary blob with a short notice so the LLM knows the
            screenshot was captured and saved, without consuming thousands of tokens.
            """
            try:
                data = json.loads(result_str)
                changed = False
                for key in ("image_base64", "screenshot_base64"):
                    if key in data:
                        data[key] = "[已保存到文件管理器，base64数据已省略]"
                        changed = True
                return json.dumps(data, ensure_ascii=False) if changed else result_str
            except Exception:
                return result_str

        # ── Helper: auto-save files from MCP results ───────────────────────
        def _try_save_file(result_str: str, tool_name: str, pid: int, _db: Any) -> None:
            """If an MCP tool result contains image_base64 or file data, persist it."""
            try:
                import base64 as _b64
                import uuid as _uuid
                from secagent.web.models import ProjectFile as _PF
                from secagent.web.routers.files import FILES_DIR, _ensure_dir

                data = json.loads(result_str)
                b64 = data.get("image_base64") or data.get("screenshot_base64")
                if b64:
                    _ensure_dir()
                    ext = ".png" if data.get("format", "png") == "png" else ".jpg"
                    fname = f"{tool_name}_{_uuid.uuid4().hex[:8]}{ext}"
                    dest = FILES_DIR / fname
                    dest.write_bytes(_b64.b64decode(b64))
                    pf = _PF(
                        project_id=pid,
                        name=fname,
                        path=fname,
                        mime_type="image/png" if ext == ".png" else "image/jpeg",
                        size=dest.stat().st_size,
                        source="mcp_screenshot",
                    )
                    _db.add(pf)
                    _db.commit()
            except Exception:
                pass  # silently skip — don't break the run

        # ── Streaming tool-call events ─────────────────────────────────
        log_lines: list[str] = []
        loop = asyncio.get_event_loop()

        def _send(msg: dict) -> None:
            asyncio.run_coroutine_threadsafe(websocket.send_json(msg), loop)

        def _run_with_streaming() -> str:
            """Monkey-patch runner to intercept tool events and stream them."""
            # ── Connect MCP servers ────────────────────────────────────
            bridge = _MCPBridge()
            mcp_tools: list = []
            for cfg_mcp in mcp_server_configs:
                try:
                    mt = bridge.connect(
                        cfg_mcp["command"], cfg_mcp["args"], cfg_mcp["env"], cfg_mcp["name"]
                    )
                    mcp_tools.extend(mt)
                    _send({"type": "info", "content": f"MCP '{cfg_mcp['name']}' 已连接，加载 {len(mt)} 个工具"})
                except Exception as exc:
                    _send({"type": "info", "content": f"MCP '{cfg_mcp['name']}' 连接失败: {exc}"})

            if mcp_tools:
                runner.tools = runner.tools + mcp_tools

            try:
                return _do_run()
            finally:
                bridge.shutdown()

        def _do_run() -> str:
            """Monkey-patch runner to intercept tool events and stream them."""
            use_compat = runner._use_openai_compat

            if use_compat:
                # Patch OpenAI path
                def patched(user_message: str, verbose: bool = True) -> str:
                    cfg2 = runner.config
                    from secagent.core.agent_runner import _build_openai_tool_schema, _get_tool_name
                    tool_map = {_get_tool_name(fn): fn for fn in runner.tools}
                    oa_tools = [_build_openai_tool_schema(fn) for fn in runner.tools]
                    if initial_messages is not None:
                        messages: list[dict] = list(initial_messages)
                    else:
                        messages = []
                        if runner.system_prompt:
                            messages.append({"role": "system", "content": runner.system_prompt})
                        messages.append({"role": "user", "content": user_message})

                    # ── 从设置中读取上下文管理参数 ──────────────────────────
                    _tool_max = int(settings.get("tool_result_max_chars") or 8000)
                    _page_max = int(settings.get("page_source_max_chars") or 5000)
                    _compress_enabled = (settings.get("context_compress_enabled") or "false").lower() == "true"
                    _compress_every_n = int(settings.get("context_compress_every_n") or 30)

                    # ── Artifact 系统：大结果转存，LLM 按需翻页查询 ─────────
                    _ARTIFACT_NO_STORE = {"browser_execute_js"}  # 这些工具的结果永不转 artifact
                    _ARTIFACT_PAGE_SIZE = 3000
                    _artifacts_store: dict[str, dict] = {}  # 本次运行生命周期内有效

                    def _store_as_artifact(content: str, source_tool: str) -> str:
                        """将大结果存为 artifact，返回 LLM 可读的紧凑引用。"""
                        import uuid as _uuid
                        aid = _uuid.uuid4().hex[:10]
                        _artifacts_store[aid] = {"content": content, "source_tool": source_tool}
                        total_pages = (len(content) + _ARTIFACT_PAGE_SIZE - 1) // _ARTIFACT_PAGE_SIZE
                        preview = content[:200].replace("\n", " ")
                        ref = json.dumps({
                            "type": "artifact",
                            "artifact_id": aid,
                            "source_tool": source_tool,
                            "total_chars": len(content),
                            "total_pages": total_pages,
                            "page_size": _ARTIFACT_PAGE_SIZE,
                            "message": (
                                f"结果较大（{len(content)} 字符 / {total_pages} 页），已存为 artifact #{aid}。"
                                f"请调用 query_execution_result(artifact_id='{aid}', page=1) 按需翻页查看。"
                            ),
                            "preview": preview,
                        }, ensure_ascii=False)
                        _send({"type": "info", "content": f"[Artifact] {source_tool} 结果 {len(content)} 字符 → artifact #{aid}（{total_pages} 页）"})
                        return ref

                    def query_execution_result(artifact_id: str, page: int = 1) -> str:
                        """按需查询大结果的某一页内容。

                        Args:
                            artifact_id: artifact 引用中的 ID。
                            page: 要查询的页码（从 1 开始，每页约 3000 字符）。
                        """
                        art = _artifacts_store.get(str(artifact_id))
                        if not art:
                            return json.dumps({"error": f"artifact '{artifact_id}' 不存在或已过期。"})
                        content = art["content"]
                        p = max(1, int(page))
                        start = (p - 1) * _ARTIFACT_PAGE_SIZE
                        end = start + _ARTIFACT_PAGE_SIZE
                        total_pages = (len(content) + _ARTIFACT_PAGE_SIZE - 1) // _ARTIFACT_PAGE_SIZE
                        return json.dumps({
                            "artifact_id": artifact_id,
                            "source_tool": art["source_tool"],
                            "page": p,
                            "total_pages": total_pages,
                            "total_chars": len(content),
                            "content": content[start:end],
                            "has_more": end < len(content),
                        }, ensure_ascii=False)

                    # 将 query_execution_result 动态注入工具列表
                    _qer_schema = {
                        "type": "function",
                        "function": {
                            "name": "query_execution_result",
                            "description": (
                                "按需读取大结果的某一页内容（artifact 分页查询）。"
                                "当工具返回 artifact 引用时，调用此工具按页获取完整数据。"
                            ),
                            "parameters": {
                                "type": "object",
                                "properties": {
                                    "artifact_id": {"type": "string", "description": "artifact 引用中的 ID"},
                                    "page": {"type": "integer", "description": "页码，从 1 开始，每页约 3000 字符"},
                                },
                                "required": ["artifact_id"],
                            },
                        },
                    }
                    tool_map["query_execution_result"] = query_execution_result
                    oa_tools.append(_qer_schema)

                    # ── Token 统计 ────────────────────────────────────────
                    _prompt_tokens = 0
                    _completion_tokens = 0

                    def _compress_context(msgs: list[dict]) -> list[dict]:
                        """将 msgs[2:-KEEP] 的历史压缩为一条摘要，减少 context 占用。"""
                        KEEP = 10  # 保留最近 10 条消息不压缩
                        if len(msgs) <= 2 + KEEP:
                            return msgs
                        to_compress = msgs[2:-KEEP]
                        parts = []
                        for m in to_compress:
                            role = m.get("role", "")
                            content = m.get("content") or ""
                            if isinstance(content, list):
                                content = str(content)
                            if role == "assistant":
                                tool_calls = m.get("tool_calls") or []
                                if tool_calls:
                                    calls_desc = "; ".join(
                                        f"{tc['function']['name']}({tc['function']['arguments'][:80]})"
                                        for tc in tool_calls
                                    )
                                    parts.append(f"[助手调用工具] {calls_desc}")
                                elif content.strip():
                                    parts.append(f"[助手思考] {content[:300]}")
                            elif role == "tool":
                                parts.append(f"[工具结果] {content[:200]}")
                        compress_prompt = (
                            "请用中文简洁总结以下渗透测试过程中的关键发现、已尝试的攻击向量和当前状态"
                            "（不超过300字，保留重要细节如URL、参数名、漏洞点）：\n\n"
                            + "\n".join(parts)
                        )
                        try:
                            cresp = runner._client.chat.completions.create(
                                model=cfg2.get_effective_model(),
                                max_tokens=600,
                                messages=[{"role": "user", "content": compress_prompt}],
                            )
                            summary = cresp.choices[0].message.content or "(无摘要)"
                        except Exception as exc:
                            summary = f"(压缩失败: {exc})"
                        summary_msg = {
                            "role": "user",
                            "content": (
                                f"[历史对话摘要 — 已压缩 {len(to_compress)} 条消息]\n{summary}"
                            ),
                        }
                        compressed = msgs[:2] + [summary_msg] + msgs[-KEEP:]
                        notice = f"[上下文压缩] 已将 {len(to_compress)} 条历史消息压缩为摘要，释放约 {sum(len(str(m)) for m in to_compress)//1024} KB"
                        log_lines.append({"type": "info", "content": notice})
                        _send({"type": "info", "content": notice})
                        return compressed

                    final_text = ""
                    for _iter in range(cfg2.max_iterations):
                        # ── 检查取消信号（用户暂停）────────────────────────
                        if cancel_event.is_set():
                            _send({"type": "info", "content": "任务已暂停，对话历史已保存，可随时续跑。"})
                            break
                        # 每轮更新消息快照，供暂停时持久化
                        messages_ref["data"] = list(messages)
                        # ── 上下文压缩触发检查 ────────────────────────────
                        if _compress_enabled and _iter > 0 and _iter % _compress_every_n == 0:
                            messages = _compress_context(messages)

                        kwargs: dict = {"model": cfg2.get_effective_model(),
                                        "max_tokens": cfg2.max_tokens, "messages": messages}
                        if oa_tools:
                            kwargs["tools"] = oa_tools
                        resp = runner._client.chat.completions.create(**kwargs)
                        # ── Token 统计 ────────────────────────────────────
                        if hasattr(resp, "usage") and resp.usage:
                            _prompt_tokens += getattr(resp.usage, "prompt_tokens", 0)
                            _completion_tokens += getattr(resp.usage, "completion_tokens", 0)
                            _send({"type": "tokens", "prompt": _prompt_tokens,
                                   "completion": _completion_tokens,
                                   "total": _prompt_tokens + _completion_tokens})
                        msg = resp.choices[0].message
                        finish = resp.choices[0].finish_reason

                        if finish == "tool_calls" and msg.tool_calls:
                            # 捕获模型在调用工具前的思考文本
                            if msg.content and msg.content.strip():
                                think_line = msg.content.strip()
                                log_lines.append({"type": "think", "content": think_line})
                                _send({"type": "think", "content": think_line})
                            for tc in msg.tool_calls:
                                call_line = f"{tc.function.name}({tc.function.arguments[:300]})"
                                log_lines.append({"type": "tool", "content": call_line})
                                _send({"type": "tool", "content": call_line})
                            messages.append({
                                "role": "assistant", "content": msg.content or "",
                                "tool_calls": [
                                    {"id": tc.id, "type": "function",
                                     "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                                    for tc in msg.tool_calls
                                ],
                            })
                            for tc in msg.tool_calls:
                                # \u6bcf\u6b21\u5de5\u5177\u8c03\u7528\u524d\u68c0\u67e5\u53d6\u6d88\u4fe1\u53f7
                                if cancel_event.is_set():
                                    _send({"type": "info", "content": "\u4efb\u52a1\u5df2\u6682\u505c\uff0c\u8df3\u8fc7\u5269\u4f59\u5de5\u5177\u8c03\u7528\u3002"})
                                    break
                                fn = tool_map.get(tc.function.name)
                                if fn is None:
                                    result_str = f"Error: tool '{tc.function.name}' not found"
                                else:
                                    try:
                                        import json as _json
                                        result_str = str(fn(**_json.loads(tc.function.arguments)))
                                    except Exception as exc:
                                        result_str = f"Error: {exc}"
                                # 发送工具结果（截断避免超大）
                                preview = result_str[:500] + ("..." if len(result_str) > 500 else "")
                                log_lines.append({"type": "tool_result", "content": preview})
                                _send({"type": "tool_result", "content": preview})
                                # Auto-save MCP screenshots to file manager
                                _try_save_file(result_str, tc.function.name, project_id, db)
                                # Strip image_base64 before passing to LLM to avoid
                                # wasting context tokens on unreadable binary data.
                                llm_result = _strip_image_b64(result_str)
                                # 大结果转 artifact，LLM 按需翻页（彻底替代截断）
                                _limit = _page_max if tc.function.name == "browser_get_page_source" else _tool_max
                                if tc.function.name not in _ARTIFACT_NO_STORE and len(llm_result) > _limit:
                                    llm_result = _store_as_artifact(llm_result, tc.function.name)
                                messages.append({"role": "tool", "tool_call_id": tc.id,
                                                 "content": llm_result})
                            # \u6240\u6709\u5de5\u5177\u6267\u884c\u5b8c\u6210\u540e\u518d\u68c0\u67e5\u4e00\u6b21\u53d6\u6d88\u4fe1\u53f7
                            if cancel_event.is_set():
                                _send({"type": "info", "content": "\u4efb\u52a1\u5df2\u6682\u505c\uff0c\u5bf9\u8bdd\u5386\u53f2\u5df2\u4fdd\u5b58\uff0c\u53ef\u968f\u65f6\u7eed\u8dd1\u3002"})
                                break
                        else:
                            final_text = msg.content or ""
                            log_lines.append({"type": "result", "content": final_text})
                            _send({"type": "result", "content": final_text})
                            break
                    else:
                        # 循环跑满 max_iterations 仍未结束
                        warn_msg = f"已达到最大迭代次数（{cfg2.max_iterations} 次），任务自动停止。如需继续请再次运行，或通过环境变量 SECAGENT_MAX_ITERATIONS 增大上限。"
                        log_lines.append({"type": "result", "content": warn_msg})
                        _send({"type": "result", "content": warn_msg})
                        final_text = warn_msg
                    return final_text
                runner._run_openai = patched
            else:
                # Patch Anthropic path
                import anthropic as _anth
                def patched(user_message: str, verbose: bool = True) -> str:
                    cfg2 = runner.config
                    messages = [{"role": "user", "content": user_message}]
                    wrapped = [
                        _anth.beta_tool(t) if not isinstance(t, _anth.BetaTool) else t
                        for t in runner.tools
                    ]
                    final_text = ""
                    it = runner._client.beta.messages.tool_runner(
                        model=cfg2.get_effective_model(), max_tokens=cfg2.max_tokens,
                        system=runner.system_prompt, tools=wrapped, messages=messages,
                    )
                    for i, message in enumerate(it):
                        if i >= cfg2.max_iterations:
                            break
                        stop = getattr(message, "stop_reason", "")
                        if stop == "tool_use":
                            for block in message.content:
                                if block.type == "text" and block.text.strip():
                                    log_lines.append({"type": "think", "content": block.text.strip()})
                                    _send({"type": "think", "content": block.text.strip()})
                                elif block.type == "tool_use":
                                    call_line = f"{block.name}({json.dumps(block.input)[:300]})"
                                    log_lines.append({"type": "tool", "content": call_line})
                                    _send({"type": "tool", "content": call_line})
                        elif stop == "end_turn":
                            for block in message.content:
                                if hasattr(block, "text"):
                                    final_text = block.text
                                    log_lines.append({"type": "result", "content": final_text})
                                    _send({"type": "result", "content": final_text})
                    return final_text
                runner._run_anthropic = patched

            parts = []
            if project.target:
                parts.append(f"目标: {project.target}")
            if task_text:
                parts.append(f"任务: {task_text}")
            if extra:
                parts.append(f"补充说明: {extra}")
            user_msg = "\n".join(parts) or "开始渗透测试"
            return runner.run(user_msg, verbose=False)

        # \u2500\u2500 \u5c06 _run_with_streaming \u653e\u5165\u72ec\u7acb\u7ebf\u7a0b\uff0c\u65b9\u4fbf\u8ffd\u8e2a\u548c\u5f3a\u5236\u53d6\u6d88 \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
        _result_box: dict[str, Any] = {}

        def _thread_target() -> None:
            try:
                _result_box["result"] = _run_with_streaming()
            except Exception as exc:
                _result_box["error"] = exc

        _t = threading.Thread(target=_thread_target, daemon=True)
        _agent_threads[project_id] = _t
        _t.start()

        # \u5f02\u6b65\u8f6e\u8be2\uff0c\u76f4\u5230\u7ebf\u7a0b\u7ed3\u675f
        while _t.is_alive():
            await asyncio.sleep(0.2)

        if "error" in _result_box:
            raise _result_box["error"]
        result = _result_box.get("result", "")

        log_entry = TaskLog(project_id=project_id, content=json.dumps(log_lines, ensure_ascii=False))
        db.add(log_entry)
        project.status = "completed"
        db.commit()

        await websocket.send_json({"type": "done", "content": result})

    except WebSocketDisconnect:
        logger.info("WS disconnected: project %s", project_id)
        cancel_event.set()
        await asyncio.sleep(0.3)  # 等待 agent 线程更新 messages_ref
        snapshot = messages_ref.get("data", [])
        try:
            from secagent.web.models import Project as _P, TaskLog as _TL
            if log_lines:
                db.add(_TL(project_id=project_id,
                           content=json.dumps(log_lines, ensure_ascii=False)))
            _proj = db.get(_P, project_id)
            if _proj:
                _proj.status = "paused"
                if snapshot:
                    _proj.conversation_snapshot = json.dumps(snapshot, ensure_ascii=False)
            db.commit()
        except Exception:
            pass
    except Exception as exc:
        logger.exception("WS error")
        # Save partial logs even on unexpected errors
        if log_lines:
            try:
                from secagent.web.models import TaskLog as _TL2
                db.add(_TL2(project_id=project_id,
                            content=json.dumps(log_lines, ensure_ascii=False)))
                db.commit()
            except Exception:
                pass
        try:
            await websocket.send_json({"type": "error", "message": str(exc)})
        except Exception:
            pass
    finally:
        _cancel_events.pop(project_id, None)
        _agent_threads.pop(project_id, None)
        project_row = db.get(Project, project_id)
        if project_row and project_row.status == "running":
            project_row.status = "idle"
            db.commit()
        db.close()


# \u2500\u2500 Terminate project (hard stop) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500

@app.post("/api/projects/{project_id}/terminate")
async def terminate_project(project_id: int):
    """Hard-stop a running agent for the given project."""
    from secagent.web.database import SessionLocal as _SL
    from secagent.web.models import Project as _P
    # \u53d1\u51fa\u53d6\u6d88\u4fe1\u53f7
    if project_id in _cancel_events:
        _cancel_events[project_id].set()
    _db = _SL()
    try:
        proj = _db.get(_P, project_id)
        if proj:
            proj.status = "idle"
            proj.conversation_snapshot = ""  # \u5f3a\u5236\u7ec8\u6b62\u65f6\u6e05\u9664\u5feb\u7167
            _db.commit()
        return {"ok": True}
    finally:
        _db.close()


# ── Task logs ─────────────────────────────────────────────────────────────────

@app.get("/api/logs/{project_id}")
def get_logs(project_id: int):
    from secagent.web.database import SessionLocal
    from secagent.web.models import TaskLog, Project
    db: Session = SessionLocal()
    try:
        project = db.get(Project, project_id)
        # Only return logs created AFTER the project was created to avoid showing
        # stale logs from a previous project that reused this ID.
        q = db.query(TaskLog).filter(TaskLog.project_id == project_id)
        if project:
            q = q.filter(TaskLog.created_at >= project.created_at)
        logs = q.order_by(TaskLog.created_at.desc()).limit(30).all()
        result = []
        for l in logs:
            try:
                entries = json.loads(l.content) if l.content.startswith("[") else [{"type": "result", "content": l.content}]
            except Exception:
                entries = [{"type": "result", "content": l.content}]
            result.append({"id": l.id, "entries": entries, "created_at": l.created_at.isoformat()})
        return result
    finally:
        db.close()


# ── Startup ───────────────────────────────────────────────────────────────────

@app.post("/api/admin/reseed")
def admin_reseed():
    """Re-insert any missing built-in tools / agents / MCPs."""
    counts = reseed_builtin()
    return {"ok": True, "inserted": counts}


@app.on_event("startup")
def on_startup():
    init_db()
    counts = reseed_builtin()   # idempotent — fills gaps if DB already exists
    # Reset any projects stuck in "running" from a previous crashed server
    from sqlalchemy.orm import Session as _Session
    from secagent.web.database import SessionLocal as _SL
    from secagent.web.models import Project as _Proj
    _db: _Session = _SL()
    try:
        stuck = _db.query(_Proj).filter(_Proj.status == "running").all()
        for p in stuck:
            p.status = "idle"
        if stuck:
            _db.commit()
            logger.info("Reset %d stuck 'running' project(s) to 'idle'", len(stuck))
    finally:
        _db.close()
    logger.info("secAgent UI ready at http://localhost:8888 | seeded: %s", counts)


def serve(host: str = "0.0.0.0", port: int = 8888, reload: bool = False) -> None:
    uvicorn.run("secagent.web.app:app", host=host, port=port, reload=reload, log_level="info")
