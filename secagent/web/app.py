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
        import shlex

        cmd_parts = shlex.split(command) if command else ["python"]
        actual_cmd = cmd_parts[0]
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

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── API routers ───────────────────────────────────────────────────────────────

for r in (projects_router, vulns_router, mcps_router, tools_router, agents_router, skills_router, settings_router):
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

    try:
        raw = await websocket.receive_text()
        payload = json.loads(raw)
        task_text = payload.get("task", "")
        extra = payload.get("extra", "")

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
        _ALL_TOOLS = {
            "dns_lookup": dns_lookup, "port_scan": port_scan, "whois_lookup": whois_lookup,
            "fetch_http_headers": fetch_http_headers, "http_request": http_request,
            "detect_waf": detect_waf, "crawl_links": crawl_links,
            "check_common_vulns": check_common_vulns,
        }
        tools = [_ALL_TOOLS[n] for n in tool_names if n in _ALL_TOOLS] or list(_ALL_TOOLS.values())

        # ── Load MCP server configs from DB ────────────────────────────
        from secagent.web.models import MCPServer as MCPServerModel
        mcp_server_configs: list[dict] = []
        if agent_row:
            try:
                mcp_names: list[str] = json.loads(agent_row.mcps_json or "[]")
            except Exception:
                mcp_names = []
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
                    messages: list[dict] = []
                    if runner.system_prompt:
                        messages.append({"role": "system", "content": runner.system_prompt})
                    messages.append({"role": "user", "content": user_message})

                    final_text = ""
                    for _ in range(cfg2.max_iterations):
                        kwargs: dict = {"model": cfg2.get_effective_model(),
                                        "max_tokens": cfg2.max_tokens, "messages": messages}
                        if oa_tools:
                            kwargs["tools"] = oa_tools
                        resp = runner._client.chat.completions.create(**kwargs)
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
                                messages.append({"role": "tool", "tool_call_id": tc.id,
                                                 "content": result_str})
                        else:
                            final_text = msg.content or ""
                            log_lines.append({"type": "result", "content": final_text})
                            _send({"type": "result", "content": final_text})
                            break
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

        result = await loop.run_in_executor(None, _run_with_streaming)

        log_entry = TaskLog(project_id=project_id, content=json.dumps(log_lines, ensure_ascii=False))
        db.add(log_entry)
        project.status = "completed"
        db.commit()

        await websocket.send_json({"type": "done", "content": result})

    except WebSocketDisconnect:
        logger.info("WS disconnected: project %s", project_id)
    except Exception as exc:
        logger.exception("WS error")
        try:
            await websocket.send_json({"type": "error", "message": str(exc)})
        except Exception:
            pass
    finally:
        project_row = db.get(Project, project_id)
        if project_row and project_row.status == "running":
            project_row.status = "idle"
            db.commit()
        db.close()


# ── Task logs ─────────────────────────────────────────────────────────────────

@app.get("/api/logs/{project_id}")
def get_logs(project_id: int):
    from secagent.web.database import SessionLocal
    from secagent.web.models import TaskLog
    db: Session = SessionLocal()
    try:
        logs = db.query(TaskLog).filter_by(project_id=project_id).order_by(TaskLog.created_at.desc()).limit(30).all()
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
    logger.info("secAgent UI ready at http://localhost:8888 | seeded: %s", counts)


def serve(host: str = "0.0.0.0", port: int = 8888, reload: bool = False) -> None:
    uvicorn.run("secagent.web.app:app", host=host, port=port, reload=reload, log_level="info")
