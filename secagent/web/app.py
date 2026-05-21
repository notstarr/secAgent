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
from pathlib import Path

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from secagent.web.database import init_db
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
    from secagent.web.models import Project, AgentModel, Setting, TaskLog, Vulnerability
    from secagent.core.config import AgentConfig

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

        # Build config from saved settings
        settings = {r.key: r.value for r in db.query(Setting).all()}
        cfg = AgentConfig(
            api_key=settings.get("api_key", ""),
            model=settings.get("model", "claude-opus-4-5-20250929"),
        )
        if settings.get("base_url"):
            cfg.openai_compat_base_url = settings["base_url"]
            cfg.openai_compat_api_key = settings.get("api_key", "")
            cfg.openai_compat_model = settings.get("model")

        # Intercept runner output and stream to WS
        import io
        from contextlib import redirect_stdout
        from secagent.agents.sigma_agent import SigmaAgent

        agent = SigmaAgent(config=cfg)
        log_lines: list[str] = []

        async def stream_run():
            loop = asyncio.get_event_loop()

            def _run():
                # Capture rich output by patching runner
                original_run = agent.runner.run

                def patched_run(user_message: str, verbose: bool = True) -> str:
                    # Wrap to intercept tool call messages
                    import anthropic
                    from secagent.core.agent_runner import AgentRunner
                    cfg2 = agent.runner.config
                    client = agent.runner._client
                    messages = [{"role": "user", "content": user_message}]
                    final_text = ""
                    iteration = 0
                    wrapped_tools = [
                        anthropic.beta_tool(t) if not isinstance(t, anthropic.BetaTool) else t
                        for t in agent.runner.tools
                    ]
                    runner_iter = client.beta.messages.tool_runner(
                        model=cfg2.get_effective_model(),
                        max_tokens=cfg2.max_tokens,
                        system=agent.runner.system_prompt,
                        tools=wrapped_tools,
                        messages=messages,
                    )
                    for message in runner_iter:
                        iteration += 1
                        stop = getattr(message, "stop_reason", "unknown")
                        if stop == "tool_use":
                            for block in message.content:
                                if block.type == "tool_use":
                                    line = f"[TOOL] {block.name}: {json.dumps(block.input)[:200]}"
                                    log_lines.append(line)
                                    asyncio.run_coroutine_threadsafe(
                                        websocket.send_json({"type": "tool", "content": line}),
                                        loop,
                                    )
                        elif stop == "end_turn":
                            for block in message.content:
                                if hasattr(block, "text"):
                                    final_text = block.text
                                    asyncio.run_coroutine_threadsafe(
                                        websocket.send_json({"type": "result", "content": final_text}),
                                        loop,
                                    )
                    return final_text

                agent.runner.run = patched_run
                return agent.run(
                    target=project.target or task_text,
                    extra_instructions=extra,
                    verbose=False,
                )

            result = await loop.run_in_executor(None, _run)
            return result

        result = await stream_run()

        # Save log
        log_entry = TaskLog(project_id=project_id, content="\n".join(log_lines))
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
        logs = db.query(TaskLog).filter_by(project_id=project_id).order_by(TaskLog.created_at.desc()).limit(20).all()
        return [{"id": l.id, "content": l.content, "created_at": l.created_at.isoformat()} for l in logs]
    finally:
        db.close()


# ── Startup ───────────────────────────────────────────────────────────────────

@app.on_event("startup")
def on_startup():
    init_db()
    logger.info("secAgent UI ready at http://localhost:8888")


def serve(host: str = "0.0.0.0", port: int = 8888, reload: bool = False) -> None:
    uvicorn.run("secagent.web.app:app", host=host, port=port, reload=reload, log_level="info")
