"""MCP servers CRUD router."""

import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from secagent.web.database import get_db
from secagent.web.models import MCPServer
from secagent.web.schemas import MCPCreate, MCPOut, MCPUpdate

router = APIRouter(prefix="/api/mcps", tags=["mcps"])


@router.get("/", response_model=list[MCPOut])
def list_mcps(db: Session = Depends(get_db)):
    return db.query(MCPServer).order_by(MCPServer.created_at.desc()).all()


@router.post("/", response_model=MCPOut)
def create_mcp(body: MCPCreate, db: Session = Depends(get_db)):
    m = MCPServer(**body.model_dump())
    db.add(m)
    db.commit()
    db.refresh(m)
    return m


@router.get("/{mid}", response_model=MCPOut)
def get_mcp(mid: int, db: Session = Depends(get_db)):
    m = db.get(MCPServer, mid)
    if not m:
        raise HTTPException(404)
    return m


@router.patch("/{mid}", response_model=MCPOut)
def update_mcp(mid: int, body: MCPUpdate, db: Session = Depends(get_db)):
    m = db.get(MCPServer, mid)
    if not m:
        raise HTTPException(404)
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(m, k, v)
    db.commit()
    db.refresh(m)
    return m


@router.delete("/{mid}")
def delete_mcp(mid: int, db: Session = Depends(get_db)):
    m = db.get(MCPServer, mid)
    if not m:
        raise HTTPException(404)
    db.delete(m)
    db.commit()
    return {"ok": True}


@router.post("/{mid}/test")
async def test_mcp(mid: int, db: Session = Depends(get_db)):
    """Connect to MCP server, list tools, return result."""
    import asyncio
    import shlex

    m = db.get(MCPServer, mid)
    if not m:
        raise HTTPException(404)

    cmd_parts = shlex.split(m.command or "python")
    args = json.loads(m.args_json or "[]")
    all_args = cmd_parts[1:] + args
    env = json.loads(m.env_json or "{}")

    try:
        from mcp import ClientSession
        from mcp.client.stdio import StdioServerParameters, stdio_client

        params = StdioServerParameters(command=cmd_parts[0], args=all_args, env=env)

        async def _run():
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    tools_result = await session.list_tools()
                    return [
                        {"name": t.name, "description": t.description or ""}
                        for t in tools_result.tools
                    ]

        tools = await asyncio.wait_for(_run(), timeout=20)
        return {"ok": True, "tools": tools}
    except asyncio.TimeoutError:
        return {"ok": False, "error": "连接超时（20s），请检查命令配置"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
