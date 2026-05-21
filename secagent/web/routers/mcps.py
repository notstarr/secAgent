"""MCP servers CRUD router."""

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
