"""REST endpoints for project memory management."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Optional

from secagent.web.database import get_db
from secagent.web.models import ProjectMemory

router = APIRouter(prefix="/api/memories", tags=["memories"])


class MemoryOut(BaseModel):
    id: int
    project_id: int
    key: str
    value: str
    source: str
    created_at: str
    updated_at: str
    model_config = {"from_attributes": True}

    @classmethod
    def from_orm_row(cls, row: ProjectMemory) -> "MemoryOut":
        return cls(
            id=row.id,
            project_id=row.project_id,
            key=row.key,
            value=row.value,
            source=row.source or "",
            created_at=row.created_at.isoformat() if row.created_at else "",
            updated_at=row.updated_at.isoformat() if row.updated_at else "",
        )


class MemoryCreate(BaseModel):
    project_id: int
    key: str
    value: str
    source: str = ""


class MemoryUpdate(BaseModel):
    key: Optional[str] = None
    value: Optional[str] = None
    source: Optional[str] = None


@router.get("/")
def list_memories(
    project_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
):
    q = db.query(ProjectMemory)
    if project_id is not None:
        q = q.filter_by(project_id=project_id)
    rows = q.order_by(ProjectMemory.updated_at.desc()).all()
    return [MemoryOut.from_orm_row(r) for r in rows]


@router.post("/")
def create_memory(body: MemoryCreate, db: Session = Depends(get_db)):
    entry = ProjectMemory(
        project_id=body.project_id,
        key=body.key,
        value=body.value,
        source=body.source,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return MemoryOut.from_orm_row(entry)


@router.patch("/{mid}")
def update_memory(mid: int, body: MemoryUpdate, db: Session = Depends(get_db)):
    entry = db.get(ProjectMemory, mid)
    if not entry:
        raise HTTPException(404, "Memory not found")
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(entry, k, v)
    db.commit()
    db.refresh(entry)
    return MemoryOut.from_orm_row(entry)


@router.delete("/{mid}")
def delete_memory(mid: int, db: Session = Depends(get_db)):
    entry = db.get(ProjectMemory, mid)
    if not entry:
        raise HTTPException(404, "Memory not found")
    db.delete(entry)
    db.commit()
    return {"ok": True}


@router.delete("/")
def delete_memories_by_project(
    project_id: int = Query(...),
    db: Session = Depends(get_db),
):
    count = db.query(ProjectMemory).filter_by(project_id=project_id).delete()
    db.commit()
    return {"ok": True, "deleted": count}
