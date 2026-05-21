"""Projects CRUD router."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from secagent.web.database import get_db
from secagent.web.models import Project
from secagent.web.schemas import ProjectCreate, ProjectOut, ProjectUpdate

router = APIRouter(prefix="/api/projects", tags=["projects"])


@router.get("/", response_model=list[ProjectOut])
def list_projects(db: Session = Depends(get_db)):
    return db.query(Project).order_by(Project.created_at.desc()).all()


@router.post("/", response_model=ProjectOut)
def create_project(body: ProjectCreate, db: Session = Depends(get_db)):
    p = Project(**body.model_dump())
    db.add(p)
    db.commit()
    db.refresh(p)
    return p


@router.get("/{pid}", response_model=ProjectOut)
def get_project(pid: int, db: Session = Depends(get_db)):
    p = db.get(Project, pid)
    if not p:
        raise HTTPException(404, "Project not found")
    return p


@router.patch("/{pid}", response_model=ProjectOut)
def update_project(pid: int, body: ProjectUpdate, db: Session = Depends(get_db)):
    p = db.get(Project, pid)
    if not p:
        raise HTTPException(404, "Project not found")
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(p, k, v)
    db.commit()
    db.refresh(p)
    return p


@router.delete("/{pid}")
def delete_project(pid: int, db: Session = Depends(get_db)):
    p = db.get(Project, pid)
    if not p:
        raise HTTPException(404, "Project not found")
    db.delete(p)
    db.commit()
    return {"ok": True}
