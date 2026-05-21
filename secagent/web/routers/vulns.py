"""Vulnerabilities CRUD + review router."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from secagent.web.database import get_db
from secagent.web.models import Vulnerability
from secagent.web.schemas import VulnCreate, VulnOut, VulnUpdate

router = APIRouter(prefix="/api/vulns", tags=["vulns"])


@router.get("/", response_model=list[VulnOut])
def list_vulns(project_id: int | None = None, db: Session = Depends(get_db)):
    q = db.query(Vulnerability)
    if project_id:
        q = q.filter(Vulnerability.project_id == project_id)
    return q.order_by(Vulnerability.discovered_at.desc()).all()


@router.post("/", response_model=VulnOut)
def create_vuln(body: VulnCreate, db: Session = Depends(get_db)):
    v = Vulnerability(**body.model_dump())
    db.add(v)
    db.commit()
    db.refresh(v)
    return v


@router.get("/{vid}", response_model=VulnOut)
def get_vuln(vid: int, db: Session = Depends(get_db)):
    v = db.get(Vulnerability, vid)
    if not v:
        raise HTTPException(404, "Vulnerability not found")
    return v


@router.patch("/{vid}", response_model=VulnOut)
def update_vuln(vid: int, body: VulnUpdate, db: Session = Depends(get_db)):
    v = db.get(Vulnerability, vid)
    if not v:
        raise HTTPException(404, "Vulnerability not found")
    for k, val in body.model_dump(exclude_none=True).items():
        setattr(v, k, val)
    db.commit()
    db.refresh(v)
    return v


@router.delete("/{vid}")
def delete_vuln(vid: int, db: Session = Depends(get_db)):
    v = db.get(Vulnerability, vid)
    if not v:
        raise HTTPException(404, "Not found")
    db.delete(v)
    db.commit()
    return {"ok": True}


@router.post("/{vid}/review")
def review_vuln(vid: int, status: str, note: str = "", db: Session = Depends(get_db)):
    """Human review: confirm or mark as false_positive."""
    if status not in ("confirmed", "false_positive", "pending"):
        raise HTTPException(400, "Invalid status")
    v = db.get(Vulnerability, vid)
    if not v:
        raise HTTPException(404, "Not found")
    v.status = status
    v.review_note = note
    db.commit()
    db.refresh(v)
    return {"ok": True, "status": v.status}
