"""Project file management router."""

from __future__ import annotations

import mimetypes
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from secagent.web.database import get_db
from secagent.web.models import Project, ProjectFile

router = APIRouter(prefix="/api/files", tags=["files"])

# Files are stored relative to the DB path
FILES_DIR = Path("secagent_files")


def _ensure_dir() -> Path:
    FILES_DIR.mkdir(parents=True, exist_ok=True)
    return FILES_DIR


# ── List ──────────────────────────────────────────────────────────────────────

@router.get("/")
def list_files(project_id: int | None = None, db: Session = Depends(get_db)):
    q = db.query(ProjectFile)
    if project_id is not None:
        q = q.filter(ProjectFile.project_id == project_id)
    files = q.order_by(ProjectFile.created_at.desc()).all()

    # Build response with project name
    result = []
    project_cache: dict[int, str] = {}
    for f in files:
        pid = f.project_id
        if pid and pid not in project_cache:
            p = db.get(Project, pid)
            project_cache[pid] = p.name if p else "未知项目"
        result.append({
            "id": f.id,
            "name": f.name,
            "mime_type": f.mime_type,
            "size": f.size,
            "source": f.source,
            "created_at": f.created_at.isoformat(),
            "project_id": f.project_id,
            "project_name": project_cache.get(pid, "无项目") if pid else "无项目",
        })
    return result


# ── Upload ────────────────────────────────────────────────────────────────────

@router.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    project_id: int | None = Form(default=None),
    db: Session = Depends(get_db),
):
    d = _ensure_dir()
    ext = Path(file.filename or "file").suffix or ""
    rel_path = f"{uuid.uuid4().hex}{ext}"
    dest = d / rel_path

    content = await file.read()
    dest.write_bytes(content)

    mime = file.content_type or mimetypes.guess_type(file.filename or "")[0] or "application/octet-stream"
    pf = ProjectFile(
        project_id=project_id,
        name=file.filename or rel_path,
        path=rel_path,
        mime_type=mime,
        size=len(content),
        source="upload",
    )
    db.add(pf)
    db.commit()
    db.refresh(pf)
    return {"id": pf.id, "name": pf.name, "size": pf.size, "mime_type": pf.mime_type}


# ── Download / preview ────────────────────────────────────────────────────────

@router.get("/{fid}/download")
def download_file(fid: int, db: Session = Depends(get_db)):
    pf = db.get(ProjectFile, fid)
    if not pf:
        raise HTTPException(404)
    dest = _ensure_dir() / pf.path
    if not dest.exists():
        raise HTTPException(404, detail="File not found on disk")
    return FileResponse(
        path=str(dest),
        media_type=pf.mime_type,
        filename=pf.name,
    )


# ── Delete ────────────────────────────────────────────────────────────────────

@router.delete("/{fid}")
def delete_file(fid: int, db: Session = Depends(get_db)):
    pf = db.get(ProjectFile, fid)
    if not pf:
        raise HTTPException(404)
    dest = _ensure_dir() / pf.path
    if dest.exists():
        dest.unlink(missing_ok=True)
    db.delete(pf)
    db.commit()
    return {"ok": True}
