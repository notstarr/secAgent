"""
Project-scoped memory tools.

Provides memory_store / memory_recall / memory_list / memory_delete
that agents can call like any other tool.  Data persists in SQLite
across runs within the same project.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any

from secagent.web.database import SessionLocal
from secagent.web.models import ProjectMemory

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Tool classes — compatible with AgentRunner's tool interface
#   (name / description / input_schema / __call__)
# ---------------------------------------------------------------------------

class MemoryStore:
    """Store or update a key-value memory entry for the current project."""

    name = "memory_store"
    description = (
        "将一条信息保存到项目记忆中。如果 key 已存在则覆盖。"
        "用于记录侦察结果、已发现的端口/子域名/入口点等关键信息，"
        "以便后续运行或其他子智能体复用。"
    )
    input_schema = {
        "type": "object",
        "properties": {
            "key": {
                "type": "string",
                "description": "记忆条目的键名，如 open_ports、discovered_subdomains、waf_info",
            },
            "value": {
                "type": "string",
                "description": "要保存的内容（纯文本或 JSON 字符串）",
            },
        },
        "required": ["key", "value"],
    }

    def __init__(self, project_id: int, source: str = "") -> None:
        self._project_id = project_id
        self._source = source

    def __call__(self, key: str, value: str) -> str:
        db = SessionLocal()
        try:
            existing = (
                db.query(ProjectMemory)
                .filter_by(project_id=self._project_id, key=key)
                .first()
            )
            if existing:
                existing.value = value
                existing.source = self._source
                existing.updated_at = datetime.utcnow()
                action = "updated"
            else:
                entry = ProjectMemory(
                    project_id=self._project_id,
                    key=key,
                    value=value,
                    source=self._source,
                )
                db.add(entry)
                action = "created"
            db.commit()
            return json.dumps({"status": "ok", "action": action, "key": key}, ensure_ascii=False)
        except Exception as exc:
            db.rollback()
            logger.exception("memory_store failed")
            return json.dumps({"status": "error", "message": str(exc)}, ensure_ascii=False)
        finally:
            db.close()


class MemoryRecall:
    """Recall one or more memory entries by key (supports prefix match)."""

    name = "memory_recall"
    description = (
        "从项目记忆中检索信息。可精确匹配 key，也支持前缀模糊查找。"
        "用于获取之前运行保存的侦察结果、端口列表、已知漏洞等。"
    )
    input_schema = {
        "type": "object",
        "properties": {
            "key": {
                "type": "string",
                "description": "要查找的 key（精确匹配）。留空则返回全部记忆。",
            },
            "prefix": {
                "type": "string",
                "description": "按前缀模糊搜索 key（可选，与 key 二选一）",
            },
        },
        "required": [],
    }

    def __init__(self, project_id: int) -> None:
        self._project_id = project_id

    def __call__(self, key: str = "", prefix: str = "") -> str:
        db = SessionLocal()
        try:
            q = db.query(ProjectMemory).filter_by(project_id=self._project_id)
            if key:
                q = q.filter_by(key=key)
            elif prefix:
                q = q.filter(ProjectMemory.key.like(f"{prefix}%"))
            rows = q.order_by(ProjectMemory.updated_at.desc()).limit(50).all()
            results = [
                {
                    "key": r.key,
                    "value": r.value,
                    "source": r.source,
                    "updated_at": r.updated_at.isoformat() if r.updated_at else "",
                }
                for r in rows
            ]
            return json.dumps(results, ensure_ascii=False)
        except Exception as exc:
            logger.exception("memory_recall failed")
            return json.dumps({"status": "error", "message": str(exc)}, ensure_ascii=False)
        finally:
            db.close()


class MemoryList:
    """List all memory keys for the current project."""

    name = "memory_list"
    description = "列出当前项目的所有记忆条目 key，快速了解已有哪些历史信息。"
    input_schema = {
        "type": "object",
        "properties": {},
        "required": [],
    }

    def __init__(self, project_id: int) -> None:
        self._project_id = project_id

    def __call__(self) -> str:
        db = SessionLocal()
        try:
            rows = (
                db.query(ProjectMemory.key, ProjectMemory.source, ProjectMemory.updated_at)
                .filter_by(project_id=self._project_id)
                .order_by(ProjectMemory.updated_at.desc())
                .all()
            )
            results = [
                {"key": r.key, "source": r.source, "updated_at": r.updated_at.isoformat() if r.updated_at else ""}
                for r in rows
            ]
            return json.dumps(results, ensure_ascii=False)
        except Exception as exc:
            logger.exception("memory_list failed")
            return json.dumps({"status": "error", "message": str(exc)}, ensure_ascii=False)
        finally:
            db.close()


class MemoryDelete:
    """Delete a memory entry by key."""

    name = "memory_delete"
    description = "删除一条项目记忆。用于清理过时或错误的信息。"
    input_schema = {
        "type": "object",
        "properties": {
            "key": {
                "type": "string",
                "description": "要删除的记忆 key",
            },
        },
        "required": ["key"],
    }

    def __init__(self, project_id: int) -> None:
        self._project_id = project_id

    def __call__(self, key: str) -> str:
        db = SessionLocal()
        try:
            deleted = (
                db.query(ProjectMemory)
                .filter_by(project_id=self._project_id, key=key)
                .delete()
            )
            db.commit()
            return json.dumps({"status": "ok", "deleted": deleted, "key": key}, ensure_ascii=False)
        except Exception as exc:
            db.rollback()
            logger.exception("memory_delete failed")
            return json.dumps({"status": "error", "message": str(exc)}, ensure_ascii=False)
        finally:
            db.close()


# ---------------------------------------------------------------------------
# Factory — create all memory tools for a project
# ---------------------------------------------------------------------------

def build_memory_tools(project_id: int, source: str = "") -> list:
    """Return a list of memory tool instances bound to a specific project."""
    return [
        MemoryStore(project_id, source=source),
        MemoryRecall(project_id),
        MemoryList(project_id),
        MemoryDelete(project_id),
    ]


def get_memory_summary(project_id: int, max_entries: int = 20) -> str:
    """
    Build a text summary of existing project memories for injection into
    the system prompt.  Returns empty string if no memories exist.
    """
    db = SessionLocal()
    try:
        rows = (
            db.query(ProjectMemory)
            .filter_by(project_id=project_id)
            .order_by(ProjectMemory.updated_at.desc())
            .limit(max_entries)
            .all()
        )
        if not rows:
            return ""
        lines = ["## 项目历史记忆（来自之前的运行）\n"]
        for r in rows:
            preview = r.value[:500] + ("..." if len(r.value) > 500 else "")
            lines.append(f"- **{r.key}** ({r.source}): {preview}")
        lines.append("\n你可以用 `memory_recall` 获取完整内容，用 `memory_store` 更新信息。\n")
        return "\n".join(lines)
    finally:
        db.close()
