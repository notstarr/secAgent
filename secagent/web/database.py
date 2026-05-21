"""SQLite database setup with SQLAlchemy."""

from __future__ import annotations

import os
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

DB_PATH = Path(os.environ.get("SECAGENT_DB", "secagent.db"))
DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
    echo=False,
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


def get_db():
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create all tables and seed default data."""
    from secagent.web import models  # noqa: F401 — registers models
    Base.metadata.create_all(bind=engine)
    _seed_defaults()


def _seed_defaults() -> None:
    """Insert default settings and built-in agent if the DB is freshly created."""
    from secagent.web.models import Setting, AgentModel
    db: Session = SessionLocal()
    try:
        if not db.query(Setting).filter_by(key="theme").first():
            db.add_all([
                Setting(key="theme", value="light"),
                Setting(key="provider", value="anthropic"),
                Setting(key="model", value="claude-opus-4-5-20250929"),
                Setting(key="api_key", value=""),
                Setting(key="base_url", value=""),
            ])
        if not db.query(AgentModel).first():
            from secagent.prompts.sigma_single import SIGMA_SINGLE_AGENT_PROMPT
            db.add(AgentModel(
                name="sigmaAI",
                description="专业网络安全渗透测试专家 (单智能体模式)",
                mode="single",
                system_prompt=SIGMA_SINGLE_AGENT_PROMPT,
                tools_json="[]",
                mcps_json="[]",
            ))
        db.commit()
    finally:
        db.close()
