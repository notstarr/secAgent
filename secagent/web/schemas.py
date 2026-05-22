"""Pydantic schemas for request/response validation."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel


# ── Project ──────────────────────────────────────────────────────────────────

class ProjectCreate(BaseModel):
    name: str
    target: str = ""
    description: str = ""
    mode: str = "single"
    agent_id: Optional[int] = None
    skills_json: str = "[]"


class ProjectUpdate(BaseModel):
    name: Optional[str] = None
    target: Optional[str] = None
    description: Optional[str] = None
    mode: Optional[str] = None
    agent_id: Optional[int] = None
    status: Optional[str] = None
    skills_json: Optional[str] = None


class ProjectOut(BaseModel):
    id: int
    name: str
    target: str
    description: str
    mode: str
    agent_id: Optional[int]
    skills_json: str
    status: str
    created_at: datetime
    model_config = {"from_attributes": True}


# ── Vulnerability ─────────────────────────────────────────────────────────────

class VulnCreate(BaseModel):
    project_id: int
    title: str = ""
    description: str = ""
    severity: str = "info"
    vuln_type: str = ""
    target: str = ""
    poc: str = ""
    request_raw: str = ""
    response_raw: str = ""
    screenshot_b64: str = ""
    impact: str = ""
    recommendation: str = ""


class VulnUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    vuln_type: Optional[str] = None
    status: Optional[str] = None
    review_note: Optional[str] = None
    poc: Optional[str] = None
    request_raw: Optional[str] = None
    response_raw: Optional[str] = None
    impact: Optional[str] = None
    recommendation: Optional[str] = None


class VulnOut(BaseModel):
    id: int
    project_id: int
    title: str
    description: str
    severity: str
    vuln_type: str
    target: str
    poc: str
    request_raw: str
    response_raw: str
    screenshot_b64: str
    impact: str
    recommendation: str
    status: str
    review_note: str
    discovered_at: datetime
    model_config = {"from_attributes": True}


# ── MCP ───────────────────────────────────────────────────────────────────────

class MCPCreate(BaseModel):
    name: str
    description: str = ""
    command: str = ""
    args_json: str = "[]"
    env_json: str = "{}"
    enabled: bool = True


class MCPUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    command: Optional[str] = None
    args_json: Optional[str] = None
    env_json: Optional[str] = None
    enabled: Optional[bool] = None


class MCPOut(BaseModel):
    id: int
    name: str
    description: str
    command: str
    args_json: str
    env_json: str
    enabled: bool
    created_at: datetime
    model_config = {"from_attributes": True}


# ── Tool ──────────────────────────────────────────────────────────────────────

class ToolCreate(BaseModel):
    name: str
    description: str = ""
    code: str = ""
    enabled: bool = True


class ToolUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    code: Optional[str] = None
    enabled: Optional[bool] = None


class ToolOut(BaseModel):
    id: int
    name: str
    description: str
    code: str
    enabled: bool
    created_at: datetime
    model_config = {"from_attributes": True}


# ── Agent ─────────────────────────────────────────────────────────────────────

class AgentCreate(BaseModel):
    name: str
    description: str = ""
    mode: str = "single"
    system_prompt: str = ""
    tools_json: str = "[]"
    mcps_json: str = "[]"
    sub_agents_json: str = "[]"


class AgentUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    mode: Optional[str] = None
    system_prompt: Optional[str] = None
    tools_json: Optional[str] = None
    mcps_json: Optional[str] = None
    sub_agents_json: Optional[str] = None


class AgentOut(BaseModel):
    id: int
    name: str
    description: str
    mode: str
    system_prompt: str
    tools_json: str
    mcps_json: str
    sub_agents_json: str
    created_at: datetime
    model_config = {"from_attributes": True}


# ── Skill ─────────────────────────────────────────────────────────────────────

class SkillCreate(BaseModel):
    name: str
    description: str = ""
    content: str = ""
    tags_json: str = "[]"


class SkillUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    content: Optional[str] = None
    tags_json: Optional[str] = None


class SkillOut(BaseModel):
    id: int
    name: str
    description: str
    content: str
    tags_json: str
    created_at: datetime
    model_config = {"from_attributes": True}


# ── Settings ──────────────────────────────────────────────────────────────────

class SettingUpdate(BaseModel):
    theme: Optional[str] = None
    provider: Optional[str] = None
    model: Optional[str] = None
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    max_iterations: Optional[str] = None
    # Context management
    tool_result_max_chars: Optional[str] = None
    page_source_max_chars: Optional[str] = None
    context_compress_enabled: Optional[str] = None  # "true" / "false"
    context_compress_every_n: Optional[str] = None
    # Executor strategy guard
    strategy_guard_enabled: Optional[str] = None  # "true" / "false"
    strategy_repeat_call_limit: Optional[str] = None
    strategy_no_progress_limit: Optional[str] = None
    strategy_browser_cooldown_rounds: Optional[str] = None
    strategy_browser_ratio_limit_pct: Optional[str] = None
    # LLM request resilience
    llm_request_timeout_sec: Optional[str] = None
    llm_request_retry: Optional[str] = None
