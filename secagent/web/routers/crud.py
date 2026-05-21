"""Tools / Agents / Skills / Settings routers."""

from typing import Any, Optional

from fastapi import APIRouter, Body, Depends, HTTPException
from sqlalchemy.orm import Session

from secagent.web.database import get_db
from secagent.web.models import AgentModel, Setting, Skill, ToolDef
from secagent.web.schemas import (
    AgentCreate, AgentOut, AgentUpdate,
    SettingUpdate,
    SkillCreate, SkillOut, SkillUpdate,
    ToolCreate, ToolOut, ToolUpdate,
)

# ── Tools ─────────────────────────────────────────────────────────────────────

tools_router = APIRouter(prefix="/api/tools", tags=["tools"])


@tools_router.get("/", response_model=list[ToolOut])
def list_tools(db: Session = Depends(get_db)):
    return db.query(ToolDef).order_by(ToolDef.created_at.desc()).all()


@tools_router.post("/", response_model=ToolOut)
def create_tool(body: ToolCreate, db: Session = Depends(get_db)):
    t = ToolDef(**body.model_dump())
    db.add(t)
    db.commit()
    db.refresh(t)
    return t


@tools_router.get("/{tid}", response_model=ToolOut)
def get_tool(tid: int, db: Session = Depends(get_db)):
    t = db.get(ToolDef, tid)
    if not t:
        raise HTTPException(404)
    return t


@tools_router.patch("/{tid}", response_model=ToolOut)
def update_tool(tid: int, body: ToolUpdate, db: Session = Depends(get_db)):
    t = db.get(ToolDef, tid)
    if not t:
        raise HTTPException(404)
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(t, k, v)
    db.commit()
    db.refresh(t)
    return t


@tools_router.delete("/{tid}")
def delete_tool(tid: int, db: Session = Depends(get_db)):
    t = db.get(ToolDef, tid)
    if not t:
        raise HTTPException(404)
    db.delete(t)
    db.commit()
    return {"ok": True}


@tools_router.post("/{tid}/test")
def test_tool(tid: int, db: Session = Depends(get_db), body: Optional[dict[str, Any]] = Body(default=None)):
    """Call a built-in tool with provided kwargs and return the result."""
    from secagent.tools.network_tools import dns_lookup, port_scan, whois_lookup
    from secagent.tools.web_tools import (
        fetch_http_headers, http_request, detect_waf, crawl_links, check_common_vulns
    )
    from secagent.tools.pentest_tools import (
        scan_xss, scan_sqli, scan_ssrf, fuzz_paths, extract_js_endpoints, test_idor
    )
    _ALL = {
        "dns_lookup": dns_lookup, "port_scan": port_scan, "whois_lookup": whois_lookup,
        "fetch_http_headers": fetch_http_headers, "http_request": http_request,
        "detect_waf": detect_waf, "crawl_links": crawl_links,
        "check_common_vulns": check_common_vulns,
        "scan_xss": scan_xss, "scan_sqli": scan_sqli, "scan_ssrf": scan_ssrf,
        "fuzz_paths": fuzz_paths, "extract_js_endpoints": extract_js_endpoints,
        "test_idor": test_idor,
    }
    t = db.get(ToolDef, tid)
    if not t:
        raise HTTPException(404)
    fn = _ALL.get(t.name)
    if fn is None:
        return {"ok": False, "error": f"工具函数 '{t.name}' 未在内置列表中，无法直接测试"}
    try:
        result = fn(**(body or {}))
        return {"ok": True, "result": str(result)[:3000]}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": True}


# ── Agents ────────────────────────────────────────────────────────────────────

agents_router = APIRouter(prefix="/api/agents", tags=["agents"])


@agents_router.get("/", response_model=list[AgentOut])
def list_agents(db: Session = Depends(get_db)):
    return db.query(AgentModel).order_by(AgentModel.created_at.desc()).all()


@agents_router.post("/", response_model=AgentOut)
def create_agent(body: AgentCreate, db: Session = Depends(get_db)):
    a = AgentModel(**body.model_dump())
    db.add(a)
    db.commit()
    db.refresh(a)
    return a


@agents_router.get("/{aid}", response_model=AgentOut)
def get_agent(aid: int, db: Session = Depends(get_db)):
    a = db.get(AgentModel, aid)
    if not a:
        raise HTTPException(404)
    return a


@agents_router.patch("/{aid}", response_model=AgentOut)
def update_agent(aid: int, body: AgentUpdate, db: Session = Depends(get_db)):
    a = db.get(AgentModel, aid)
    if not a:
        raise HTTPException(404)
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(a, k, v)
    db.commit()
    db.refresh(a)
    return a


@agents_router.delete("/{aid}")
def delete_agent(aid: int, db: Session = Depends(get_db)):
    a = db.get(AgentModel, aid)
    if not a:
        raise HTTPException(404)
    db.delete(a)
    db.commit()
    return {"ok": True}


# ── Skills ────────────────────────────────────────────────────────────────────

skills_router = APIRouter(prefix="/api/skills", tags=["skills"])


@skills_router.get("/", response_model=list[SkillOut])
def list_skills(db: Session = Depends(get_db)):
    return db.query(Skill).order_by(Skill.created_at.desc()).all()


@skills_router.post("/", response_model=SkillOut)
def create_skill(body: SkillCreate, db: Session = Depends(get_db)):
    s = Skill(**body.model_dump())
    db.add(s)
    db.commit()
    db.refresh(s)
    return s


@skills_router.get("/{sid}", response_model=SkillOut)
def get_skill(sid: int, db: Session = Depends(get_db)):
    s = db.get(Skill, sid)
    if not s:
        raise HTTPException(404)
    return s


@skills_router.patch("/{sid}", response_model=SkillOut)
def update_skill(sid: int, body: SkillUpdate, db: Session = Depends(get_db)):
    s = db.get(Skill, sid)
    if not s:
        raise HTTPException(404)
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(s, k, v)
    db.commit()
    db.refresh(s)
    return s


@skills_router.delete("/{sid}")
def delete_skill(sid: int, db: Session = Depends(get_db)):
    s = db.get(Skill, sid)
    if not s:
        raise HTTPException(404)
    db.delete(s)
    db.commit()
    return {"ok": True}


# ── Settings ──────────────────────────────────────────────────────────────────

settings_router = APIRouter(prefix="/api/settings", tags=["settings"])


@settings_router.get("/")
def get_settings(db: Session = Depends(get_db)):
    rows = db.query(Setting).all()
    result = {r.key: r.value for r in rows}
    # Never expose api_key in full
    if "api_key" in result and result["api_key"]:
        result["api_key"] = "••••••••"
    return result


@settings_router.patch("/")
def update_settings(body: SettingUpdate, db: Session = Depends(get_db)):
    data = body.model_dump(exclude_none=True)
    for key, val in data.items():
        row = db.get(Setting, key)
        if row:
            row.value = val
        else:
            db.add(Setting(key=key, value=val))
    db.commit()
    return {"ok": True}


@settings_router.post("/api-key")
def set_api_key(api_key: str, db: Session = Depends(get_db)):
    """Separate endpoint to update the raw API key."""
    row = db.get(Setting, "api_key")
    if row:
        row.value = api_key
    else:
        db.add(Setting(key="api_key", value=api_key))
    db.commit()
    return {"ok": True}
