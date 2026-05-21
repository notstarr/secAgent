"""Vulnerability assessment agent."""

from __future__ import annotations

from typing import Any, Optional

from secagent.agents.base_agent import BaseSecAgent
from secagent.core.config import AgentConfig
from secagent.tools.web_tools import (
    fetch_http_headers,
    http_request,
    detect_waf,
    check_common_vulns,
)
from secagent.tools.network_tools import port_scan


class VulnAgent(BaseSecAgent):
    """
    Automated vulnerability assessment agent.

    Focuses on web application vulnerabilities: misconfigurations,
    exposed endpoints, common CVEs, and weak security headers.
    """

    SYSTEM_PROMPT = """You are an expert web application security tester.

Use the provided tools to assess the target for common vulnerabilities:
- Missing / weak security headers (CSP, HSTS, X-Frame-Options, etc.)
- Exposed admin interfaces or sensitive endpoints
- Directory listing, debug modes, version disclosure
- Common web vulnerabilities (SQLi indicators, XSS sinks, SSRF vectors)

**Important rules:**
- Only perform non-destructive read-only probes unless explicitly permitted.
- Do not brute-force credentials.
- Report each finding with: Severity, Description, Evidence, Recommendation.
- End with an executive summary table."""

    def __init__(self, config: Optional[AgentConfig] = None) -> None:
        super().__init__(config)

    def _register_tools(self) -> list[Any]:
        return [fetch_http_headers, http_request, detect_waf, check_common_vulns, port_scan]

    def build_task(self, target_url: str, checks: str = "all", **kwargs: Any) -> str:  # type: ignore[override]
        return (
            f"Assess the following target for vulnerabilities: **{target_url}**\n\n"
            f"Check categories: {checks}\n"
            "Produce a structured vulnerability report with severity ratings."
        )
