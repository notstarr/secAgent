"""Reconnaissance agent - passive & active information gathering."""

from __future__ import annotations

from typing import Any, Optional

from secagent.agents.base_agent import BaseSecAgent
from secagent.core.config import AgentConfig
from secagent.tools.network_tools import dns_lookup, port_scan, whois_lookup
from secagent.tools.web_tools import fetch_http_headers, crawl_links, detect_waf


class ReconAgent(BaseSecAgent):
    """
    Perform reconnaissance on a target host or domain.

    Equipped with DNS, WHOIS, port scanning, HTTP header analysis,
    and basic link crawling tools.
    """

    SYSTEM_PROMPT = """You are an expert penetration tester specialising in reconnaissance.

Your job is to systematically gather information about a target using the available tools.
Follow this methodology:
1. WHOIS / domain registration info
2. DNS enumeration (A, MX, NS, TXT, CNAME records)
3. Port scanning (common ports: 21,22,23,25,53,80,110,143,443,445,3306,3389,8080,8443)
4. HTTP header analysis and WAF detection
5. Crawl visible links from the web root

Summarise findings in a structured Markdown report at the end.
**Stay within authorised scope. Never attempt exploitation.**"""

    def __init__(self, config: Optional[AgentConfig] = None) -> None:
        super().__init__(config)

    def _register_tools(self) -> list[Any]:
        return [dns_lookup, port_scan, whois_lookup, fetch_http_headers, crawl_links, detect_waf]

    def build_task(self, target: str, scope: str = "passive+active", **kwargs: Any) -> str:  # type: ignore[override]
        return (
            f"Perform a {'passive' if scope == 'passive' else 'full'} reconnaissance on the "
            f"target: **{target}**\n\n"
            f"Scope: {scope}\n"
            "Produce a structured report with all findings."
        )
