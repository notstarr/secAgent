"""
Multi-agent orchestrator.

Uses Claude's Managed Agents API to dispatch subtasks to specialised
worker agents (recon, vuln) in parallel and merge their results.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import anthropic
from anthropic import Anthropic

from secagent.core.config import AgentConfig
from secagent.agents.recon_agent import ReconAgent
from secagent.agents.vuln_agent import VulnAgent

logger = logging.getLogger(__name__)


class OrchestratorAgent:
    """
    Top-level orchestrator that coordinates ReconAgent and VulnAgent.

    Phase 1 — Recon: discover services, DNS, headers.
    Phase 2 — Vuln:  assess discovered web endpoints.
    Phase 3 — Report: synthesise findings into a pentest summary.
    """

    ORCHESTRATOR_SYSTEM = """You are a senior penetration test lead coordinating a security assessment.

You have access to two specialist sub-agents:
- **recon_agent**: performs passive and active reconnaissance
- **vuln_agent**: assesses web applications for vulnerabilities

Workflow:
1. Dispatch recon_agent first to map the attack surface.
2. Based on recon findings, dispatch vuln_agent for each discovered web endpoint.
3. Synthesise all results into a final penetration test report.

Always attribute findings to the agent that discovered them."""

    def __init__(self, config: Optional[AgentConfig] = None) -> None:
        self.config = config or AgentConfig()
        self.config.validate()
        self._recon = ReconAgent(self.config)
        self._vuln = VulnAgent(self.config)

    # ------------------------------------------------------------------
    # Sequential orchestration (no Managed Agents API required)
    # ------------------------------------------------------------------

    def run_sequential(self, target: str, verbose: bool = True) -> dict[str, str]:
        """
        Run recon then vuln assessment sequentially.

        Returns a dict with keys 'recon', 'vuln', and 'summary'.
        """
        from rich.console import Console
        from rich.rule import Rule

        console = Console()

        console.print(Rule(f"[bold red]secAgent — Target: {target}[/bold red]"))

        # Phase 1: Recon
        console.print(Rule("[cyan]Phase 1 — Reconnaissance[/cyan]"))
        recon_result = self._recon.run(target=target, verbose=verbose)

        # Phase 2: Vuln (use HTTP/HTTPS if target doesn't start with scheme)
        vuln_target = target if target.startswith("http") else f"https://{target}"
        console.print(Rule("[cyan]Phase 2 — Vulnerability Assessment[/cyan]"))
        vuln_result = self._vuln.run(target_url=vuln_target, verbose=verbose)

        # Phase 3: Synthesise
        console.print(Rule("[cyan]Phase 3 — Synthesis[/cyan]"))
        summary = self._synthesise(target, recon_result, vuln_result, verbose)

        return {"recon": recon_result, "vuln": vuln_result, "summary": summary}

    # ------------------------------------------------------------------
    # Managed Agents orchestration (requires Anthropic Managed Agents)
    # ------------------------------------------------------------------

    def run_managed(self, target: str, verbose: bool = True) -> str:
        """
        Run orchestration using the Claude Managed Agents API.

        This dispatches sub-tasks as proper agent workers. Requires
        the Managed Agents feature to be enabled on your account.
        """
        cfg = self.config
        client = Anthropic(api_key=cfg.api_key)

        # Define sub-agent tools that invoke our local agents
        @anthropic.beta_tool  # type: ignore[attr-defined]
        def run_recon(target_host: str) -> str:
            """Run passive and active reconnaissance on a target host.

            Args:
                target_host: The hostname or IP address to scan.

            Returns:
                Reconnaissance report as markdown.
            """
            return self._recon.run(target=target_host, verbose=verbose)

        @anthropic.beta_tool  # type: ignore[attr-defined]
        def run_vuln_scan(target_url: str) -> str:
            """Run a vulnerability assessment on a web URL.

            Args:
                target_url: Full URL (https://...) of the target.

            Returns:
                Vulnerability report as markdown.
            """
            return self._vuln.run(target_url=target_url, verbose=verbose)

        runner = client.beta.messages.tool_runner(
            model=cfg.get_effective_model(),
            max_tokens=cfg.max_tokens,
            system=self.ORCHESTRATOR_SYSTEM,
            tools=[run_recon, run_vuln_scan],
            messages=[
                {
                    "role": "user",
                    "content": (
                        f"Perform a comprehensive security assessment of **{target}**.\n"
                        "1. Start with recon_agent to map the attack surface.\n"
                        "2. Run vuln_agent on all discovered HTTP/HTTPS endpoints.\n"
                        "3. Produce a final pentest report."
                    ),
                }
            ],
        )

        final_text = ""
        for message in runner:
            if hasattr(message, "stop_reason") and message.stop_reason == "end_turn":
                for block in message.content:
                    if hasattr(block, "text"):
                        final_text = block.text
        return final_text

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _synthesise(
        self, target: str, recon: str, vuln: str, verbose: bool
    ) -> str:
        """Ask Claude to produce a unified pentest summary."""
        from secagent.core.agent_runner import AgentRunner

        runner = AgentRunner(config=self.config, system_prompt=self.ORCHESTRATOR_SYSTEM, tools=[])
        synthesis_task = (
            f"# Security Assessment Synthesis — Target: {target}\n\n"
            f"## Reconnaissance Findings\n{recon}\n\n"
            f"## Vulnerability Assessment Findings\n{vuln}\n\n"
            "Produce a final executive-level penetration test report that:\n"
            "- Summarises the attack surface\n"
            "- Lists all vulnerabilities by severity (Critical/High/Medium/Low/Info)\n"
            "- Provides remediation recommendations\n"
            "- Includes an overall risk rating"
        )
        return runner.run(synthesis_task, verbose=verbose)
