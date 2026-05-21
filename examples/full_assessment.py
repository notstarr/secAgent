"""Full orchestrated assessment example."""

from __future__ import annotations

from secagent.agents.orchestrator import OrchestratorAgent
from secagent.core.config import AgentConfig


def main() -> None:
    config = AgentConfig()
    orchestrator = OrchestratorAgent(config=config)

    # Sequential mode: recon → vuln → synthesis
    results = orchestrator.run_sequential(target="scanme.nmap.org")

    with open("full_assessment.md", "w") as f:
        f.write("# Full Security Assessment\n\n")
        f.write("## Reconnaissance\n\n" + results["recon"] + "\n\n")
        f.write("## Vulnerability Assessment\n\n" + results["vuln"] + "\n\n")
        f.write("## Executive Summary\n\n" + results["summary"])

    print("Assessment saved to full_assessment.md")


if __name__ == "__main__":
    main()
