"""Minimal quick-start example: run ReconAgent on a single target."""

from __future__ import annotations

from secagent.agents.recon_agent import ReconAgent
from secagent.core.config import AgentConfig


def main() -> None:
    config = AgentConfig()  # reads ANTHROPIC_API_KEY from .env / environment

    agent = ReconAgent(config=config)
    report = agent.run(target="scanme.nmap.org", scope="passive+active")

    # Save report
    with open("recon_report.md", "w") as f:
        f.write(report)
    print("Report saved to recon_report.md")


if __name__ == "__main__":
    main()
