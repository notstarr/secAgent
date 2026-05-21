"""SigmaAgent single-agent mode example."""

from secagent.agents.sigma_agent import SigmaAgent
from secagent.core.config import AgentConfig


def main() -> None:
    config = AgentConfig()
    agent = SigmaAgent(config=config)

    report = agent.run(
        target="https://scanme.nmap.org",
        scope="full",
    )

    agent.save_report("sigma_report.md", report)


if __name__ == "__main__":
    main()
