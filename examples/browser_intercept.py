"""Intercept network traffic example — capture API calls from a web app."""

from secagent.agents.browser_agent import BrowserAgent
from secagent.core.config import AgentConfig


def main() -> None:
    config = AgentConfig()
    agent = BrowserAgent(config=config, headless=False)

    # Capture all network requests during a session
    report = agent.intercept_session("https://httpbin.org")

    print(report)


if __name__ == "__main__":
    main()
