"""Browser automation example — scan a web page with Chrome."""

from secagent.agents.browser_agent import BrowserAgent
from secagent.core.config import AgentConfig


def main() -> None:
    config = AgentConfig()
    agent = BrowserAgent(config=config, headless=False)  # headless=True for no window

    # Quick security scan
    report = agent.scan_page("https://example.com")

    with open("browser_scan_report.md", "w") as f:
        f.write(report)
    print("Report saved to browser_scan_report.md")


if __name__ == "__main__":
    main()
