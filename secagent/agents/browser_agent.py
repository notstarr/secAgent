"""Browser Agent — Chrome automation via MCP + Playwright."""

from __future__ import annotations

import sys
from typing import Any, Optional

from secagent.core.config import AgentConfig
from secagent.core.mcp_runner import MCPAgentRunner


class BrowserAgent:
    """
    A security-focused Chrome browser automation agent.

    Uses the secagent-browser MCP server (Playwright-based) to give Claude
    full control over a Chrome browser — navigate, click, type, screenshot,
    intercept requests, execute JS, and more.

    Example
    -------
    agent = BrowserAgent()
    result = agent.run("Go to https://example.com, take a screenshot, and report all visible links.")
    """

    SYSTEM_PROMPT = """You are an expert web security tester and browser automation specialist.

You control a real Chrome browser via the provided tools. Available capabilities:
- browser_launch      : Start Chrome (call this first, headless=False shows the window)
- browser_navigate    : Go to a URL
- browser_screenshot  : Capture the current viewport or full page
- browser_get_text    : Extract visible text from the page or a CSS selector
- browser_get_html    : Get raw HTML source
- browser_click       : Click any element by CSS selector
- browser_type        : Type text into input fields
- browser_select      : Select a dropdown option
- browser_scroll      : Scroll the page
- browser_execute_js  : Run arbitrary JavaScript
- browser_find_elements: Query all elements matching a CSS selector
- browser_wait_for    : Wait for an element or URL change
- browser_get_cookies : List all cookies
- browser_set_headers : Inject custom request headers
- browser_intercept_requests / browser_get_requests : Log network traffic
- browser_new_tab     : Open a new browser tab
- browser_close       : Shut down the browser when finished

Workflow guidance:
1. Always call browser_launch first.
2. Use browser_screenshot frequently to understand the current page state.
3. Prefer browser_find_elements to understand page structure before clicking.
4. When security testing: document every interesting finding with evidence.
5. Call browser_close when your task is complete.

IMPORTANT: Only operate on authorised targets. Do not attempt to bypass authentication
on systems you do not own."""

    def __init__(self, config: Optional[AgentConfig] = None, headless: bool = False) -> None:
        self.config = config or AgentConfig()
        self.headless = headless
        self._runner = MCPAgentRunner(
            server_command=[sys.executable, "-m", "secagent.mcp_servers.browser_server"],
            config=self.config,
            system_prompt=self.SYSTEM_PROMPT,
        )

    def run(self, task: str, verbose: bool = True) -> str:
        """
        Execute a browser automation task described in natural language.

        Args:
            task: Plain-language description of what to do in the browser.
            verbose: Print tool calls and responses to console. Default True.

        Returns:
            Final text report / summary from Claude.
        """
        # Prepend headless preference to task if needed
        hint = f"[headless={'true' if self.headless else 'false'}] " if not self.headless else ""
        return self._runner.run(f"{hint}{task}", verbose=verbose)

    # ------------------------------------------------------------------
    # Convenience task shortcuts
    # ------------------------------------------------------------------

    def scan_page(self, url: str, verbose: bool = True) -> str:
        """Open a URL and produce a security-focused page report."""
        return self.run(
            f"Security scan of {url}:\n"
            "1. Navigate to the URL.\n"
            "2. Take a screenshot.\n"
            "3. Extract all visible links and forms.\n"
            "4. Check response headers via browser_execute_js (window.performance).\n"
            "5. List cookies (names and flags).\n"
            "6. Enable request interception, reload, retrieve captured requests.\n"
            "7. Report findings with a security risk assessment.\n"
            "8. Close the browser.",
            verbose=verbose,
        )

    def fill_and_submit(
        self,
        url: str,
        form_data: dict[str, str],
        submit_selector: str = "button[type=submit]",
        verbose: bool = True,
    ) -> str:
        """Navigate to a URL, fill a form, and submit it."""
        fields_desc = "\n".join(
            f"- Fill selector '{sel}' with value '{val}'"
            for sel, val in form_data.items()
        )
        return self.run(
            f"Fill and submit form at {url}:\n"
            f"1. Navigate to {url}.\n"
            f"2. Screenshot to verify the form is visible.\n"
            f"{fields_desc}\n"
            f"3. Click '{submit_selector}' to submit.\n"
            "4. Screenshot the result page and report what happened.\n"
            "5. Close the browser.",
            verbose=verbose,
        )

    def intercept_session(self, url: str, verbose: bool = True) -> str:
        """Browse a site and capture all network requests (useful for API discovery)."""
        return self.run(
            f"Capture all network traffic from {url}:\n"
            "1. Launch browser and enable request interception.\n"
            f"2. Navigate to {url}.\n"
            "3. Scroll the page to trigger lazy-loaded requests.\n"
            "4. Retrieve all captured requests.\n"
            "5. Summarise: API endpoints, auth headers, interesting parameters.\n"
            "6. Close the browser.",
            verbose=verbose,
        )
