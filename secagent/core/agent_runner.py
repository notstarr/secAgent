"""Agent runner - core agentic loop using Claude Agent SDK tool_runner."""

from __future__ import annotations

import logging
from typing import Any, Callable, Optional

import anthropic
from anthropic import Anthropic
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from secagent.core.config import AgentConfig

logger = logging.getLogger(__name__)
console = Console()


class AgentRunner:
    """
    Core runner that manages the Claude agentic loop.

    Uses `client.beta.messages.tool_runner` to automatically handle
    multi-turn tool use until Claude produces a final text response.
    """

    def __init__(
        self,
        config: Optional[AgentConfig] = None,
        system_prompt: str = "",
        tools: Optional[list[Callable[..., Any]]] = None,
    ) -> None:
        self.config = config or AgentConfig()
        self.config.validate()
        self.system_prompt = system_prompt
        self.tools: list[Callable[..., Any]] = tools or []
        self._client = self._build_client()

    # ------------------------------------------------------------------
    # Client construction
    # ------------------------------------------------------------------

    def _build_client(self) -> Anthropic:
        """Build the Anthropic client, supporting OpenAI-compatible endpoints."""
        cfg = self.config
        if cfg.openai_compat_api_key and cfg.openai_compat_base_url:
            logger.info("Using OpenAI-compatible endpoint: %s", cfg.openai_compat_base_url)
            return Anthropic(
                api_key=cfg.openai_compat_api_key,
                base_url=cfg.openai_compat_base_url,
            )
        return Anthropic(api_key=cfg.api_key)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_tool(self, fn: Callable[..., Any]) -> None:
        """Register a tool function (decorated with @beta_tool or plain callable)."""
        self.tools.append(fn)

    def run(self, user_message: str, verbose: bool = True) -> str:
        """
        Run the agent loop synchronously.

        Iterates through all tool calls until Claude emits a final
        text-only response, then returns that text.
        """
        cfg = self.config
        messages: list[dict[str, Any]] = [{"role": "user", "content": user_message}]

        if verbose:
            console.print(
                Panel(
                    Text(user_message, style="bold cyan"),
                    title="[bold green]User Task",
                    border_style="green",
                )
            )

        # Wrap plain callables as beta_tool objects if needed
        wrapped_tools = [
            anthropic.beta_tool(t) if not isinstance(t, anthropic.BetaTool) else t  # type: ignore[attr-defined]
            for t in self.tools
        ]

        final_text = ""
        iteration = 0

        runner = self._client.beta.messages.tool_runner(
            model=cfg.get_effective_model(),
            max_tokens=cfg.max_tokens,
            system=self.system_prompt,
            tools=wrapped_tools,  # type: ignore[arg-type]
            messages=messages,
        )

        for message in runner:
            iteration += 1
            if iteration > cfg.max_iterations:
                logger.warning("Max iterations (%d) reached.", cfg.max_iterations)
                break

            if verbose:
                self._display_message(message, iteration)

            # Collect final text from end_turn stop reason
            if hasattr(message, "stop_reason") and message.stop_reason == "end_turn":
                for block in message.content:
                    if hasattr(block, "text"):
                        final_text = block.text

        return final_text

    # ------------------------------------------------------------------
    # Display helpers
    # ------------------------------------------------------------------

    def _display_message(self, message: Any, iteration: int) -> None:
        """Pretty-print a message from the runner."""
        stop_reason = getattr(message, "stop_reason", "unknown")

        if stop_reason == "tool_use":
            for block in message.content:
                if block.type == "tool_use":
                    console.print(
                        f"[yellow]⚙ [{iteration}] Tool call:[/yellow] "
                        f"[bold]{block.name}[/bold] "
                        f"[dim]{block.input}[/dim]"
                    )
        elif stop_reason == "end_turn":
            for block in message.content:
                if hasattr(block, "text") and block.text:
                    console.print(
                        Panel(
                            block.text,
                            title="[bold blue]Agent Response",
                            border_style="blue",
                        )
                    )
        else:
            logger.debug("Message stop_reason=%s", stop_reason)
