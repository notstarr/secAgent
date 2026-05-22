"""Agent runner - core agentic loop, supports Anthropic native + OpenAI-compatible endpoints."""

from __future__ import annotations

import inspect
import json
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


def _get_tool_name(fn: Any) -> str:
    """Get the callable/schema name of a tool (handles BetaFunctionTool)."""
    if hasattr(fn, "name"):
        return fn.name
    return getattr(fn, "__name__", str(fn))


def _build_openai_tool_schema(fn: Any) -> dict:
    """Convert a tool (BetaFunctionTool or plain callable) to OpenAI function schema."""
    # BetaFunctionTool has .name / .description / .input_schema
    if hasattr(fn, "name") and hasattr(fn, "input_schema"):
        return {
            "type": "function",
            "function": {
                "name": fn.name,
                "description": getattr(fn, "description", "") or "",
                "parameters": fn.input_schema or {"type": "object", "properties": {}},
            },
        }
    # Plain callable fallback
    sig = inspect.signature(fn)
    props = {}
    required = []
    for name, param in sig.parameters.items():
        props[name] = {"type": "string", "description": name}
        if param.default is inspect.Parameter.empty:
            required.append(name)
    return {
        "type": "function",
        "function": {
            "name": getattr(fn, "__name__", "unknown"),
            "description": fn.__doc__ or "",
            "parameters": {"type": "object", "properties": props, "required": required},
        },
    }


class AgentRunner:
    """
    Core runner that manages the Claude agentic loop.

    - Anthropic native API: uses client.beta.messages.tool_runner
    - OpenAI-compatible API: uses openai.OpenAI with function-calling loop
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
        self._use_openai_compat = bool(
            self.config.openai_compat_api_key and self.config.openai_compat_base_url
        )
        self._client = self._build_client()

    # ------------------------------------------------------------------
    # Client construction
    # ------------------------------------------------------------------

    def _build_client(self) -> Any:
        cfg = self.config
        if self._use_openai_compat:
            logger.info("Using OpenAI-compatible endpoint: %s", cfg.openai_compat_base_url)
            from openai import OpenAI
            client_kwargs = {
                "api_key": cfg.openai_compat_api_key,
                "base_url": cfg.openai_compat_base_url,
            }
            # Do not inherit HTTP(S)_PROXY from process environment by default.
            # Some private endpoints are only reachable via direct connection.
            try:
                from openai import DefaultHttpxClient
                client_kwargs["http_client"] = DefaultHttpxClient(trust_env=False)
            except Exception:
                pass
            return OpenAI(**client_kwargs)
        return Anthropic(api_key=cfg.api_key)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_tool(self, fn: Callable[..., Any]) -> None:
        self.tools.append(fn)

    def run(self, user_message: str, verbose: bool = True) -> str:
        if self._use_openai_compat:
            return self._run_openai(user_message, verbose)
        return self._run_anthropic(user_message, verbose)

    # ------------------------------------------------------------------
    # Anthropic native loop
    # ------------------------------------------------------------------

    def _run_anthropic(self, user_message: str, verbose: bool) -> str:
        cfg = self.config
        messages: list[dict[str, Any]] = [{"role": "user", "content": user_message}]

        if verbose:
            console.print(Panel(Text(user_message, style="bold cyan"),
                                title="[bold green]User Task", border_style="green"))

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
            if hasattr(message, "stop_reason") and message.stop_reason == "end_turn":
                for block in message.content:
                    if hasattr(block, "text"):
                        final_text = block.text

        return final_text

    # ------------------------------------------------------------------
    # OpenAI-compatible tool loop
    # ------------------------------------------------------------------

    def _run_openai(self, user_message: str, verbose: bool) -> str:
        cfg = self.config
        tool_map: dict[str, Any] = {_get_tool_name(fn): fn for fn in self.tools}
        oa_tools = [_build_openai_tool_schema(fn) for fn in self.tools]

        messages: list[dict[str, Any]] = []
        if self.system_prompt:
            messages.append({"role": "system", "content": self.system_prompt})
        messages.append({"role": "user", "content": user_message})

        if verbose:
            console.print(Panel(Text(user_message, style="bold cyan"),
                                title="[bold green]User Task", border_style="green"))

        final_text = ""
        for iteration in range(cfg.max_iterations):
            kwargs: dict[str, Any] = {
                "model": cfg.get_effective_model(),
                "max_tokens": cfg.max_tokens,
                "messages": messages,
            }
            if oa_tools:
                kwargs["tools"] = oa_tools

            resp = self._client.chat.completions.create(**kwargs)
            msg = resp.choices[0].message
            finish = resp.choices[0].finish_reason

            if verbose:
                if finish == "tool_calls" and msg.tool_calls:
                    for tc in msg.tool_calls:
                        console.print(
                            f"[yellow]⚙ [{iteration+1}] Tool call:[/yellow] "
                            f"[bold]{tc.function.name}[/bold] "
                            f"[dim]{tc.function.arguments[:200]}[/dim]"
                        )

            if finish == "tool_calls" and msg.tool_calls:
                # Append assistant message with tool_calls
                messages.append({
                    "role": "assistant",
                    "content": msg.content or "",
                    "tool_calls": [
                        {"id": tc.id, "type": "function",
                         "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                        for tc in msg.tool_calls
                    ],
                })
                # Execute each tool and append results
                for tc in msg.tool_calls:
                    fn = tool_map.get(tc.function.name)
                    if fn is None:
                        result = f"Error: tool '{tc.function.name}' not found"
                    else:
                        try:
                            args = json.loads(tc.function.arguments)
                            result = fn(**args)
                        except Exception as exc:
                            result = f"Error executing {tc.function.name}: {exc}"
                    if verbose:
                        console.print(f"  [dim]→ {str(result)[:300]}[/dim]")
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": str(result),
                    })
            else:
                # Final response
                final_text = msg.content or ""
                if verbose and final_text:
                    console.print(Panel(final_text, title="[bold blue]Agent Response",
                                        border_style="blue"))
                break

        return final_text

    # ------------------------------------------------------------------
    # Display helpers (Anthropic mode)
    # ------------------------------------------------------------------

    def _display_message(self, message: Any, iteration: int) -> None:
        stop_reason = getattr(message, "stop_reason", "unknown")
        if stop_reason == "tool_use":
            for block in message.content:
                if block.type == "tool_use":
                    console.print(
                        f"[yellow]⚙ [{iteration}] Tool call:[/yellow] "
                        f"[bold]{block.name}[/bold] [dim]{block.input}[/dim]"
                    )
        elif stop_reason == "end_turn":
            for block in message.content:
                if hasattr(block, "text") and block.text:
                    console.print(Panel(block.text, title="[bold blue]Agent Response",
                                        border_style="blue"))
        else:
            logger.debug("Message stop_reason=%s", stop_reason)
