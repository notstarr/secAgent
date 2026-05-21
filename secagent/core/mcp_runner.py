"""
MCP Client Runner

Connects to an MCP server via stdio, converts its tools to Anthropic-compatible
tool definitions, and runs a full agentic loop with Claude.

Usage:
    runner = MCPAgentRunner(
        server_command=["python", "-m", "secagent.mcp_servers.browser_server"],
        config=AgentConfig(),
        system_prompt="You are a browser automation assistant.",
    )
    result = asyncio.run(runner.run_async("Navigate to https://example.com and take a screenshot"))
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Optional

from anthropic import Anthropic
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from rich.console import Console
from rich.panel import Panel

from secagent.core.config import AgentConfig

logger = logging.getLogger(__name__)
console = Console()


class MCPAgentRunner:
    """
    Agentic loop that connects to an MCP server and exposes its tools to Claude.

    The runner:
    1. Spawns the MCP server as a subprocess (stdio transport)
    2. Calls list_tools() to discover available tools
    3. Converts them to Anthropic tool definitions
    4. Runs the Claude agentic loop, forwarding tool calls back to the MCP server
    """

    def __init__(
        self,
        server_command: list[str],
        config: Optional[AgentConfig] = None,
        system_prompt: str = "",
        server_env: Optional[dict[str, str]] = None,
    ) -> None:
        self.server_command = server_command
        self.config = config or AgentConfig()
        self.config.validate()
        self.system_prompt = system_prompt
        self.server_env = server_env

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, user_message: str, verbose: bool = True) -> str:
        """Synchronous wrapper around run_async."""
        return asyncio.run(self.run_async(user_message, verbose))

    async def run_async(self, user_message: str, verbose: bool = True) -> str:
        """
        Connect to the MCP server and run the full agentic loop.

        Returns the final text response from Claude.
        """
        server_params = StdioServerParameters(
            command=self.server_command[0],
            args=self.server_command[1:],
            env=self.server_env,
        )

        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()

                # Discover tools from MCP server
                tools_result = await session.list_tools()
                anthropic_tools = [
                    self._convert_mcp_tool(t) for t in tools_result.tools
                ]

                if verbose:
                    console.print(
                        f"[dim]Connected to MCP server — "
                        f"{len(anthropic_tools)} tools available: "
                        f"{[t['name'] for t in anthropic_tools]}[/dim]"
                    )
                    console.print(
                        Panel(user_message, title="[bold green]User Task", border_style="green")
                    )

                return await self._agent_loop(
                    session, anthropic_tools, user_message, verbose
                )

    # ------------------------------------------------------------------
    # Core agentic loop
    # ------------------------------------------------------------------

    async def _agent_loop(
        self,
        session: ClientSession,
        tools: list[dict[str, Any]],
        user_message: str,
        verbose: bool,
    ) -> str:
        cfg = self.config
        client = self._build_client()

        messages: list[dict[str, Any]] = [{"role": "user", "content": user_message}]
        final_text = ""
        iteration = 0

        while iteration < cfg.max_iterations:
            iteration += 1

            response = client.messages.create(
                model=cfg.get_effective_model(),
                max_tokens=cfg.max_tokens,
                system=self.system_prompt,
                tools=tools,  # type: ignore[arg-type]
                messages=messages,
            )

            # Accumulate assistant message
            messages.append({"role": "assistant", "content": response.content})

            if response.stop_reason == "end_turn":
                for block in response.content:
                    if hasattr(block, "text"):
                        final_text = block.text
                        if verbose:
                            console.print(
                                Panel(
                                    block.text,
                                    title="[bold blue]Agent Response",
                                    border_style="blue",
                                )
                            )
                break

            if response.stop_reason != "tool_use":
                logger.warning("Unexpected stop_reason: %s", response.stop_reason)
                break

            # Process all tool calls in this turn
            tool_results: list[dict[str, Any]] = []
            for block in response.content:
                if block.type != "tool_use":
                    continue

                tool_name = block.name
                tool_input = block.input

                if verbose:
                    console.print(
                        f"[yellow]⚙ [{iteration}] MCP tool:[/yellow] "
                        f"[bold]{tool_name}[/bold] [dim]{json.dumps(tool_input)[:200]}[/dim]"
                    )

                # Forward call to MCP server
                try:
                    mcp_result = await session.call_tool(tool_name, tool_input)
                    content = self._extract_mcp_content(mcp_result)
                except Exception as exc:
                    content = json.dumps({"error": str(exc)})

                if verbose:
                    console.print(f"  [dim]↳ {content[:300]}[/dim]")

                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": content,
                    }
                )

            messages.append({"role": "user", "content": tool_results})

        return final_text

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_client(self) -> Anthropic:
        cfg = self.config
        if cfg.openai_compat_api_key and cfg.openai_compat_base_url:
            return Anthropic(
                api_key=cfg.openai_compat_api_key,
                base_url=cfg.openai_compat_base_url,
            )
        return Anthropic(api_key=cfg.api_key)

    @staticmethod
    def _convert_mcp_tool(tool: Any) -> dict[str, Any]:
        """Convert an MCP tool definition to Anthropic tool format."""
        return {
            "name": tool.name,
            "description": tool.description or "",
            "input_schema": tool.inputSchema,
        }

    @staticmethod
    def _extract_mcp_content(result: Any) -> str:
        """Extract string content from an MCP tool result."""
        if not result.content:
            return ""
        parts: list[str] = []
        for item in result.content:
            if hasattr(item, "text"):
                parts.append(item.text)
            elif hasattr(item, "data"):
                # Binary (e.g. screenshot) — return metadata only
                parts.append(f"[binary data, {len(item.data)} bytes]")
        return "\n".join(parts)
