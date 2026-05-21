"""CLI entry point for secAgent."""

from __future__ import annotations

import click
from rich.console import Console

from secagent.core.config import AgentConfig

console = Console()


@click.group()
@click.version_option(package_name="secagent")
def cli() -> None:
    """secAgent — Security Testing Agent powered by Claude Agent SDK."""


@cli.command()
@click.argument("target")
@click.option("--scope", default="passive+active", help="Recon scope: passive | passive+active")
@click.option("--model", default=None, help="Override the Claude model to use")
@click.option("-v", "--verbose", is_flag=True, default=True)
def recon(target: str, scope: str, model: str | None, verbose: bool) -> None:
    """Perform reconnaissance on TARGET (hostname, IP, or URL)."""
    from secagent.agents.recon_agent import ReconAgent

    cfg = AgentConfig()
    if model:
        cfg.model = model
    agent = ReconAgent(config=cfg)
    result = agent.run(target=target, scope=scope, verbose=verbose)
    if not verbose:
        console.print(result)


@cli.command()
@click.argument("target_url")
@click.option("--checks", default="all", help="Comma-separated check categories or 'all'")
@click.option("--model", default=None, help="Override the Claude model to use")
@click.option("-v", "--verbose", is_flag=True, default=True)
def vuln(target_url: str, checks: str, model: str | None, verbose: bool) -> None:
    """Run a vulnerability assessment against TARGET_URL."""
    from secagent.agents.vuln_agent import VulnAgent

    cfg = AgentConfig()
    if model:
        cfg.model = model
    agent = VulnAgent(config=cfg)
    result = agent.run(target_url=target_url, checks=checks, verbose=verbose)
    if not verbose:
        console.print(result)


@cli.command()
@click.argument("target")
@click.option(
    "--mode",
    default="sequential",
    type=click.Choice(["sequential", "managed"]),
    help="Orchestration mode",
)
@click.option("--model", default=None, help="Override the Claude model to use")
@click.option("-v", "--verbose", is_flag=True, default=True)
def assess(target: str, mode: str, model: str | None, verbose: bool) -> None:
    """Full security assessment of TARGET (recon + vuln + report)."""
    from secagent.agents.orchestrator import OrchestratorAgent

    cfg = AgentConfig()
    if model:
        cfg.model = model
    orchestrator = OrchestratorAgent(config=cfg)

    if mode == "managed":
        result = orchestrator.run_managed(target=target, verbose=verbose)
        console.print(result)
    else:
        orchestrator.run_sequential(target=target, verbose=verbose)


@cli.command()
@click.argument("target")
@click.option("--scope", default="full", help="Test scope description")
@click.option("--extra", default="", help="Extra instructions appended to the task")
@click.option("--output", "-o", default="", help="Save report to this file path")
@click.option("--model", default=None, help="Override the Claude model to use")
@click.option("-v", "--verbose", is_flag=True, default=True)
def sigma(
    target: str,
    scope: str,
    extra: str,
    output: str,
    model: str | None,
    verbose: bool,
) -> None:
    """Run sigmaAI single-agent pentest against TARGET (单智能体渗透测试)."""
    from secagent.agents.sigma_agent import SigmaAgent

    cfg = AgentConfig()
    if model:
        cfg.model = model
    agent = SigmaAgent(config=cfg)
    report = agent.run(target=target, scope=scope, extra_instructions=extra, verbose=verbose)
    if output:
        agent.save_report(output, report)
    elif not verbose:
        console.print(report)


@cli.command()
@click.argument("task")
@click.option("--headless", is_flag=True, default=False, help="Run Chrome in headless mode")
@click.option("--model", default=None, help="Override the Claude model to use")
@click.option("-v", "--verbose", is_flag=True, default=True)
def browser(task: str, headless: bool, model: str | None, verbose: bool) -> None:
    """Control Chrome with natural language TASK description."""
    from secagent.agents.browser_agent import BrowserAgent

    cfg = AgentConfig()
    if model:
        cfg.model = model
    agent = BrowserAgent(config=cfg, headless=headless)
    result = agent.run(task, verbose=verbose)
    if not verbose:
        console.print(result)


@cli.command("browser-server")
def browser_server() -> None:
    """Start the Browser MCP server (stdio transport)."""
    from secagent.mcp_servers.browser_server import mcp
    mcp.run()


if __name__ == "__main__":
    cli()
