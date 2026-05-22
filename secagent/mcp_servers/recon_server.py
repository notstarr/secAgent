"""
Recon CLI MCP Server

Expose common security CLI scanners through FastMCP tools:
- httpx
- katana
- nuclei
- ffuf
- sqlmap

Run:
    python -m secagent.mcp_servers.recon_server
"""

from __future__ import annotations

import asyncio
import json
import shlex
from shutil import which

from fastmcp import FastMCP

mcp = FastMCP(
    name="secagent-recon",
    instructions=(
        "CLI recon and scanner tools. "
        "Use conservative timeouts and targeted scopes."
    ),
)


def _parse_extra_args(extra_args: str) -> list[str]:
    if not extra_args.strip():
        return []
    try:
        return shlex.split(extra_args)
    except Exception as exc:
        raise ValueError(f"Invalid extra_args: {exc}") from exc


async def _run_cli(
    binary: str,
    args: list[str],
    timeout_sec: int = 120,
    max_output_chars: int = 120_000,
) -> str:
    if which(binary) is None:
        return json.dumps(
            {
                "ok": False,
                "error": f"Binary not found: {binary}",
                "binary": binary,
                "args": args,
            },
            ensure_ascii=False,
        )

    proc = await asyncio.create_subprocess_exec(
        binary,
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out_b, err_b = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
        timed_out = False
    except asyncio.TimeoutError:
        proc.kill()
        out_b, err_b = await proc.communicate()
        timed_out = True

    stdout = out_b.decode("utf-8", errors="replace")
    stderr = err_b.decode("utf-8", errors="replace")
    if len(stdout) > max_output_chars:
        stdout = stdout[:max_output_chars] + "\n...[truncated]..."
    if len(stderr) > max_output_chars:
        stderr = stderr[:max_output_chars] + "\n...[truncated]..."

    return json.dumps(
        {
            "ok": (proc.returncode == 0) and (not timed_out),
            "binary": binary,
            "args": args,
            "exit_code": proc.returncode,
            "timed_out": timed_out,
            "stdout": stdout,
            "stderr": stderr,
        },
        ensure_ascii=False,
    )


@mcp.tool()
async def httpx_probe(
    target: str,
    timeout_sec: int = 120,
    extra_args: str = "",
) -> str:
    """Run httpx against a target URL/domain.

    Args:
        target: Target URL or host (for example: https://example.com).
        timeout_sec: Process timeout in seconds.
        extra_args: Optional extra CLI flags (string).
    """
    args = ["-u", target, "-silent", "-status-code", "-title", "-tech-detect"]
    args.extend(_parse_extra_args(extra_args))
    return await _run_cli("httpx", args, timeout_sec=timeout_sec)


@mcp.tool()
async def katana_crawl(
    target: str,
    depth: int = 3,
    timeout_sec: int = 120,
    extra_args: str = "",
) -> str:
    """Run katana crawl for URL discovery.

    Args:
        target: Target URL.
        depth: Crawl depth.
        timeout_sec: Process timeout in seconds.
        extra_args: Optional extra CLI flags (string).
    """
    args = ["-u", target, "-d", str(max(1, depth)), "-silent"]
    args.extend(_parse_extra_args(extra_args))
    return await _run_cli("katana", args, timeout_sec=timeout_sec)


@mcp.tool()
async def nuclei_scan(
    target: str,
    severity: str = "critical,high,medium",
    timeout_sec: int = 180,
    extra_args: str = "",
) -> str:
    """Run nuclei template scan.

    Args:
        target: Target URL/domain.
        severity: Comma-separated severities.
        timeout_sec: Process timeout in seconds.
        extra_args: Optional extra CLI flags (string).
    """
    args = ["-u", target, "-silent", "-severity", severity]
    args.extend(_parse_extra_args(extra_args))
    return await _run_cli("nuclei", args, timeout_sec=timeout_sec)


@mcp.tool()
async def ffuf_scan(
    target_url: str,
    wordlist: str,
    timeout_sec: int = 180,
    extra_args: str = "",
) -> str:
    """Run ffuf path fuzzing.

    Args:
        target_url: URL containing FUZZ marker (for example: https://x/FUZZ).
        wordlist: Absolute path to a wordlist file.
        timeout_sec: Process timeout in seconds.
        extra_args: Optional extra CLI flags (string).
    """
    args = ["-u", target_url, "-w", wordlist, "-s"]
    args.extend(_parse_extra_args(extra_args))
    return await _run_cli("ffuf", args, timeout_sec=timeout_sec)


@mcp.tool()
async def sqlmap_scan(
    url: str,
    timeout_sec: int = 240,
    extra_args: str = "",
) -> str:
    """Run sqlmap in conservative non-interactive mode.

    Args:
        url: Target URL (prefer one with query parameters).
        timeout_sec: Process timeout in seconds.
        extra_args: Optional extra CLI flags (string).
    """
    args = ["-u", url, "--batch", "--random-agent", "--level", "1", "--risk", "1"]
    args.extend(_parse_extra_args(extra_args))
    return await _run_cli("sqlmap", args, timeout_sec=timeout_sec)


if __name__ == "__main__":
    mcp.run()

