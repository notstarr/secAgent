"""Execute Python scripts and shell commands — gives the agent full scripting power."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from typing import Annotated

import anthropic


@anthropic.beta_tool  # type: ignore[attr-defined]
def execute_python_script(
    script: Annotated[str, "Python script content to execute (multi-line)"],
    timeout: Annotated[int, "Max execution time in seconds"] = 60,
    packages: Annotated[str, "Comma-separated pip packages to install before running, e.g. 'pyjwt,pycryptodome'"] = "",
) -> str:
    """Execute an arbitrary Python script and return its stdout/stderr output.

    Use this tool when you need to:
    - Write custom exploit scripts or PoC code
    - Process/decode/encrypt data (base64, JWT, hashes, etc.)
    - Parse and analyze complex responses
    - Automate multi-step attack chains
    - Run any computation that built-in tools can't handle

    The script runs in the same Python environment as the agent,
    with access to installed packages (httpx, etc.).

    Returns JSON with exit_code, stdout, and stderr.
    """
    venv_python = sys.executable  # use the same venv python

    # Install packages if requested
    if packages.strip():
        pkg_list = [p.strip() for p in packages.split(",") if p.strip()]
        try:
            install_result = subprocess.run(
                [venv_python, "-m", "pip", "install", "--quiet", "--disable-pip-version-check"] + pkg_list,
                capture_output=True, text=True, timeout=120,
            )
            if install_result.returncode != 0:
                return json.dumps({
                    "exit_code": -1,
                    "error": f"pip install failed: {install_result.stderr[:500]}",
                }, ensure_ascii=False)
        except Exception as exc:
            return json.dumps({
                "exit_code": -1,
                "error": f"pip install error: {exc}",
            }, ensure_ascii=False)

    # Write script to temp file for clean execution
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, prefix="secagent_script_"
        ) as f:
            f.write(script)
            script_path = f.name

        result = subprocess.run(
            [venv_python, script_path],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=tempfile.gettempdir(),
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )

        stdout = result.stdout
        stderr = result.stderr

        # Cap output to avoid context overflow
        max_output = 32 * 1024  # 32 KB
        stdout_truncated = len(stdout) > max_output
        stderr_truncated = len(stderr) > max_output
        stdout = stdout[:max_output]
        stderr = stderr[:max_output]

        return json.dumps({
            "exit_code": result.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "stdout_truncated": stdout_truncated,
            "stderr_truncated": stderr_truncated,
        }, ensure_ascii=False)

    except subprocess.TimeoutExpired:
        return json.dumps({
            "exit_code": -1,
            "error": f"Script execution timed out after {timeout}s",
        }, ensure_ascii=False)
    except Exception as exc:
        return json.dumps({
            "exit_code": -1,
            "error": f"{type(exc).__name__}: {exc}",
        }, ensure_ascii=False)
    finally:
        try:
            os.unlink(script_path)
        except Exception:
            pass


@anthropic.beta_tool  # type: ignore[attr-defined]
def exec_command(
    command: Annotated[str, "Shell command to execute"],
    workdir: Annotated[str, "Working directory (absolute path), defaults to /tmp"] = "/tmp",
    timeout: Annotated[int, "Max execution time in seconds"] = 120,
) -> str:
    """Execute a shell command and return stdout/stderr output.

    Use this tool when you need to:
    - Run system commands (nmap, curl, dig, openssl, etc.)
    - Install tools via apt/brew/pip
    - Manipulate files, search logs, process data with shell pipelines
    - Run any CLI tool available on the system

    Supports pipes, redirects, and all standard shell features.

    Returns JSON with exit_code, stdout, and stderr.
    """
    # Validate workdir
    if workdir and not os.path.isdir(workdir):
        try:
            os.makedirs(workdir, exist_ok=True)
        except Exception:
            workdir = "/tmp"

    try:
        result = subprocess.run(
            command,
            shell=True,
            executable="/bin/bash",
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=workdir or "/tmp",
            env={**os.environ, "LC_ALL": "C.UTF-8"},
        )

        stdout = result.stdout
        stderr = result.stderr

        # Cap output to avoid context overflow
        max_output = 32 * 1024  # 32 KB
        stdout_truncated = len(stdout) > max_output
        stderr_truncated = len(stderr) > max_output
        stdout = stdout[:max_output]
        stderr = stderr[:max_output]

        return json.dumps({
            "exit_code": result.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "stdout_truncated": stdout_truncated,
            "stderr_truncated": stderr_truncated,
        }, ensure_ascii=False)

    except subprocess.TimeoutExpired:
        return json.dumps({
            "exit_code": -1,
            "error": f"Command timed out after {timeout}s",
        }, ensure_ascii=False)
    except Exception as exc:
        return json.dumps({
            "exit_code": -1,
            "error": f"{type(exc).__name__}: {exc}",
        }, ensure_ascii=False)
