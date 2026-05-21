"""Custom tool example: demonstrate adding your own tool to secAgent."""

from __future__ import annotations

import json
from typing import Annotated

import anthropic
from secagent.agents.recon_agent import ReconAgent
from secagent.core.config import AgentConfig


@anthropic.beta_tool  # type: ignore[attr-defined]
def check_ssl_cert(
    hostname: Annotated[str, "Hostname to check TLS/SSL certificate for"],
    port: Annotated[int, "Port (default 443)"] = 443,
) -> str:
    """Check the TLS/SSL certificate of a hostname.

    Returns issuer, subject, validity dates, and SANs.
    """
    import ssl
    import socket

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5)
            s.connect((hostname, port))
            cert = s.getpeercert()
        return json.dumps(cert, default=str, indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)})


def main() -> None:
    """Run ReconAgent with a custom SSL-checking tool added."""
    config = AgentConfig()

    agent = ReconAgent(config=config)
    # Inject an extra tool at runtime
    agent.runner.add_tool(check_ssl_cert)

    result = agent.run(target="example.com", scope="passive")
    print("\n\nFinal Report:\n", result)


if __name__ == "__main__":
    main()
