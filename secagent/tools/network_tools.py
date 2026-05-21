"""Network-level security tools (DNS, port scan, WHOIS)."""

from __future__ import annotations

import json
import socket
from typing import Annotated

import anthropic


# ---------------------------------------------------------------------------
# DNS Lookup
# ---------------------------------------------------------------------------

@anthropic.beta_tool  # type: ignore[attr-defined]
def dns_lookup(
    hostname: Annotated[str, "The hostname or domain to query"],
    record_types: Annotated[
        list[str],
        "DNS record types to fetch, e.g. ['A', 'MX', 'TXT', 'NS', 'CNAME']",
    ] = ("A", "MX", "TXT", "NS"),  # type: ignore[assignment]
) -> str:
    """Perform DNS lookups for a given hostname across multiple record types.

    Returns a JSON object mapping each record type to its values.
    """
    try:
        import dns.resolver  # type: ignore[import]
    except ImportError:
        return json.dumps({"error": "dnspython not installed. Run: pip install dnspython"})

    results: dict[str, list[str]] = {}
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0

    for rtype in record_types:
        try:
            answers = resolver.resolve(hostname, rtype)
            results[rtype] = [str(r) for r in answers]
        except Exception as exc:
            results[rtype] = [f"Error: {exc}"]

    return json.dumps(results, indent=2)


# ---------------------------------------------------------------------------
# Port Scan
# ---------------------------------------------------------------------------

@anthropic.beta_tool  # type: ignore[attr-defined]
def port_scan(
    host: Annotated[str, "Hostname or IP address to scan"],
    ports: Annotated[
        list[int],
        "List of TCP ports to check",
    ] = (21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080, 8443),  # type: ignore[assignment]
    timeout: Annotated[float, "Connection timeout in seconds per port"] = 1.0,
) -> str:
    """Perform a TCP connect scan on the specified ports of a host.

    Returns a JSON object with 'open' and 'closed' port lists.
    """
    # Resolve hostname to IP to avoid repeated DNS lookups
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror as exc:
        return json.dumps({"error": f"Cannot resolve host: {exc}"})

    open_ports: list[int] = []
    closed_ports: list[int] = []

    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                open_ports.append(port)
        except (OSError, ConnectionRefusedError):
            closed_ports.append(port)

    return json.dumps({"host": host, "ip": ip, "open": open_ports, "closed": closed_ports})


# ---------------------------------------------------------------------------
# WHOIS Lookup
# ---------------------------------------------------------------------------

@anthropic.beta_tool  # type: ignore[attr-defined]
def whois_lookup(
    domain: Annotated[str, "Domain name to query WHOIS for"],
) -> str:
    """Retrieve WHOIS registration information for a domain.

    Returns a JSON object with registrar, creation date, expiry date,
    name servers, and registrant info (where available).
    """
    try:
        import whois  # type: ignore[import]

        data = whois.whois(domain)
        result = {
            "domain": domain,
            "registrar": getattr(data, "registrar", None),
            "creation_date": str(getattr(data, "creation_date", None)),
            "expiration_date": str(getattr(data, "expiration_date", None)),
            "name_servers": getattr(data, "name_servers", None),
            "status": getattr(data, "status", None),
            "emails": getattr(data, "emails", None),
            "org": getattr(data, "org", None),
        }
        return json.dumps(result, default=str, indent=2)
    except ImportError:
        # Fallback: raw socket WHOIS
        return _raw_whois(domain)
    except Exception as exc:
        return json.dumps({"error": str(exc)})


def _raw_whois(domain: str) -> str:
    """Simple raw WHOIS query via port 43."""
    try:
        tld = domain.rsplit(".", 1)[-1]
        whois_server = f"whois.iana.org"
        with socket.create_connection((whois_server, 43), timeout=10) as s:
            s.sendall(f"{tld}\r\n".encode())
            response = b""
            while chunk := s.recv(4096):
                response += chunk
        # Parse whois server from response
        for line in response.decode(errors="replace").splitlines():
            if line.lower().startswith("whois:"):
                actual_server = line.split(":", 1)[1].strip()
                with socket.create_connection((actual_server, 43), timeout=10) as s2:
                    s2.sendall(f"{domain}\r\n".encode())
                    raw = b""
                    while chunk2 := s2.recv(4096):
                        raw += chunk2
                return json.dumps({"raw": raw.decode(errors="replace")})
        return json.dumps({"raw": response.decode(errors="replace")})
    except Exception as exc:
        return json.dumps({"error": str(exc)})
