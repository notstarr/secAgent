"""Web application security tools."""

from __future__ import annotations

import json
import re
from typing import Annotated
from urllib.parse import urljoin, urlparse

import anthropic
import httpx


# ---------------------------------------------------------------------------
# HTTP Headers
# ---------------------------------------------------------------------------

@anthropic.beta_tool  # type: ignore[attr-defined]
def fetch_http_headers(
    url: Annotated[str, "Full URL to fetch headers from (e.g. https://example.com)"],
    follow_redirects: Annotated[bool, "Follow HTTP redirects"] = True,
) -> str:
    """Fetch HTTP response headers from a URL.

    Returns a JSON object with status code, final URL (after redirects),
    and all response headers. Useful for detecting security header misconfigs.
    """
    try:
        with httpx.Client(timeout=10, follow_redirects=follow_redirects, verify=False) as client:
            response = client.head(url)
            # Fall back to GET if HEAD returns 405
            if response.status_code == 405:
                response = client.get(url)
        return json.dumps(
            {
                "url": str(response.url),
                "status_code": response.status_code,
                "headers": dict(response.headers),
            },
            indent=2,
        )
    except Exception as exc:
        return json.dumps({"error": str(exc)})


# ---------------------------------------------------------------------------
# HTTP Request (generic)
# ---------------------------------------------------------------------------

@anthropic.beta_tool  # type: ignore[attr-defined]
def http_request(
    url: Annotated[str, "URL to request"],
    method: Annotated[str, "HTTP method: GET, POST, PUT, DELETE, OPTIONS, HEAD"] = "GET",
    headers: Annotated[dict[str, str], "Extra HTTP headers to include"] = {},  # noqa: B006
    body: Annotated[str, "Request body for POST/PUT"] = "",
    follow_redirects: Annotated[bool, "Follow HTTP redirects"] = True,
) -> str:
    """Perform an HTTP request and return status, headers, and truncated body.

    Body is capped at 8 KB to avoid context overflow.
    **Do not use for authentication brute-forcing or DoS.**
    """
    MAX_BODY = 8 * 1024  # 8 KB
    try:
        with httpx.Client(timeout=15, follow_redirects=follow_redirects, verify=False) as client:
            resp = client.request(
                method.upper(),
                url,
                headers=headers,
                content=body.encode() if body else None,
            )
        body_text = resp.text[:MAX_BODY]
        return json.dumps(
            {
                "url": str(resp.url),
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "body_preview": body_text,
                "body_truncated": len(resp.text) > MAX_BODY,
            },
            indent=2,
        )
    except Exception as exc:
        return json.dumps({"error": str(exc)})


# ---------------------------------------------------------------------------
# WAF Detection
# ---------------------------------------------------------------------------

_WAF_SIGNATURES: dict[str, list[str]] = {
    "Cloudflare": ["cf-ray", "cloudflare", "__cfduid"],
    "AWS WAF": ["x-amzn-requestid", "x-amz-cf-id"],
    "Akamai": ["akamai", "x-akamai-transformed"],
    "Imperva / Incapsula": ["x-cdn", "incap_ses", "visid_incap"],
    "F5 BIG-IP ASM": ["ts", "bigipserver"],
    "ModSecurity": ["mod_security", "modsec"],
    "Sucuri": ["x-sucuri-id", "x-sucuri-cache"],
}


@anthropic.beta_tool  # type: ignore[attr-defined]
def detect_waf(
    url: Annotated[str, "URL to check for WAF presence"],
) -> str:
    """Attempt to detect a Web Application Firewall (WAF) in front of a URL.

    Checks response headers and cookies against known WAF signatures.
    Returns a JSON object with detected WAF name (or 'None detected').
    """
    try:
        with httpx.Client(timeout=10, follow_redirects=True, verify=False) as client:
            resp = client.get(url)

        headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
        cookie_str = " ".join(
            cookie.lower() for cookie in resp.headers.get_list("set-cookie")
        )
        combined = " ".join(headers_lower.keys()) + " " + " ".join(headers_lower.values()) + " " + cookie_str

        detected = []
        for waf_name, sigs in _WAF_SIGNATURES.items():
            if any(sig in combined for sig in sigs):
                detected.append(waf_name)

        return json.dumps(
            {
                "url": url,
                "waf_detected": detected if detected else ["None detected"],
                "status_code": resp.status_code,
            },
            indent=2,
        )
    except Exception as exc:
        return json.dumps({"error": str(exc)})


# ---------------------------------------------------------------------------
# Link Crawler
# ---------------------------------------------------------------------------

@anthropic.beta_tool  # type: ignore[attr-defined]
def crawl_links(
    url: Annotated[str, "Starting URL to crawl"],
    max_links: Annotated[int, "Maximum number of unique links to return"] = 50,
) -> str:
    """Crawl a web page and extract all unique internal and external links.

    Returns a JSON object with 'internal' and 'external' link lists.
    Capped at `max_links` total links.
    """
    try:
        with httpx.Client(timeout=15, follow_redirects=True, verify=False) as client:
            resp = client.get(url)

        base = urlparse(url)
        base_origin = f"{base.scheme}://{base.netloc}"

        href_pattern = re.compile(r'href=["\']([^"\'#?]+)["\']', re.IGNORECASE)
        raw_links = href_pattern.findall(resp.text)

        internal: set[str] = set()
        external: set[str] = set()

        for raw in raw_links:
            if len(internal) + len(external) >= max_links:
                break
            absolute = raw if raw.startswith("http") else urljoin(base_origin, raw)
            parsed = urlparse(absolute)
            if parsed.netloc == base.netloc:
                internal.add(absolute)
            elif parsed.netloc:
                external.add(absolute)

        return json.dumps(
            {"internal": sorted(internal), "external": sorted(external)},
            indent=2,
        )
    except Exception as exc:
        return json.dumps({"error": str(exc)})


# ---------------------------------------------------------------------------
# Common Vulnerability Checks
# ---------------------------------------------------------------------------

_SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/robots.txt", "/sitemap.xml",
    "/admin", "/admin/login", "/wp-admin", "/phpmyadmin",
    "/api/swagger.json", "/api/openapi.json", "/swagger-ui.html",
    "/.well-known/security.txt", "/server-status", "/server-info",
    "/actuator", "/actuator/health", "/actuator/env",
    "/debug", "/_debug_toolbar",
]

_SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]


@anthropic.beta_tool  # type: ignore[attr-defined]
def check_common_vulns(
    base_url: Annotated[str, "Base URL of the web application (e.g. https://example.com)"],
) -> str:
    """Check for common web vulnerabilities and misconfigurations.

    Probes well-known sensitive paths and evaluates security headers.
    Returns a JSON report of findings.
    """
    findings: list[dict[str, str]] = []
    base_url = base_url.rstrip("/")

    try:
        with httpx.Client(timeout=10, follow_redirects=True, verify=False) as client:
            # 1. Probe sensitive paths
            for path in _SENSITIVE_PATHS:
                try:
                    resp = client.get(base_url + path, timeout=5)
                    if resp.status_code in (200, 301, 302, 403):
                        findings.append(
                            {
                                "type": "exposed_path",
                                "path": path,
                                "status_code": str(resp.status_code),
                                "severity": "Medium" if resp.status_code == 200 else "Low",
                                "note": f"Path accessible (HTTP {resp.status_code})",
                            }
                        )
                except Exception:
                    pass

            # 2. Security header check
            resp = client.get(base_url)
            headers_lower = {k.lower() for k in resp.headers.keys()}
            for header in _SECURITY_HEADERS:
                if header not in headers_lower:
                    findings.append(
                        {
                            "type": "missing_security_header",
                            "header": header,
                            "severity": "Medium" if "content-security" in header else "Low",
                            "note": f"Header '{header}' is absent",
                        }
                    )

            # 3. Server version disclosure
            server = resp.headers.get("server", "")
            if re.search(r"\d+\.\d+", server):
                findings.append(
                    {
                        "type": "version_disclosure",
                        "header": "server",
                        "value": server,
                        "severity": "Low",
                        "note": "Server header reveals version information",
                    }
                )

    except Exception as exc:
        return json.dumps({"error": str(exc)})

    return json.dumps({"base_url": base_url, "findings": findings}, indent=2)
