"""Tools package."""
from secagent.tools.network_tools import dns_lookup, port_scan, whois_lookup
from secagent.tools.web_tools import (
    fetch_http_headers,
    http_request,
    detect_waf,
    crawl_links,
    check_common_vulns,
)

__all__ = [
    "dns_lookup",
    "port_scan",
    "whois_lookup",
    "fetch_http_headers",
    "http_request",
    "detect_waf",
    "crawl_links",
    "check_common_vulns",
]
