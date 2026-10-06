"""
SSRF Protection Module.
Guards against Server-Side Request Forgery by validating URLs and resolved IP addresses
against loopback, private, link-local, cloud metadata, and reserved networks.
"""

import ipaddress
import socket
from urllib.parse import urlparse
from typing import Tuple, List, Optional
import httpx

# Blocked IP networks (IPv4 and IPv6)
BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # Current network
    ipaddress.ip_network("10.0.0.0/8"),         # Private RFC 1918
    ipaddress.ip_network("100.64.0.0/10"),      # Shared Address Space
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # Link Local / Cloud Metadata (169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),      # Private RFC 1918
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1
    ipaddress.ip_network("192.88.99.0/24"),     # 6to4 Relay Anycast
    ipaddress.ip_network("192.168.0.0/16"),     # Private RFC 1918
    ipaddress.ip_network("198.18.0.0/15"),      # Network Interconnect Benchmarking
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved for Future Use
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast
    # IPv6
    ipaddress.ip_network("::/128"),             # Unspecified
    ipaddress.ip_network("::1/128"),            # Loopback
    ipaddress.ip_network("fc00::/7"),           # Unique Local Address (ULA)
    ipaddress.ip_network("fe80::/10"),          # Link-local unicast
    ipaddress.ip_network("ff00::/8"),           # Multicast
]

# Additional blocked hostnames
BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "metadata.google.internal",
    "metadata.internal",
    "instance-data",
}


def is_ip_blocked(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Checks whether an IP address belongs to any blocked/private network."""
    # Convert IPv4-mapped IPv6 addresses (e.g., ::ffff:127.0.0.1) to IPv4
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
        ip_obj = ip_obj.ipv4_mapped

    for net in BLOCKED_NETWORKS:
        if ip_obj in net:
            return True
    return False


def resolve_hostname_ips(hostname: str) -> List[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Resolves hostname to all associated IP addresses."""
    try:
        addr_info = socket.getaddrinfo(hostname, None)
        ips = []
        for item in addr_info:
            raw_ip = item[4][0]
            ips.append(ipaddress.ip_address(raw_ip))
        return ips
    except (socket.gaierror, ValueError):
        return []


def is_safe_url_to_fetch(url: str) -> Tuple[bool, Optional[str]]:
    """
    Validates a URL against SSRF vulnerabilities.
    Returns (is_safe, error_reason).
    """
    try:
        parsed = urlparse(url)
    except Exception as e:
        return False, f"Malformed URL syntax: {str(e)}"

    # Scheme check: only http and https are permitted
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        return False, f"Unsupported scheme '{scheme}'. Only HTTP and HTTPS are permitted."

    hostname = parsed.hostname
    if not hostname:
        return False, "URL does not contain a valid hostname."

    hostname_lower = hostname.strip().lower().rstrip(".")

    # Blocked hostnames check
    if hostname_lower in BLOCKED_HOSTNAMES or hostname_lower.endswith(".internal") or hostname_lower.endswith(".local"):
        return False, f"Prohibited internal hostname '{hostname}'"

    # Check if hostname is directly an IP address
    try:
        direct_ip = ipaddress.ip_address(hostname_lower)
        if is_ip_blocked(direct_ip):
            return False, f"Destination IP {direct_ip} is in a private/restricted address space."
        return True, None
    except ValueError:
        pass  # Not a literal IP, continue to DNS resolution

    # Resolve hostname to verify destination IPs
    resolved_ips = resolve_hostname_ips(hostname_lower)
    if not resolved_ips:
        return False, f"Unable to resolve DNS for hostname '{hostname}'"

    for ip in resolved_ips:
        if is_ip_blocked(ip):
            return False, f"Resolved IP {ip} for '{hostname}' is in a private/restricted address space."

    return True, None


async def safe_fetch_page_metadata(
    url: str,
    timeout: float = 4.0,
    max_bytes: int = 512 * 1024,
) -> Tuple[Optional[str], Optional[int], Optional[str]]:
    """
    Safely retrieves page HTML metadata with strict SSRF protection,
    redirect validation, execution timeout, and maximum payload size limit.
    Returns (html_content, status_code, error_message).
    """
    is_safe, reason = is_safe_url_to_fetch(url)
    if not is_safe:
        return None, None, f"SSRF Protection: {reason}"

    headers = {
        "User-Agent": "PhishGuard-SafeScanner/1.0 (Cybersecurity Analysis; Contact: sec@phishguard.local)",
        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }

    current_url = url
    max_redirects = 3

    try:
        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=timeout,
            verify=True,
            limits=httpx.Limits(max_keepalive_connections=5, max_connections=10),
        ) as client:
            for _ in range(max_redirects + 1):
                # Check SSRF on current_url before request
                safe, err = is_safe_url_to_fetch(current_url)
                if not safe:
                    return None, None, f"Redirect to unsafe destination blocked: {err}"

                try:
                    response = await client.get(current_url, headers=headers)
                except httpx.TimeoutException:
                    return None, None, "Connection timed out during page fetch."
                except httpx.ConnectError:
                    return None, None, "Unable to establish connection to host."
                except Exception as e:
                    return None, None, f"Fetch error: {str(e)}"

                # If redirect, validate destination
                if response.status_code in (301, 302, 303, 307, 308):
                    location = response.headers.get("Location")
                    if not location:
                        break
                    # Resolve relative redirect
                    from urllib.parse import urljoin
                    current_url = urljoin(current_url, location)
                    continue

                # Check Content-Type
                content_type = response.headers.get("content-type", "").lower()
                if "text/html" not in content_type and "text/plain" not in content_type:
                    return None, response.status_code, "Non-HTML resource received"

                # Read safely up to max_bytes
                content = response.content[:max_bytes]
                try:
                    html_text = content.decode("utf-8", errors="replace")
                except Exception:
                    html_text = str(content)

                return html_text, response.status_code, None

            return None, None, "Excessive redirects detected"

    except Exception as e:
        return None, None, f"Safe fetch failed: {str(e)}"
