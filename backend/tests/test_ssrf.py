"""
Security Tests for SSRF Protection.
Verifies that loopback, RFC 1918 private IPs, link-local metadata addresses,
and prohibited hostnames are rejected.
"""

import pytest
from app.security.ssrf import is_safe_url_to_fetch


def test_blocked_loopback_addresses():
    loopback_urls = [
        "http://127.0.0.1/admin",
        "http://127.0.0.2:8080/",
        "http://localhost/",
        "http://localhost:8000/api",
        "http://[::1]/secret",
    ]
    for url in loopback_urls:
        safe, err = is_safe_url_to_fetch(url)
        assert not safe, f"Loopback URL should be blocked: {url}"
        assert err is not None


def test_blocked_private_rfc1918_addresses():
    private_urls = [
        "http://10.0.0.1/internal",
        "http://10.254.1.1/",
        "http://172.16.0.1/dashboard",
        "http://172.31.255.255/",
        "http://192.168.1.1/router",
        "http://192.168.0.100:3000/",
    ]
    for url in private_urls:
        safe, err = is_safe_url_to_fetch(url)
        assert not safe, f"Private RFC 1918 URL should be blocked: {url}"


def test_blocked_cloud_metadata():
    metadata_urls = [
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://instance-data/latest/meta-data/",
    ]
    for url in metadata_urls:
        safe, err = is_safe_url_to_fetch(url)
        assert not safe, f"Cloud metadata URL should be blocked: {url}"


def test_allowed_public_urls():
    # Only test syntax / public IP check (no DNS network call needed for IP test)
    safe, err = is_safe_url_to_fetch("https://8.8.8.8/")
    assert safe, f"Public IP should be allowed, got error: {err}"
