"""
Unit tests for URL Sanitizer and Normalizer.
"""

import pytest
from app.security.url_sanitizer import sanitize_and_normalize_url


def test_valid_urls():
    url, err = sanitize_and_normalize_url("https://example.com/path?arg=1")
    assert err is None
    assert url == "https://example.com/path?arg=1"

    # Auto-prepend https
    url2, err2 = sanitize_and_normalize_url("github.com/google")
    assert err2 is None
    assert url2.startswith("https://github.com")


def test_dangerous_schemes():
    bad_schemes = [
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "file:///etc/passwd",
        "vbscript:msgbox",
    ]
    for bad in bad_schemes:
        url, err = sanitize_and_normalize_url(bad)
        assert url is None
        assert "Prohibited" in err or "Unsupported" in err


def test_empty_and_null_bytes():
    url, err = sanitize_and_normalize_url("")
    assert url is None

    url2, err2 = sanitize_and_normalize_url("   \x00\x1f  ")
    assert url2 is None


def test_length_limits():
    oversized = "https://example.com/" + ("a" * 2500)
    url, err = sanitize_and_normalize_url(oversized)
    assert url is None
    assert "exceeds maximum allowed length" in err
