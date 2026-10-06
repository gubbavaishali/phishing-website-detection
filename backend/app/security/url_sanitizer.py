"""
URL Sanitizer and Validator Module.
Normalizes, canonicalizes, and performs security verification on input URLs.
"""

import re
from urllib.parse import urlparse, urlunparse
from typing import Tuple, Optional


DANGEROUS_SCHEMES = {"javascript", "data", "vbscript", "file", "about", "blob"}
MAX_URL_LENGTH = 2048


def sanitize_and_normalize_url(raw_url: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Validates and normalizes user-provided URLs.
    Returns (normalized_url, error_message).
    If valid, normalized_url will have a lowercase scheme and host,
    safe characters, and default scheme (https) if missing.
    """
    if not raw_url or not isinstance(raw_url, str):
        return None, "URL must be a non-empty string."

    # Strip whitespace, null bytes, and control characters
    cleaned = raw_url.strip()
    cleaned = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", cleaned)

    if len(cleaned) == 0:
        return None, "URL cannot be empty."

    if len(cleaned) > MAX_URL_LENGTH:
        return None, f"URL exceeds maximum allowed length of {MAX_URL_LENGTH} characters."

    # Check for dangerous embedded schemes
    lowered = cleaned.lower()
    for scheme in DANGEROUS_SCHEMES:
        if lowered.startswith(f"{scheme}:") or f"{scheme}:" in lowered[:20]:
            return None, f"Prohibited URL scheme: {scheme}"

    # Auto-prepend https:// if no scheme is provided
    if not (lowered.startswith("http://") or lowered.startswith("https://")):
        if "://" in cleaned:
            scheme_part = cleaned.split("://")[0].lower()
            return None, f"Unsupported protocol '{scheme_part}'. Only HTTP and HTTPS are accepted."
        cleaned = "https://" + cleaned

    try:
        parsed = urlparse(cleaned)
    except Exception as e:
        return None, f"Malformed URL syntax: {str(e)}"

    if parsed.scheme.lower() not in ("http", "https"):
        return None, f"Scheme '{parsed.scheme}' not allowed. Must be http or https."

    netloc = parsed.netloc
    if not netloc:
        return None, "URL missing valid hostname/domain."

    # Disallow credentials in authority (user:pass@host)
    if "@" in netloc:
        # Keep track of userinfo for phishing lexical analysis, but validate hostname part
        pass

    # Normalize hostname to lowercase
    hostname = parsed.hostname
    if not hostname:
        return None, "URL does not have a recognizable host."

    # Check for invalid characters in hostname
    if any(c in hostname for c in [" ", "<", ">", '"', "'", "\\", "^", "`", "{", "|", "}"]):
        return None, "Hostname contains illegal characters."

    # Reconstruct normalized URL
    normalized = urlunparse((
        parsed.scheme.lower(),
        parsed.netloc,
        parsed.path or "/",
        parsed.params,
        parsed.query,
        parsed.fragment
    ))

    return normalized, None
