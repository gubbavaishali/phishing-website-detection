"""
Domain and DNS Analysis Module.
Analyzes domain structure, TLD reputation category, entropy (DGA detection),
subdomain depth, and DNS resolution status.
"""

import math
import socket
from typing import Dict, Any, List
from urllib.parse import urlparse
import tldextract


# TLD Risk classification based on anti-abuse / spam research reports
RISKY_TLDS = {
    "xyz", "top", "buzz", "club", "icu", "work", "click", "loan", "cam",
    "sbs", "cfd", "monster", "rest", "bar", "gq", "cf", "tk", "ml", "ga",
    "fit", "surf", "stream", "online", "site", "vip", "bid", "review"
}

TRUSTED_TLDS = {
    "gov", "mil", "edu", "ac.uk", "gov.uk", "gc.ca", "gov.au"
}


def calculate_shannon_entropy(text: str) -> float:
    """Calculates Shannon entropy of string to identify random / DGA domains."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


class DomainAnalyzer:
    """Extracts and evaluates structural and cryptographic domain indicators."""

    def __init__(self):
        self.risky_tlds = RISKY_TLDS
        self.trusted_tlds = TRUSTED_TLDS

    def analyze(self, url: str, check_dns: bool = False) -> Dict[str, Any]:
        parsed = urlparse(url)
        extracted = tldextract.extract(url)

        domain = extracted.domain.lower() if extracted.domain else ""
        suffix = extracted.suffix.lower() if extracted.suffix else ""
        subdomain = extracted.subdomain.lower() if extracted.subdomain else ""
        hostname = parsed.hostname.lower() if parsed.hostname else ""

        # Shannon Entropy on domain label
        entropy = calculate_shannon_entropy(domain)

        # Subdomain count
        subdomain_parts = [p for p in subdomain.split(".") if p] if subdomain else []
        subdomain_count = len(subdomain_parts)

        # TLD Evaluation
        tld_is_risky = 1 if suffix in self.risky_tlds else 0
        tld_is_trusted = 1 if suffix in self.trusted_tlds else 0

        # Hyphens and Digits in domain
        has_hyphen = 1 if "-" in domain else 0
        digit_count_domain = sum(1 for c in domain if c.isdigit())
        digit_ratio_domain = round(digit_count_domain / len(domain), 3) if domain else 0.0

        # DNS Check (optional, fast-pathed)
        dns_resolves = False
        resolved_ips: List[str] = []
        if check_dns and hostname:
            try:
                orig_timeout = socket.getdefaulttimeout()
                socket.setdefaulttimeout(0.5)
                addr_info = socket.getaddrinfo(hostname, None)
                for item in addr_info:
                    ip = item[4][0]
                    if ip not in resolved_ips:
                        resolved_ips.append(ip)
                dns_resolves = len(resolved_ips) > 0
                socket.setdefaulttimeout(orig_timeout)
            except Exception:
                dns_resolves = False

        # Domain findings
        findings = []
        if tld_is_risky:
            findings.append(f"TLD '.{suffix}' is statistically associated with higher phishing abuse rates.")
        if subdomain_count >= 3:
            findings.append(f"Excessive subdomain depth ({subdomain_count} levels) used for obfuscation.")
        if entropy > 3.6 and len(domain) > 10:
            findings.append(f"High domain randomness/entropy ({entropy}) indicative of algorithmically generated domain (DGA).")
        if digit_ratio_domain > 0.35:
            findings.append(f"High concentration of numerical digits ({int(digit_ratio_domain*100)}%) in domain name.")

        return {
            "registered_domain": f"{domain}.{suffix}" if suffix else domain,
            "domain_name": domain,
            "tld": suffix,
            "subdomain": subdomain,
            "domain_length": len(domain),
            "subdomain_length": len(subdomain),
            "subdomain_count": subdomain_count,
            "domain_entropy": entropy,
            "tld_is_risky": tld_is_risky,
            "tld_is_trusted": tld_is_trusted,
            "has_hyphen_in_domain": has_hyphen,
            "digit_ratio_domain": digit_ratio_domain,
            "dns_resolves": dns_resolves,
            "resolved_ip_count": len(resolved_ips),
            "domain_findings": findings,
        }
