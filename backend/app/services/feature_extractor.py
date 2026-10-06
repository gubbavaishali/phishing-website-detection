"""
Authoritative Feature Extraction Service.
Extracts lexical, domain, brand similarity, HTML metadata, and reputation signals
into a deterministic, ordered feature vector used identically in training and inference.
"""

import re
import ipaddress
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
import tldextract

from app.services.brand_similarity import BrandSimilarityAnalyzer
from app.services.domain_analyzer import DomainAnalyzer
from app.services.html_analyzer import HTMLMetadataAnalyzer


# Fixed authoritative feature list in exact order
FEATURE_NAMES: List[str] = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "count_dots",
    "count_hyphens",
    "count_at",
    "count_question",
    "count_percent",
    "count_equal",
    "count_underscore",
    "count_slash",
    "count_digits",
    "digit_ratio",
    "count_subdomains",
    "has_ip",
    "is_shortened",
    "has_suspicious_keyword",
    "suspicious_keyword_count",
    "is_https",
    "double_slash_in_path",
    "tld_in_subdomain",
    "has_punycode",
    "domain_length",
    "subdomain_length",
    "domain_entropy",
    "tld_is_risky",
    "has_hyphen_in_domain",
    "brand_similarity_score",
    "is_suspicious_brand_use",
    "has_password_input",
    "has_login_form",
    "external_form_action",
    "has_hidden_iframe",
    "script_count",
    "external_resources_ratio",
    "threat_feed_score",
]

# Known URL shortener services
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "goo.gl", "buff.ly",
    "ow.ly", "adf.ly", "bit.do", "cutt.ly", "tiny.cc", "rebrand.ly",
}

# Suspicious phishing lexical keywords
PHISHING_KEYWORDS = [
    "login", "signin", "verify", "verification", "secure", "security",
    "account", "update", "banking", "authenticate", "confirm", "wallet",
    "password", "support", "helpdesk", "recovery", "billing", "invoice",
    "validate", "unlock", "alert", "notification", "suspend", "webscr",
]

COMMON_TLDS = {"com", "net", "org", "info", "biz", "co", "io", "xyz"}


class FeatureExtractor:
    """Extracts all feature signals from URL, domain, HTML, and threat sources."""

    def __init__(self):
        self.brand_analyzer = BrandSimilarityAnalyzer()
        self.domain_analyzer = DomainAnalyzer()
        self.html_analyzer = HTMLMetadataAnalyzer()

    def extract_lexical_features(self, url: str) -> Dict[str, Any]:
        """Extracts purely lexical / syntactic URL features."""
        parsed = urlparse(url)
        extracted = tldextract.extract(url)

        hostname = (parsed.hostname or "").lower()
        path = parsed.path or ""
        query = parsed.query or ""
        url_lower = url.lower()

        # Check if hostname is an IP address
        has_ip = 0
        try:
            ipaddress.ip_address(hostname)
            has_ip = 1
        except ValueError:
            has_ip = 0

        # Digits count & ratio
        digit_count = sum(1 for c in url if c.isdigit())
        digit_ratio = round(digit_count / len(url), 4) if len(url) > 0 else 0.0

        # Shortener check
        is_shortened = 1 if f"{extracted.domain}.{extracted.suffix}".lower() in SHORTENER_DOMAINS else 0

        # Suspicious keywords
        found_keywords = [kw for kw in PHISHING_KEYWORDS if kw in url_lower]
        has_suspicious_keyword = 1 if len(found_keywords) > 0 else 0
        suspicious_keyword_count = len(found_keywords)

        # Punycode check
        has_punycode = 1 if "xn--" in hostname else 0

        # Double slash in path check
        double_slash_in_path = 1 if "//" in path else 0

        # TLD embedded in subdomain check (e.g. paypal.com.attacker.org)
        tld_in_sub = 0
        subdomain = extracted.subdomain.lower()
        for tld in COMMON_TLDS:
            if f".{tld}." in f".{subdomain}." or subdomain.endswith(f".{tld}"):
                tld_in_sub = 1
                break

        return {
            "url_length": len(url),
            "hostname_length": len(hostname),
            "path_length": len(path),
            "query_length": len(query),
            "count_dots": url.count("."),
            "count_hyphens": url.count("-"),
            "count_at": url.count("@"),
            "count_question": url.count("?"),
            "count_percent": url.count("%"),
            "count_equal": url.count("="),
            "count_underscore": url.count("_"),
            "count_slash": url.count("/"),
            "count_digits": digit_count,
            "digit_ratio": digit_ratio,
            "has_ip": has_ip,
            "is_shortened": is_shortened,
            "has_suspicious_keyword": has_suspicious_keyword,
            "suspicious_keyword_count": suspicious_keyword_count,
            "is_https": 1 if parsed.scheme.lower() == "https" else 0,
            "double_slash_in_path": double_slash_in_path,
            "tld_in_subdomain": tld_in_sub,
            "has_punycode": has_punycode,
            "found_keywords": found_keywords,
        }

    def extract_all(
        self,
        url: str,
        html_content: Optional[str] = None,
        threat_score: float = 0.0,
    ) -> Dict[str, Any]:
        """
        Extracts complete multi-signal feature dictionary and numerical vector.
        """
        lexical = self.extract_lexical_features(url)
        domain_info = self.domain_analyzer.analyze(url)
        brand_info = self.brand_analyzer.analyze(url)
        html_info = self.html_analyzer.analyze(html_content, url)

        # Assemble unified feature dictionary
        features = {
            "url_length": lexical["url_length"],
            "hostname_length": lexical["hostname_length"],
            "path_length": lexical["path_length"],
            "query_length": lexical["query_length"],
            "count_dots": lexical["count_dots"],
            "count_hyphens": lexical["count_hyphens"],
            "count_at": lexical["count_at"],
            "count_question": lexical["count_question"],
            "count_percent": lexical["count_percent"],
            "count_equal": lexical["count_equal"],
            "count_underscore": lexical["count_underscore"],
            "count_slash": lexical["count_slash"],
            "count_digits": lexical["count_digits"],
            "digit_ratio": lexical["digit_ratio"],
            "count_subdomains": domain_info["subdomain_count"],
            "has_ip": lexical["has_ip"],
            "is_shortened": lexical["is_shortened"],
            "has_suspicious_keyword": lexical["has_suspicious_keyword"],
            "suspicious_keyword_count": lexical["suspicious_keyword_count"],
            "is_https": lexical["is_https"],
            "double_slash_in_path": lexical["double_slash_in_path"],
            "tld_in_subdomain": lexical["tld_in_subdomain"],
            "has_punycode": lexical["has_punycode"],
            "domain_length": domain_info["domain_length"],
            "subdomain_length": domain_info["subdomain_length"],
            "domain_entropy": domain_info["domain_entropy"],
            "tld_is_risky": domain_info["tld_is_risky"],
            "has_hyphen_in_domain": domain_info["has_hyphen_in_domain"],
            "brand_similarity_score": brand_info["similarity_score"],
            "is_suspicious_brand_use": 1 if brand_info["is_suspicious_brand_use"] else 0,
            "has_password_input": html_info["has_password_input"],
            "has_login_form": html_info["has_login_form"],
            "external_form_action": html_info["external_form_action"],
            "has_hidden_iframe": html_info["has_hidden_iframe"],
            "script_count": html_info["script_count"],
            "external_resources_ratio": html_info["external_resources_ratio"],
            "threat_feed_score": threat_score,
        }

        # Deterministic ordered vector for ML
        vector = [float(features[name]) for name in FEATURE_NAMES]

        return {
            "features": features,
            "feature_vector": vector,
            "feature_names": FEATURE_NAMES,
            "lexical_details": lexical,
            "domain_details": domain_info,
            "brand_details": brand_info,
            "html_details": html_info,
        }
