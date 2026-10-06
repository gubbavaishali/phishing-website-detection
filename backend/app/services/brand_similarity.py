"""
Brand Similarity & Impersonation Detection Module.
Detects typosquatting, combosquatting, subdomain deception, and homoglyphs
targeting prominent institutions (banks, tech companies, crypto exchanges, e-commerce).
"""

import re
from typing import Dict, Any, Optional, List, Tuple
from urllib.parse import urlparse
import tldextract


# Prominent brand definitions with their genuine registered domains
TARGET_BRANDS: Dict[str, Dict[str, Any]] = {
    "paypal": {
        "name": "PayPal",
        "official_domains": ["paypal.com", "paypal.me"],
        "category": "financial",
    },
    "apple": {
        "name": "Apple",
        "official_domains": ["apple.com", "icloud.com"],
        "category": "technology",
    },
    "google": {
        "name": "Google",
        "official_domains": ["google.com", "youtube.com", "gmail.com"],
        "category": "technology",
    },
    "microsoft": {
        "name": "Microsoft",
        "official_domains": ["microsoft.com", "live.com", "office.com", "outlook.com"],
        "category": "technology",
    },
    "amazon": {
        "name": "Amazon",
        "official_domains": ["amazon.com", "aws.amazon.com"],
        "category": "ecommerce",
    },
    "netflix": {
        "name": "Netflix",
        "official_domains": ["netflix.com"],
        "category": "entertainment",
    },
    "chase": {
        "name": "Chase Bank",
        "official_domains": ["chase.com"],
        "category": "financial",
    },
    "bankofamerica": {
        "name": "Bank of America",
        "official_domains": ["bankofamerica.com", "bofa.com"],
        "category": "financial",
    },
    "wellsfargo": {
        "name": "Wells Fargo",
        "official_domains": ["wellsfargo.com"],
        "category": "financial",
    },
    "facebook": {
        "name": "Facebook",
        "official_domains": ["facebook.com", "fb.com", "meta.com"],
        "category": "social",
    },
    "instagram": {
        "name": "Instagram",
        "official_domains": ["instagram.com"],
        "category": "social",
    },
    "linkedin": {
        "name": "LinkedIn",
        "official_domains": ["linkedin.com"],
        "category": "social",
    },
    "binance": {
        "name": "Binance",
        "official_domains": ["binance.com"],
        "category": "crypto",
    },
    "coinbase": {
        "name": "Coinbase",
        "official_domains": ["coinbase.com"],
        "category": "crypto",
    },
    "steam": {
        "name": "Steam",
        "official_domains": ["steampowered.com", "steamcommunity.com"],
        "category": "gaming",
    },
    "whatsapp": {
        "name": "WhatsApp",
        "official_domains": ["whatsapp.com"],
        "category": "messaging",
    },
    "dhl": {
        "name": "DHL",
        "official_domains": ["dhl.com"],
        "category": "logistics",
    },
    "fedex": {
        "name": "FedEx",
        "official_domains": ["fedex.com"],
        "category": "logistics",
    },
}

# Common phishing combosquatting modifiers
SECURITY_KEYWORDS = {
    "login", "signin", "verify", "verification", "secure", "security",
    "account", "update", "banking", "support", "helpdesk", "recover",
    "auth", "authentication", "billing", "invoice", "confirm", "wallet",
    "portal", "customer", "service", "protect", "alert", "notification"
}

# Character homoglyph/substitution map
HOMOGLYPH_MAP = {
    '0': 'o',
    '1': 'l',
    'i': 'l',
    '!': 'l',
    '|': 'l',
    '3': 'e',
    '4': 'a',
    '@': 'a',
    '5': 's',
    '$': 's',
    '8': 'b',
    'v': 'u',
}


def normalize_substitutions(text: str) -> str:
    """Normalizes typical leetspeak/homoglyph characters to canonical ASCII letters."""
    result = []
    # Replace 'rn' -> 'm' and 'vv' -> 'w'
    s = text.lower().replace("rn", "m").replace("vv", "w")
    for ch in s:
        result.append(HOMOGLYPH_MAP.get(ch, ch))
    return "".join(result)


def levenshtein_distance(s1: str, s2: str) -> int:
    """Computes Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def compute_string_similarity(s1: str, s2: str) -> float:
    """Returns normalized similarity ratio between 0.0 and 1.0."""
    max_len = max(len(s1), len(s2))
    if max_len == 0:
        return 1.0
    dist = levenshtein_distance(s1, s2)
    return max(0.0, 1.0 - (dist / max_len))


class BrandSimilarityAnalyzer:
    """Analyzes URLs for deceptive brand impersonation."""

    def __init__(self):
        self.brands = TARGET_BRANDS

    def analyze(self, url: str) -> Dict[str, Any]:
        parsed = urlparse(url)
        extracted = tldextract.extract(url)

        registered_domain = f"{extracted.domain}.{extracted.suffix}".lower() if extracted.suffix else extracted.domain.lower()
        subdomain = extracted.subdomain.lower()
        domain_name = extracted.domain.lower()
        path = parsed.path.lower()

        # Check if the domain is legitimately owned by any targeted brand
        for brand_key, data in self.brands.items():
            if registered_domain in data["official_domains"]:
                return {
                    "matched_brand": data["name"],
                    "similarity_score": 1.0,
                    "technique": "official_domain",
                    "is_suspicious_brand_use": False,
                    "details": f"Legitimate domain verified for {data['name']}.",
                    "combosquatting": False,
                    "typosquatting": False,
                    "subdomain_deception": False,
                }

        best_match: Optional[str] = None
        best_score: float = 0.0
        technique = "none"
        suspicious = False
        details: List[str] = []

        # 1. Check Subdomain Brand Deception (e.g. paypal.com.attacker.xyz or login-paypal.attacker.com)
        for brand_key, data in self.brands.items():
            brand_canonical = brand_key
            if brand_canonical in subdomain:
                best_match = data["name"]
                best_score = max(best_score, 0.92)
                suspicious = True
                technique = "subdomain_deception"
                details.append(f"Brand '{data['name']}' found in subdomain of unrelated domain '{registered_domain}'.")

        # 2. Check Combosquatting in domain (e.g. paypal-security.com, paypa1-security.xyz)
        norm_domain = normalize_substitutions(domain_name)
        for brand_key, data in self.brands.items():
            if brand_key in domain_name or brand_key in norm_domain:
                # Check if accompanied by security keywords, hyphens, or is compound
                has_sec_keyword = any(kw in domain_name for kw in SECURITY_KEYWORDS)
                has_hyphen = "-" in domain_name
                if has_sec_keyword or has_hyphen or len(domain_name) > len(brand_key) or brand_key in norm_domain:
                    best_match = data["name"]
                    best_score = max(best_score, 0.90)
                    suspicious = True
                    technique = "combosquatting" if has_hyphen or has_sec_keyword else "typosquatting"
                    details.append(f"Domain combines brand '{data['name']}' with suspicious tokens, substitutions, or hyphens.")

        # 3. Check Typosquatting / Homoglyphs in domain name
        clean_domain = re.sub(r"^(my|the|e|i|web|online|safe|login|secure)-?", "", domain_name)
        clean_norm_domain = normalize_substitutions(clean_domain)

        for brand_key, data in self.brands.items():
            brand_len = len(brand_key)
            if abs(len(domain_name) - brand_len) <= 3:
                # Direct similarity
                sim1 = compute_string_similarity(domain_name, brand_key)
                # Homoglyph normalized similarity
                sim2 = compute_string_similarity(norm_domain, brand_key)
                sim3 = compute_string_similarity(clean_norm_domain, brand_key)
                top_sim = max(sim1, sim2, sim3)

                if top_sim >= 0.75 and top_sim < 1.0:
                    if top_sim > best_score:
                        best_score = top_sim
                        best_match = data["name"]
                        suspicious = True
                        technique = "typosquatting"
                        details.append(f"Domain '{domain_name}' typosquats brand '{data['name']}' (similarity: {top_sim:.2f}).")

        # 4. Check Path Deception (brand in path on sketchy or unverified domain)
        if not suspicious:
            for brand_key, data in self.brands.items():
                if f"/{brand_key}" in path or f"{brand_key}-" in path:
                    best_match = data["name"]
                    best_score = max(best_score, 0.65)
                    suspicious = True
                    technique = "path_deception"
                    details.append(f"Path mimics brand '{data['name']}' on third-party domain.")

        return {
            "matched_brand": best_match,
            "similarity_score": round(best_score, 3),
            "technique": technique,
            "is_suspicious_brand_use": suspicious,
            "details": "; ".join(details) if details else "No brand impersonation detected.",
            "combosquatting": technique == "combosquatting",
            "typosquatting": technique == "typosquatting",
            "subdomain_deception": technique == "subdomain_deception",
        }
