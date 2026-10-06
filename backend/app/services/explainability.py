"""
Explainability & Attribution Engine.
Translates statistical feature vectors, model weights, and heuristic signals
into clear, actionable, human-readable explanations and SHAP-style factor contributions.
"""

from typing import Dict, Any, List


class ExplainabilityService:
    """Generates transparent user-facing explanations and feature impact attributions."""

    @staticmethod
    def generate_explanation(
        url: str,
        risk_data: Dict[str, Any],
        features: Dict[str, Any],
        lexical: Dict[str, Any],
        domain: Dict[str, Any],
        brand: Dict[str, Any],
        html: Dict[str, Any],
        threat: Dict[str, Any],
        feature_importances: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Produces categorized human-readable explanations, primary risk factors,
        and localized feature contribution scores.
        """
        classification = risk_data["classification"]
        risk_score = risk_data["risk_score"]

        reasons: List[Dict[str, Any]] = []

        # 1. Threat Feed Hits
        if threat.get("threat_detected"):
            reasons.append({
                "category": "Threat Intelligence",
                "severity": "CRITICAL",
                "title": "Threat Feed Blacklist Match",
                "description": threat.get("summary", "URL flagged by security threat intelligence sources."),
                "impact": "Increases Risk Significantly"
            })

        # 2. Brand Impersonation / Typosquatting / Combosquatting
        if brand.get("is_suspicious_brand_use"):
            matched = brand.get("matched_brand", "Prominent Institution")
            technique = brand.get("technique", "brand_deception")
            reasons.append({
                "category": "Brand Impersonation",
                "severity": "HIGH",
                "title": f"Impersonation of {matched}",
                "description": brand.get("details", f"Domain strongly resembles {matched}."),
                "impact": "Increases Risk"
            })
        elif brand.get("technique") == "official_domain":
            reasons.append({
                "category": "Brand Verification",
                "severity": "POSITIVE",
                "title": f"Verified Domain for {brand.get('matched_brand')}",
                "description": "Domain matches officially documented infrastructure for this institution.",
                "impact": "Lowers Risk"
            })

        # 3. Direct IP Host
        if lexical.get("has_ip") == 1:
            reasons.append({
                "category": "URL Structure",
                "severity": "HIGH",
                "title": "Numerical IP Host Address",
                "description": "Host uses a raw numerical IP address instead of a registered domain name to evade domain reputation filters.",
                "impact": "Increases Risk"
            })

        # 4. Password Input / External Form Action
        if html.get("has_password_input") == 1:
            if html.get("external_form_action") == 1:
                reasons.append({
                    "category": "Webpage Content",
                    "severity": "CRITICAL",
                    "title": "Cross-Domain Credential Exfiltration",
                    "description": "Webpage requests login passwords and submits them to an external, third-party domain.",
                    "impact": "Increases Risk Significantly"
                })
            else:
                reasons.append({
                    "category": "Webpage Content",
                    "severity": "MEDIUM",
                    "title": "Credential Password Form",
                    "description": "Webpage presents password authentication input fields.",
                    "impact": "Increases Risk"
                })

        # 5. Suspicious Keywords
        keywords = lexical.get("found_keywords", [])
        if len(keywords) > 0:
            reasons.append({
                "category": "Lexical Analysis",
                "severity": "MEDIUM" if len(keywords) > 1 else "LOW",
                "title": f"Suspicious Keywords ({len(keywords)} detected)",
                "description": f"URL incorporates security-sensitive action tokens: {', '.join(keywords)}.",
                "impact": "Increases Risk"
            })

        # 6. TLD Abuse Category
        if domain.get("tld_is_risky") == 1:
            tld = domain.get("tld", "")
            reasons.append({
                "category": "Domain Infrastructure",
                "severity": "MEDIUM",
                "title": f"High-Abuse TLD (.{tld})",
                "description": f"The top-level domain '.{tld}' exhibits disproportionately high frequencies of malicious registration in cybersecurity threat feeds.",
                "impact": "Increases Risk"
            })

        # 7. Subdomain Obfuscation
        sub_count = domain.get("subdomain_count", 0)
        if sub_count >= 3:
            reasons.append({
                "category": "Domain Structure",
                "severity": "MEDIUM",
                "title": f"Excessive Subdomain Depth ({sub_count} levels)",
                "description": "Layered subdomains often attempt to mimic authentic domains or obscure the registered origin.",
                "impact": "Increases Risk"
            })

        # 8. Obfuscation & Homoglyphs
        if lexical.get("has_punycode") == 1:
            reasons.append({
                "category": "Evasion Techniques",
                "severity": "HIGH",
                "title": "Internationalized Domain Name (Punycode)",
                "description": "Punycode (xn--) detected; frequently used in visual spoofing / homograph attacks.",
                "impact": "Increases Risk"
            })

        if lexical.get("is_shortened") == 1:
            reasons.append({
                "category": "Evasion Techniques",
                "severity": "MEDIUM",
                "title": "URL Shortener Redirect",
                "description": "URL leverages a shortening service to hide the final destination target.",
                "impact": "Increases Risk"
            })

        # 9. Benign indicators if few or no risks
        if classification == "legitimate":
            if lexical.get("is_https") == 1:
                reasons.append({
                    "category": "Transport Security",
                    "severity": "POSITIVE",
                    "title": "Standard HTTPS Encryption",
                    "description": "Connection utilizes encrypted HTTPS protocol with standard port assignment.",
                    "impact": "Expected for Normal Web"
                })
            if sub_count <= 1:
                reasons.append({
                    "category": "Domain Structure",
                    "severity": "POSITIVE",
                    "title": "Standard Domain Hierarchy",
                    "description": "Domain follows canonical naming conventions without redundant subdomain nesting.",
                    "impact": "Consistent with Benign Sites"
                })
            reasons.append({
                "category": "Threat Intelligence",
                "severity": "POSITIVE",
                "title": "Clean Reputation Feeds",
                "description": "No active phishing or malware listings detected across threat intelligence sources.",
                "impact": "Lowers Risk"
            })

        # Feature contribution table (Top contributing factors)
        contributions = []
        for feat in feature_importances[:8]:
            fname = feat["feature"]
            fval = features.get(fname, 0.0)
            importance = feat["importance"]

            is_elevating = False
            if fname in ("is_https", "script_count"):
                is_elevating = fval == 0
            else:
                is_elevating = fval > 0

            contributions.append({
                "feature": fname,
                "value": fval,
                "importance_weight": importance,
                "directional_effect": "Elevates Risk" if is_elevating else "Lowers Risk",
            })

        # Summary bullet points for quick glance
        bullet_reasons = [r["title"] for r in reasons if r["severity"] in ("CRITICAL", "HIGH", "MEDIUM")]
        if not bullet_reasons:
            bullet_reasons = [r["title"] for r in reasons if r["severity"] == "POSITIVE"]

        return {
            "summary_reasons": bullet_reasons[:5],
            "detailed_reasons": reasons,
            "feature_contributions": contributions,
            "disclaimer": "Machine-learning predictions and risk estimates are advisory detection aids, not absolute guarantees of website safety."
        }
