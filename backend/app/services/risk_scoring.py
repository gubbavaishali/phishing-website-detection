"""
Transparent Risk Scoring Engine.
Synthesizes machine learning prediction probabilities, threat intelligence hits,
brand impersonation indicators, and structural anomalies into a calibrated 0-100 risk score.
"""

from typing import Dict, Any, Tuple


class RiskScoringService:
    """Computes transparent, defensible risk scores and threat tiers."""

    @staticmethod
    def calculate_risk(
        ml_probability: float,
        features: Dict[str, Any],
        threat_data: Dict[str, Any],
        brand_data: Dict[str, Any],
        html_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Calculates calibrated risk score (0 to 100), classification category,
        and provides transparent factor breakdown.
        """
        # Base score from ML model (0 to 60 points)
        base_ml_score = ml_probability * 60.0

        # Heuristic threat multipliers and additions
        modifiers = 0.0
        applied_rules = []

        # 1. Threat Feed Hit (Immediate severe indicator)
        if threat_data.get("threat_detected", False):
            bonus = 35.0
            modifiers += bonus
            applied_rules.append({"rule": "Threat Intelligence Feed Match", "impact": f"+{int(bonus)} pts"})

        # 2. Brand Impersonation / Combosquatting / Typosquatting
        if brand_data.get("is_suspicious_brand_use", False):
            sim = brand_data.get("similarity_score", 0.0)
            bonus = min(30.0, 15.0 + (sim * 15.0))
            modifiers += bonus
            applied_rules.append({
                "rule": f"Brand Deception ({brand_data.get('matched_brand', 'Target')})",
                "impact": f"+{int(bonus)} pts"
            })

        # 3. Direct IP Address Host
        if features.get("has_ip", 0) == 1:
            bonus = 25.0
            modifiers += bonus
            applied_rules.append({"rule": "Host is Direct Numerical IP", "impact": f"+{int(bonus)} pts"})

        # 4. Credential / Password form on unverified domain
        if html_data.get("has_password_input", 0) == 1:
            bonus = 15.0
            if html_data.get("external_form_action", 0) == 1:
                bonus += 15.0  # Password transmitted to foreign third party
                applied_rules.append({"rule": "Credentials Submitted to Foreign Domain", "impact": "+30 pts"})
            else:
                applied_rules.append({"rule": "Password Input Field Detected", "impact": "+15 pts"})
            modifiers += bonus

        # 5. High Abuse TLD (.xyz, .top, .buzz, etc.)
        if features.get("tld_is_risky", 0) == 1:
            bonus = 10.0
            modifiers += bonus
            applied_rules.append({"rule": "High-Abuse Top-Level Domain (TLD)", "impact": f"+{int(bonus)} pts"})

        # 6. IDN Homograph / Punycode
        if features.get("has_punycode", 0) == 1:
            bonus = 15.0
            modifiers += bonus
            applied_rules.append({"rule": "IDN Punycode Character Obfuscation", "impact": f"+{int(bonus)} pts"})

        # 7. Benign Dampeners (Official brand domain or trusted TLD)
        if brand_data.get("technique") == "official_domain":
            dampener = -30.0
            modifiers += dampener
            applied_rules.append({"rule": "Verified Official Domain", "impact": f"{int(dampener)} pts"})
        elif features.get("is_https", 0) == 1 and ml_probability < 0.15 and not brand_data.get("is_suspicious_brand_use"):
            dampener = -10.0
            modifiers += dampener
            applied_rules.append({"rule": "Valid HTTPS with Standard Domain Structure", "impact": f"{int(dampener)} pts"})

        raw_score = base_ml_score + modifiers
        final_score = int(round(max(0.0, min(100.0, raw_score))))

        # Classification Tiers
        if final_score >= 80:
            classification = "phishing"
            severity = "VERY HIGH RISK"
            label = "Likely Phishing (High Confidence)"
        elif final_score >= 60:
            classification = "phishing"
            severity = "HIGH RISK"
            label = "Likely Phishing"
        elif final_score >= 30:
            classification = "suspicious"
            severity = "MEDIUM RISK"
            label = "Suspicious"
        else:
            classification = "legitimate"
            severity = "LOW RISK"
            label = "Likely Legitimate"

        # Confidence calculation
        if final_score >= 80 or final_score <= 15:
            confidence = round(max(ml_probability, 1.0 - ml_probability, 0.90), 2)
            confidence_level = "High"
        elif final_score >= 60 or final_score <= 30:
            confidence = round(max(ml_probability, 1.0 - ml_probability, 0.80), 2)
            confidence_level = "Medium"
        else:
            confidence = round(0.65, 2)
            confidence_level = "Moderate"

        return {
            "risk_score": final_score,
            "classification": classification,
            "severity_tier": severity,
            "classification_label": label,
            "confidence": confidence,
            "confidence_level": confidence_level,
            "base_ml_score": round(base_ml_score, 1),
            "heuristic_modifiers": round(modifiers, 1),
            "applied_rules": applied_rules,
        }
