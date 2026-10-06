"""
Unit tests for Risk Scoring and Explainability.
"""

import pytest
from app.services.risk_scoring import RiskScoringService
from app.services.explainability import ExplainabilityService


def test_high_risk_scoring_for_phishing():
    features = {"has_ip": 1, "tld_is_risky": 1, "is_https": 0}
    threat = {"threat_detected": True, "reputation_score": 1.0}
    brand = {"is_suspicious_brand_use": True, "matched_brand": "PayPal", "similarity_score": 0.9}
    html = {"has_password_input": 1, "external_form_action": 1}

    risk = RiskScoringService.calculate_risk(
        ml_probability=0.95,
        features=features,
        threat_data=threat,
        brand_data=brand,
        html_data=html
    )

    assert risk["risk_score"] >= 80
    assert risk["classification"] == "phishing"
    assert risk["severity_tier"] == "VERY HIGH RISK"


def test_low_risk_scoring_for_legitimate():
    features = {"has_ip": 0, "tld_is_risky": 0, "is_https": 1}
    threat = {"threat_detected": False, "reputation_score": 0.0}
    brand = {"is_suspicious_brand_use": False, "technique": "official_domain", "matched_brand": "Google"}
    html = {"has_password_input": 0, "external_form_action": 0}

    risk = RiskScoringService.calculate_risk(
        ml_probability=0.02,
        features=features,
        threat_data=threat,
        brand_data=brand,
        html_data=html
    )

    assert risk["risk_score"] <= 20
    assert risk["classification"] == "legitimate"
    assert risk["severity_tier"] == "LOW RISK"


def test_explainability_generation():
    risk_data = {"classification": "phishing", "risk_score": 88}
    features = {"has_ip": 1, "is_https": 0}
    lexical = {"has_ip": 1, "found_keywords": ["login", "verify"]}
    domain = {"tld_is_risky": 1, "tld": "xyz", "subdomain_count": 3}
    brand = {"is_suspicious_brand_use": True, "matched_brand": "PayPal", "technique": "combosquatting"}
    html = {"has_password_input": 1, "external_form_action": 1}
    threat = {"threat_detected": True, "summary": "Flagged by threat feed"}
    top_feats = [{"feature": "is_https", "importance": 0.15}]

    expl = ExplainabilityService.generate_explanation(
        url="http://192.168.1.1/paypal/verify",
        risk_data=risk_data,
        features=features,
        lexical=lexical,
        domain=domain,
        brand=brand,
        html=html,
        threat=threat,
        feature_importances=top_feats
    )

    assert len(expl["summary_reasons"]) > 0
    assert len(expl["detailed_reasons"]) > 0
    assert "disclaimer" in expl
