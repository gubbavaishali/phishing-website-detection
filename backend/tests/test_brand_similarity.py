"""
Unit tests for Brand Similarity and Impersonation Analyzer.
"""

import pytest
from app.services.brand_similarity import BrandSimilarityAnalyzer


analyzer = BrandSimilarityAnalyzer()


def test_official_brand_domain():
    res = analyzer.analyze("https://www.paypal.com/signin")
    assert res["matched_brand"] == "PayPal"
    assert res["technique"] == "official_domain"
    assert not res["is_suspicious_brand_use"]


def test_combosquatting_detection():
    res = analyzer.analyze("https://paypal-account-verification-alert.com/webscr")
    assert res["matched_brand"] == "PayPal"
    assert res["is_suspicious_brand_use"]
    assert res["combosquatting"]


def test_typosquatting_homoglyph_detection():
    res = analyzer.analyze("https://paypa1-security.xyz/login")
    assert res["matched_brand"] == "PayPal"
    assert res["is_suspicious_brand_use"]
    assert res["similarity_score"] >= 0.75


def test_subdomain_brand_deception():
    res = analyzer.analyze("http://paypal.com.account-update.xyz/auth")
    assert res["matched_brand"] == "PayPal"
    assert res["is_suspicious_brand_use"]
    assert res["subdomain_deception"]


def test_benign_unrelated_domain():
    res = analyzer.analyze("https://developer.mozilla.org/en-US/")
    assert not res["is_suspicious_brand_use"]
