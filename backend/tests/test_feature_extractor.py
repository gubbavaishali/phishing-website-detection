"""
Unit tests for Feature Extractor.
"""

import pytest
from app.services.feature_extractor import FeatureExtractor, FEATURE_NAMES


extractor = FeatureExtractor()


def test_feature_vector_length_and_order():
    res = extractor.extract_all("https://example.com/login?u=test")
    vector = res["feature_vector"]
    names = res["feature_names"]

    assert len(vector) == len(FEATURE_NAMES)
    assert len(names) == len(FEATURE_NAMES)
    assert names == FEATURE_NAMES


def test_ip_address_detection():
    res = extractor.extract_all("http://192.168.1.1/login")
    assert res["features"]["has_ip"] == 1


def test_suspicious_keywords_detection():
    res = extractor.extract_all("https://bank-verify-account.com/login/update")
    assert res["features"]["has_suspicious_keyword"] == 1
    assert res["features"]["suspicious_keyword_count"] >= 3


def test_punycode_detection():
    res = extractor.extract_all("https://xn--appl-coa.com/signin")
    assert res["features"]["has_punycode"] == 1


def test_risky_tld_detection():
    res = extractor.extract_all("https://account-security.xyz/")
    assert res["features"]["tld_is_risky"] == 1
