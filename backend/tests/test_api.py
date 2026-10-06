"""
Integration tests for FastAPI endpoints.
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app


client = TestClient(app)


def test_healthcheck_endpoint():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["model_loaded"] is True
    assert "model_version" in data


def test_benchmark_endpoint():
    response = client.get("/api/v1/benchmark")
    assert response.status_code == 200
    data = response.json()
    assert "model_comparisons" in data
    assert "Random Forest" in data["model_comparisons"]
    assert "generalization_benchmark" in data


def test_analyze_legitimate_url():
    response = client.post(
        "/api/v1/analyze",
        json={"url": "https://www.google.com/search?q=test", "inspect_html": False}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] in ("legitimate", "suspicious", "phishing")
    assert "risk_score" in data
    assert "reasons" in data
    assert data["risk_score"] < 40  # Google should have low risk


def test_analyze_phishing_url():
    response = client.post(
        "/api/v1/analyze",
        json={"url": "http://192.168.1.1/paypal-login-verify/auth.php", "inspect_html": False}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] == "phishing"
    assert data["risk_score"] >= 60


def test_analyze_invalid_url():
    response = client.post(
        "/api/v1/analyze",
        json={"url": "javascript:alert('xss')", "inspect_html": False}
    )
    assert response.status_code == 422


def test_history_endpoint():
    response = client.get("/api/v1/history?limit=10&page=1")
    assert response.status_code == 200
    data = response.json()
    # Now returns paginated envelope: {scans, total, page, limit}
    assert isinstance(data, dict)
    assert "scans" in data
    assert isinstance(data["scans"], list)
    assert "total" in data
    assert "page" in data
    assert "limit" in data
    assert data["page"] == 1
    assert data["limit"] == 10


def test_history_stats_endpoint():
    response = client.get("/api/v1/history/stats")
    assert response.status_code == 200
    stats = response.json()
    assert "total_scans" in stats
