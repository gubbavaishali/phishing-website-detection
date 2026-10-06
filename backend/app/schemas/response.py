"""
Pydantic API Response Schemas.
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class DetailedReason(BaseModel):
    category: str
    severity: str
    title: str
    description: str
    impact: str


class FeatureContribution(BaseModel):
    feature: str
    value: float
    importance_weight: float
    directional_effect: str


class BrandAnalysisResponse(BaseModel):
    matched_brand: Optional[str] = None
    similarity_score: float
    technique: str
    is_suspicious_brand_use: bool
    details: str


class DomainAnalysisResponse(BaseModel):
    registered_domain: str
    domain_name: str
    tld: str
    subdomain: str
    subdomain_count: int
    domain_entropy: float
    tld_is_risky: int
    has_hyphen_in_domain: int
    dns_resolves: bool


class ThreatIntelResponse(BaseModel):
    threat_detected: bool
    reputation_score: float
    sources: Dict[str, Any]
    summary: str


class HtmlAnalysisResponse(BaseModel):
    html_retrieved: bool
    has_password_input: int
    has_login_form: int
    external_form_action: int
    has_hidden_iframe: int
    script_count: int
    external_resources_ratio: float
    suspicious_html_indicators: List[str]


class AnalyzeUrlResponse(BaseModel):
    scan_id: str
    submitted_url: str
    normalized_url: str
    classification: str = Field(..., description="phishing, suspicious, or legitimate")
    classification_label: str
    risk_score: int = Field(..., ge=0, le=100)
    severity_tier: str
    confidence: float
    confidence_level: str
    reasons: List[str]
    detailed_reasons: List[DetailedReason]
    feature_contributions: List[FeatureContribution]
    brand_analysis: BrandAnalysisResponse
    domain_analysis: DomainAnalysisResponse
    threat_intelligence: ThreatIntelResponse
    html_analysis: HtmlAnalysisResponse
    features: Dict[str, Any]
    model_version: str
    disclaimer: str
    scanned_at: str


class ScanHistoryItem(BaseModel):
    id: str
    submitted_url: str
    normalized_url: str
    classification: str
    risk_score: int
    confidence: float
    model_version: str
    reasons: List[str]
    created_at: str


class HealthResponse(BaseModel):
    status: str
    service: str
    model_loaded: bool
    model_version: str
    feature_schema_version: str
    algorithm: str
    database_connected: bool = True
