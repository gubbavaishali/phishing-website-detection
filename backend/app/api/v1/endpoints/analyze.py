"""
Analyze URL API Endpoint.
Orchestrates URL sanitization, SSRF-protected safe HTML retrieval,
feature extraction, ML classification, risk calculation, explainability, and scan persistence.
"""

from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, status
from app.schemas.request import AnalyzeUrlRequest
from app.schemas.response import AnalyzeUrlResponse
from app.security.url_sanitizer import sanitize_and_normalize_url
from app.security.ssrf import safe_fetch_page_metadata, is_safe_url_to_fetch
from app.services.feature_extractor import FeatureExtractor
from app.services.threat_intel import ThreatIntelligenceService
from app.services.risk_scoring import RiskScoringService
from app.services.explainability import ExplainabilityService
from app.services.database import ScanDatabase
from app.ml.model_loader import ModelLoader
from app.config import settings


router = APIRouter()

extractor = FeatureExtractor()
threat_service = ThreatIntelligenceService(google_api_key=settings.GOOGLE_SAFE_BROWSING_API_KEY)
db = ScanDatabase(supabase_url=settings.SUPABASE_URL, supabase_key=settings.SUPABASE_KEY)


@router.post("/analyze", response_model=AnalyzeUrlResponse, summary="Analyze a URL for phishing threats")
async def analyze_url(payload: AnalyzeUrlRequest):
    # 1. URL Validation & Normalization
    raw_url = payload.url.strip()
    normalized_url, error = sanitize_and_normalize_url(raw_url)
    if error or not normalized_url:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "URL_VALIDATION_FAILED", "message": error or "Invalid URL format."}
        )

    # 2. SSRF Check & Controlled HTML Retrieval
    html_content = None
    if payload.inspect_html and settings.ENABLE_HTML_INSPECTION:
        is_safe, ssrf_err = is_safe_url_to_fetch(normalized_url)
        if is_safe:
            html_content, _, _ = await safe_fetch_page_metadata(
                normalized_url,
                timeout=settings.HTTP_TIMEOUT_SECONDS,
                max_bytes=settings.MAX_RESPONSE_SIZE_BYTES
            )

    # 3. Threat Intelligence Cross-Check
    threat_data = await threat_service.check_reputation(normalized_url)
    threat_score = threat_data.get("reputation_score", 0.0)

    # 4. Multi-Signal Feature Extraction
    extracted_data = extractor.extract_all(
        url=normalized_url,
        html_content=html_content,
        threat_score=threat_score
    )

    features = extracted_data["features"]
    feature_vector = extracted_data["feature_vector"]
    lexical = extracted_data["lexical_details"]
    domain = extracted_data["domain_details"]
    brand = extracted_data["brand_details"]
    html = extracted_data["html_details"]

    # 5. Machine Learning Model Inference
    model_loader = ModelLoader.get_instance()
    ml_probability = model_loader.predict_proba(feature_vector)

    # 6. Risk Scoring & Classification
    risk_data = RiskScoringService.calculate_risk(
        ml_probability=ml_probability,
        features=features,
        threat_data=threat_data,
        brand_data=brand,
        html_data=html
    )

    # 7. Human-Readable Explainability Generation
    top_features = model_loader.metadata.get("top_features", [])
    explanation = ExplainabilityService.generate_explanation(
        url=normalized_url,
        risk_data=risk_data,
        features=features,
        lexical=lexical,
        domain=domain,
        brand=brand,
        html=html,
        threat=threat_data,
        feature_importances=top_features
    )

    # 8. Persistent Record Storage
    scan_id = await db.save_scan(
        submitted_url=raw_url,
        normalized_url=normalized_url,
        classification=risk_data["classification"],
        risk_score=risk_data["risk_score"],
        confidence=risk_data["confidence"],
        model_version=model_loader.model_version,
        features=features,
        reasons=explanation["summary_reasons"]
    )

    scanned_at = datetime.now(timezone.utc).isoformat()

    return AnalyzeUrlResponse(
        scan_id=scan_id,
        submitted_url=raw_url,
        normalized_url=normalized_url,
        classification=risk_data["classification"],
        classification_label=risk_data["classification_label"],
        risk_score=risk_data["risk_score"],
        severity_tier=risk_data["severity_tier"],
        confidence=risk_data["confidence"],
        confidence_level=risk_data["confidence_level"],
        reasons=explanation["summary_reasons"],
        detailed_reasons=explanation["detailed_reasons"],
        feature_contributions=explanation["feature_contributions"],
        brand_analysis=brand,
        domain_analysis=domain,
        threat_intelligence=threat_data,
        html_analysis=html,
        features=features,
        model_version=model_loader.model_version,
        disclaimer=explanation["disclaimer"],
        scanned_at=scanned_at,
    )
