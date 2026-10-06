"""
Healthcheck and Observability Endpoint.
"""

from fastapi import APIRouter
from app.schemas.response import HealthResponse
from app.ml.model_loader import ModelLoader
from app.config import settings


router = APIRouter()


@router.get("/health", response_model=HealthResponse, summary="Check API health and model status")
def healthcheck():
    model_loader = ModelLoader.get_instance()
    return HealthResponse(
        status="healthy",
        service=settings.APP_NAME,
        model_loaded=model_loader.model is not None,
        model_version=model_loader.model_version,
        feature_schema_version=model_loader.feature_schema_version,
        algorithm=model_loader.metadata.get("algorithm", "Random Forest"),
        database_connected=True,
    )
