"""
Scan History API Endpoint.
Retrieves recent phishing scan records and summary statistics.
"""

from typing import List, Dict, Any
from fastapi import APIRouter, Query
from app.schemas.response import ScanHistoryItem
from app.services.database import ScanDatabase
from app.config import settings


router = APIRouter()
db = ScanDatabase(supabase_url=settings.SUPABASE_URL, supabase_key=settings.SUPABASE_KEY)


@router.get("/history", summary="Get recent scan history")
async def get_scan_history(
    limit: int = Query(default=20, ge=1, le=100),
    page: int = Query(default=1, ge=1),
):
    """Returns paginated scan history with envelope: {scans, total, page, limit}."""
    all_records = await db.get_recent_scans(limit=500)
    total = len(all_records)
    start = (page - 1) * limit
    paginated = all_records[start: start + limit]
    return {
        "scans": paginated,
        "total": total,
        "page": page,
        "limit": limit,
    }


@router.get("/history/stats", summary="Get aggregate scan statistics")
async def get_scan_statistics():
    records = await db.get_recent_scans(limit=500)
    total = len(records)
    phishing = sum(1 for r in records if r.get("classification") == "phishing")
    suspicious = sum(1 for r in records if r.get("classification") == "suspicious")
    legitimate = sum(1 for r in records if r.get("classification") == "legitimate")

    avg_score = round(sum(r.get("risk_score", 0) for r in records) / total, 1) if total > 0 else 0.0

    return {
        "total_scans": total,
        "phishing_detected": phishing,
        "suspicious_detected": suspicious,
        "legitimate_verified": legitimate,
        "average_risk_score": avg_score,
    }
