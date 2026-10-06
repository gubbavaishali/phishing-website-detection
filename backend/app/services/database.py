"""
Persistent Scan Store Module.
Provides durable scan storage using Supabase PostgreSQL when credentials exist,
with transparent fallback to local SQLite for out-of-the-box local operation.
"""

import os
import sqlite3
import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import httpx


DB_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "scans.db")


class ScanDatabase:
    """Manages scan history records with Supabase and SQLite fallback."""

    def __init__(self, supabase_url: Optional[str] = None, supabase_key: Optional[str] = None):
        self.supabase_url = supabase_url.rstrip("/") if supabase_url else None
        self.supabase_key = supabase_key
        self.use_supabase = bool(self.supabase_url and self.supabase_key)
        self._init_sqlite()

    def _init_sqlite(self):
        """Initializes local SQLite schema with indexes and constraints."""
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    submitted_url TEXT NOT NULL,
                    normalized_url TEXT NOT NULL,
                    classification TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    confidence REAL NOT NULL,
                    model_version TEXT NOT NULL,
                    features_json TEXT,
                    reasons_json TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_created ON scans (created_at DESC);")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_url ON scans (normalized_url);")
            conn.commit()

    async def save_scan(
        self,
        submitted_url: str,
        normalized_url: str,
        classification: str,
        risk_score: int,
        confidence: float,
        model_version: str,
        features: Dict[str, Any],
        reasons: List[str]
    ) -> str:
        """Persists scan record and returns unique scan ID."""
        scan_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        # Try Supabase if configured
        if self.use_supabase:
            try:
                async with httpx.AsyncClient(timeout=4.0) as client:
                    headers = {
                        "apikey": self.supabase_key,
                        "Authorization": f"Bearer {self.supabase_key}",
                        "Content-Type": "application/json",
                        "Prefer": "return=minimal"
                    }
                    payload = {
                        "id": scan_id,
                        "submitted_url": submitted_url,
                        "normalized_url": normalized_url,
                        "classification": classification,
                        "risk_score": risk_score,
                        "confidence": confidence,
                        "model_version": model_version,
                        "features_json": json.dumps(features),
                        "reasons_json": json.dumps(reasons),
                        "created_at": now
                    }
                    resp = await client.post(f"{self.supabase_url}/rest/v1/scans", json=payload, headers=headers)
                    if resp.status_code in (200, 201):
                        return scan_id
            except Exception:
                # Fallback to local SQLite on network / config error
                pass

        # Local SQLite persistence
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO scans (id, submitted_url, normalized_url, classification, risk_score, confidence, model_version, features_json, reasons_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    submitted_url,
                    normalized_url,
                    classification,
                    risk_score,
                    confidence,
                    model_version,
                    json.dumps(features),
                    json.dumps(reasons),
                    now
                )
            )
            conn.commit()

        return scan_id

    async def get_recent_scans(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Retrieves most recent scan records."""
        if self.use_supabase:
            try:
                async with httpx.AsyncClient(timeout=4.0) as client:
                    headers = {
                        "apikey": self.supabase_key,
                        "Authorization": f"Bearer {self.supabase_key}",
                    }
                    resp = await client.get(
                        f"{self.supabase_url}/rest/v1/scans?select=*&order=created_at.desc&limit={limit}",
                        headers=headers
                    )
                    if resp.status_code == 200:
                        records = resp.json()
                        for r in records:
                            if isinstance(r.get("reasons_json"), str):
                                try:
                                    r["reasons"] = json.loads(r["reasons_json"])
                                except Exception:
                                    r["reasons"] = []
                        return records
            except Exception:
                pass

        # Query local SQLite
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, submitted_url, normalized_url, classification, risk_score, confidence, model_version, reasons_json, created_at FROM scans ORDER BY created_at DESC LIMIT ?",
                (limit,)
            )
            rows = cursor.fetchall()
            results = []
            for row in rows:
                d = dict(row)
                try:
                    d["reasons"] = json.loads(d["reasons_json"]) if d["reasons_json"] else []
                except Exception:
                    d["reasons"] = []
                d.pop("reasons_json", None)
                results.append(d)
            return results
