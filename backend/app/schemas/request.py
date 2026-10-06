"""
Pydantic API Request Schemas.
"""

from pydantic import BaseModel, Field


class AnalyzeUrlRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048, description="Target website URL to analyze for phishing threats.")
    inspect_html: bool = Field(default=True, description="Whether to safely inspect HTML metadata with SSRF protection.")
