"""
Backend Application Settings and Configuration.
"""

from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = "PhishGuard Detection API"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    HOST: str = "127.0.0.1"
    PORT: int = 8000
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:3001",
        "http://127.0.0.1:3001",
    ]

    ENABLE_HTML_INSPECTION: bool = True
    HTTP_TIMEOUT_SECONDS: float = 4.0
    MAX_RESPONSE_SIZE_BYTES: int = 512 * 1024

    SUPABASE_URL: str = ""
    SUPABASE_KEY: str = ""

    GOOGLE_SAFE_BROWSING_API_KEY: str = ""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


settings = Settings()
