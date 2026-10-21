import os
from pathlib import Path
from typing import List, Set
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, field_validator


class Settings(BaseSettings):
    """
    Centralized configuration management using Pydantic Settings.
    Loads values from environment variables or .env file with type validation.
    """
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )

    # Project metadata
    PROJECT_NAME: str = "Cybersecurity GRC & Compliance Management Platform"
    PROJECT_VERSION: str = "0.1.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    API_V1_STR: str = "/api/v1"

    # Base Paths
    BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent
    APP_DIR: Path = Path(__file__).resolve().parent.parent
    TEMPLATES_DIR: Path = Path(__file__).resolve().parent.parent / "templates"
    STATIC_DIR: Path = Path(__file__).resolve().parent.parent / "static"

    # Cryptography & Authentication
    SECRET_KEY: str = Field(
        default="grc-dev-secret-key-32-character-token-for-local-demo",
        description="Cryptographic secret key for signing session tokens and JWTs"
    )
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # Database Configuration
    DATABASE_URL: str = Field(
        default="sqlite:///./grc_platform.db",
        description="SQLAlchemy database connection URI (supports SQLite or PostgreSQL)"
    )

    # Secure Evidence File Storage
    UPLOAD_DIR: str = "./uploads"
    MAX_UPLOAD_SIZE_MB: int = 10
    ALLOWED_EXTENSIONS: str = "pdf,png,jpg,jpeg,docx,xlsx,csv,txt"

    # Session & Cookie Security
    COOKIE_NAME: str = "grc_session"
    COOKIE_SECURE: bool = False  # Set to True in production with HTTPS
    COOKIE_HTTPONLY: bool = True
    COOKIE_SAMESITE: str = "lax"  # "lax", "strict", or "none"

    # Rate Limiting
    RATE_LIMIT_LOGIN_PER_MINUTE: int = 5

    @property
    def max_upload_size_bytes(self) -> int:
        return self.MAX_UPLOAD_SIZE_MB * 1024 * 1024

    @property
    def allowed_extensions_set(self) -> Set[str]:
        return {ext.strip().lower().lstrip(".") for ext in self.ALLOWED_EXTENSIONS.split(",") if ext.strip()}

    @property
    def is_sqlite(self) -> bool:
        return self.DATABASE_URL.startswith("sqlite")

    @property
    def resolved_upload_dir(self) -> Path:
        p = Path(self.UPLOAD_DIR)
        if not p.is_absolute():
            p = self.BASE_DIR / p
        p.mkdir(parents=True, exist_ok=True)
        return p


settings = Settings()
