"""
src/aegis/core/config.py — Centralized, Type-Safe Configuration for Project Aegis.
Gracefully supports pydantic-settings if installed, with a robust pydantic.BaseModel fallback.
"""
import os
from typing import Optional, List
from dotenv import load_dotenv
from pydantic import Field, BaseModel

load_dotenv()

try:
    from pydantic_settings import BaseSettings, SettingsConfigDict
    _HAS_PYDANTIC_SETTINGS = True
except ImportError:
    BaseSettings = BaseModel
    SettingsConfigDict = None
    _HAS_PYDANTIC_SETTINGS = False


class Settings(BaseSettings):
    # LLM Settings
    OPENAI_API_KEY: Optional[str] = Field(default_factory=lambda: os.getenv("OPENAI_API_KEY"))
    OPENAI_BASE_URL: Optional[str] = Field(default_factory=lambda: os.getenv("OPENAI_BASE_URL") or os.getenv("OPENAI_API_BASE"))
    OPENAI_MODEL: str = Field(default_factory=lambda: os.getenv("OPENAI_MODEL", "gpt-4o-mini"))
    GROQ_API_KEY: Optional[str] = Field(default_factory=lambda: os.getenv("GROQ_API_KEY"))
    DEEPSEEK_API_KEY: Optional[str] = Field(default_factory=lambda: os.getenv("DEEPSEEK_API_KEY"))

    # Redis & Job Queue
    REDIS_URL: str = Field(default_factory=lambda: os.getenv("REDIS_URL", "redis://localhost:6379/0"))
    AEGIS_JOB_TIMEOUT_S: int = Field(default_factory=lambda: int(os.getenv("AEGIS_JOB_TIMEOUT_S", "1800")))
    AEGIS_WORKER_CONCURRENCY: int = Field(default_factory=lambda: int(os.getenv("AEGIS_WORKER_CONCURRENCY", "3")))
    AEGIS_MAX_CONCURRENT_AUDITS: int = Field(default_factory=lambda: int(os.getenv("AEGIS_MAX_CONCURRENT_AUDITS", "5")))
    AEGIS_RATE_LIMIT_RPM: int = Field(default_factory=lambda: int(os.getenv("AEGIS_RATE_LIMIT_RPM", "10")))
    AEGIS_CACHE_TTL: int = Field(default_factory=lambda: int(os.getenv("AEGIS_CACHE_TTL", "3600")))
    AEGIS_API_KEY: Optional[str] = Field(default_factory=lambda: os.getenv("AEGIS_API_KEY"))

    # Alerting
    ALERT_WEBHOOK_URL: Optional[str] = Field(default_factory=lambda: os.getenv("ALERT_WEBHOOK_URL"))

    # Scope & Security Bounds
    ALLOW_LOCAL_TARGETS: bool = Field(default_factory=lambda: os.getenv("ALLOW_LOCAL_TARGETS", "true").lower() in ("true", "1", "yes"))
    ALLOW_ALL_TARGETS: bool = Field(default_factory=lambda: os.getenv("ALLOW_ALL_TARGETS", "true").lower() in ("true", "1", "yes"))
    ALLOWED_SANDBOX_SUFFIXES: str = Field(
        default_factory=lambda: os.getenv("ALLOWED_SANDBOX_SUFFIXES", ".sandbox.internal,.staging.internal,localhost,127.0.0.1")
    )

    # Cloud Deployment Platform Integrations
    AEGIS_DEPLOY_PLATFORM: Optional[str] = Field(default_factory=lambda: os.getenv("AEGIS_DEPLOY_PLATFORM"))
    VERCEL_DEPLOY_HOOK: Optional[str] = Field(default_factory=lambda: os.getenv("VERCEL_DEPLOY_HOOK"))
    RENDER_SERVICE_ID: Optional[str] = Field(default_factory=lambda: os.getenv("RENDER_SERVICE_ID"))
    RENDER_API_KEY: Optional[str] = Field(default_factory=lambda: os.getenv("RENDER_API_KEY"))
    RAILWAY_SERVICE_ID: Optional[str] = Field(default_factory=lambda: os.getenv("RAILWAY_SERVICE_ID"))
    RAILWAY_TOKEN: Optional[str] = Field(default_factory=lambda: os.getenv("RAILWAY_TOKEN"))
    AWS_ECS_CLUSTER: Optional[str] = Field(default_factory=lambda: os.getenv("AWS_ECS_CLUSTER"))
    AWS_ECS_SERVICE: Optional[str] = Field(default_factory=lambda: os.getenv("AWS_ECS_SERVICE"))

    # Server / API
    CORS_ALLOWED_ORIGINS: str = Field(default_factory=lambda: os.getenv("CORS_ALLOWED_ORIGINS", "http://localhost:3000"))
    TARGET_URL: str = Field(default_factory=lambda: os.getenv("TARGET_URL", "http://localhost:8000"))

    if _HAS_PYDANTIC_SETTINGS:
        model_config = SettingsConfigDict(
            env_file=".env",
            env_file_encoding="utf-8",
            extra="ignore"
        )

    @property
    def cors_origins_list(self) -> List[str]:
        return [o.strip() for o in self.CORS_ALLOWED_ORIGINS.split(",") if o.strip()]

    def get_effective_api_key(self) -> str:
        key = self.OPENAI_API_KEY or self.GROQ_API_KEY or self.DEEPSEEK_API_KEY
        if not key:
            if self.OPENAI_BASE_URL and ("localhost" in self.OPENAI_BASE_URL or "127.0.0.1" in self.OPENAI_BASE_URL):
                return "ollama"
            raise ValueError("Missing LLM API Key! Please set OPENAI_API_KEY in your .env file.")
        return key


settings = Settings()
