"""Centralized Pydantic v2 configuration for PyTorch Neural Guard, Pinecone, DSPy, CrewAI, and AST Sandbox."""

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Validated security arena settings loaded from environment variables or .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- Application ---
    APP_NAME: str = "Neural Zero-Trust AI Firewall & Red-Team Arena"
    APP_VERSION: str = "1.0.0"
    APP_ENV: Literal["development", "staging",
                     "production", "testing"] = "development"
    DEBUG: bool = False
    API_V1_PREFIX: str = "/api/v1"
    LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    # --- Database ---
    DATABASE_URL: str = "sqlite+aiosqlite:///./zero_trust_arena.db"

    # --- PyTorch Self-Attention Threat Model & Entropy Thresholds ---
    PYTORCH_EMBED_DIM: int = 64
    PYTORCH_ATTENTION_HEADS: int = 4
    NEURAL_THREAT_THRESHOLD: float = 0.62
    SHANNON_ENTROPY_THRESHOLD: float = 4.35
    ENABLE_AUTO_PII_REDACTION: bool = True

    # --- Pinecone Vector Threat Intelligence ---
    PINECONE_API_KEY: str = ""
    PINECONE_INDEX_NAME: str = "owasp-llm-threat-signatures"
    PINECONE_SIMILARITY_THRESHOLD: float = 0.72

    # --- DSPy & CrewAI Self-Hardening ---
    DSPY_BOOTSTRAP_ROUNDS: int = 3


@lru_cache
def get_settings() -> Settings:
    """Return cached application settings singleton."""
    return Settings()


settings = get_settings()
