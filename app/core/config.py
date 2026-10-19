"""Centralized Pydantic v2 configuration for the Neural Zero-Trust AI Firewall & Red-Team Arena."""

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Type-safe configuration across PyTorch, Pinecone, AST Sandbox, CrewAI, and DSPy."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # --- Application & API ---
    APP_NAME: str = "Neural Zero-Trust AI Firewall & Red-Team Arena"
    APP_VERSION: str = "1.0.0"
    APP_ENV: Literal["development", "staging", "production", "testing"] = "development"
    DEBUG: bool = False
    API_V1_PREFIX: str = "/api/v1"
    LOG_LEVEL: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    # --- Async Database ---
    DATABASE_URL: str = "sqlite+aiosqlite:///./zero_trust_firewall.db"

    # --- PyTorch Self-Attention & Shannon Entropy Guard ---
    PYTORCH_EMBED_DIM: int = 64
    PYTORCH_ATTENTION_HEADS: int = 4
    NEURAL_THREAT_THRESHOLD: float = 0.62
    SHANNON_ENTROPY_THRESHOLD: float = 4.35

    # --- Pinecone Vector Threat Store ---
    PINECONE_API_KEY: str = ""
    PINECONE_INDEX_NAME: str = "owasp-llm-threat-signatures"
    PINECONE_SIMILARITY_THRESHOLD: float = 0.72

    # --- Python AST Formal Sandbox & DSPy Compiler ---
    MAX_AST_COMPLEXITY_SCORE: int = 15
    AST_MAX_COMPLEXITY: int = 15
    DSPY_BOOTSTRAP_ROUNDS: int = 3


@lru_cache
def get_settings() -> Settings:
    """Return cached singleton instance of application settings."""
    return Settings()


settings = get_settings()