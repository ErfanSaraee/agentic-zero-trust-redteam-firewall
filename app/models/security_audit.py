"""SQLAlchemy 2.0 ORM models for Zero-Trust firewall audits and CrewAI vs. DSPy Red-Team campaigns."""

import enum
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Enum, Float, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class ThreatVerdict(str, enum.Enum):
    """Final Zero-Trust gateway enforcement decision."""

    SAFE_ALLOWED = "SAFE_ALLOWED"
    SANITIZED_PII = "SANITIZED_PII"
    BLOCKED_INJECTION = "BLOCKED_INJECTION"
    BLOCKED_AST_VIOLATION = "BLOCKED_AST_VIOLATION"


class OWASPCategory(str, enum.Enum):
    """Standardized OWASP Top-10 for LLM & Agentic Applications categories."""

    LLM01_PROMPT_INJECTION = "LLM01: Prompt Injection & Jailbreak"
    LLM02_SENSITIVE_INFO_DISCLOSURE = "LLM02: Sensitive PII & Secret Disclosure"
    LLM05_IMPROPER_OUTPUT_HANDLING = "LLM05: Unsafe Code Execution (AST RCE)"
    LLM07_SYSTEM_PROMPT_LEAKAGE = "LLM07: System Prompt Extraction"
    LLM08_VECTOR_AND_MCP_POISONING = "LLM08: Vector & MCP Tool Poisoning"
    NONE = "NONE (Benign Traffic)"


class FirewallAuditLog(Base):
    """Persists every prompt & code inspection across PyTorch, Pinecone, Entropy, and AST layers."""

    __tablename__ = "firewall_audit_logs"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    prompt_preview: Mapped[str] = mapped_column(Text, nullable=False)
    sanitized_prompt: Mapped[str] = mapped_column(Text, nullable=False)
    verdict: Mapped[ThreatVerdict] = mapped_column(
        Enum(ThreatVerdict), nullable=False, index=True
    )
    owasp_category: Mapped[OWASPCategory] = mapped_column(
        Enum(OWASPCategory), nullable=False, index=True
    )
    composite_risk_score: Mapped[float] = mapped_column(Float, nullable=False)

    # Layer 1: PyTorch Self-Attention Neural Guard & Shannon Entropy
    pytorch_threat_prob: Mapped[float] = mapped_column(Float, nullable=False)
    shannon_entropy: Mapped[float] = mapped_column(Float, nullable=False)
    attention_top_tokens: Mapped[dict[str, float]
                                 ] = mapped_column(JSON, nullable=False)

    # Layer 2: Pinecone Vector Threat Intelligence
    pinecone_max_similarity: Mapped[float] = mapped_column(
        Float, nullable=False)
    matched_signature_id: Mapped[str] = mapped_column(
        String(80), nullable=False)

    # Layer 3: PII Redaction & Python AST Formal Sandbox
    pii_redacted_count: Mapped[int] = mapped_column(
        Integer, default=0, nullable=False)
    ast_is_safe: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False)
    ast_violations: Mapped[list[str]] = mapped_column(
        JSON, default=list, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class RedTeamCampaignRecord(Base):
    """Stores autonomous CrewAI adversarial campaigns and DSPy self-hardened prompt artifacts."""

    __tablename__ = "redteam_campaign_records"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    campaign_name: Mapped[str] = mapped_column(String(120), nullable=False)
    total_attacks: Mapped[int] = mapped_column(Integer, nullable=False)
    blocked_attacks: Mapped[int] = mapped_column(Integer, nullable=False)
    defense_success_rate: Mapped[float] = mapped_column(Float, nullable=False)

    # DSPy Self-Hardening Prompt Compiler Artifacts
    initial_system_prompt: Mapped[str] = mapped_column(Text, nullable=False)
    dspy_compiled_prompt: Mapped[str] = mapped_column(Text, nullable=False)

    # Telemetry & Radar Breakdown
    owasp_radar_scores: Mapped[dict[str, float]
                               ] = mapped_column(JSON, nullable=False)
    attack_results_log: Mapped[list[dict[str, Any]]
                               ] = mapped_column(JSON, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
