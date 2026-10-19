"""FastAPI v1 endpoints for Zero-Trust PyTorch/Pinecone/AST inspection and CrewAI vs. DSPy Red-Teaming."""

from typing import Any
import uuid

from fastapi import APIRouter, Body, Depends, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.redteam_arena import redteam_arena
from app.core.logging import get_logger
from app.db.session import get_db_session
from app.models.security_audit import (
    FirewallAuditLog,
    RedTeamCampaignRecord,
    ThreatVerdict,
)
from app.schemas.security import (
    ASTVerificationResult,
    FirewallInspectRequest,
    FirewallInspectResponse,
    RedTeamCampaignResponse,
)
from app.security.ast_sandbox import ast_security_sandbox
from app.security.zero_trust_gateway import zero_trust_gateway

logger = get_logger(__name__)
router = APIRouter()


@router.post(
    "/firewall/inspect",
    response_model=FirewallInspectResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Inspect prompt and generated code via PyTorch Self-Attention, Pinecone, and AST Sandbox",
)
async def inspect_payload(
    payload: FirewallInspectRequest,
    session: AsyncSession = Depends(get_db_session),
) -> FirewallInspectResponse:
    """Execute multi-layer Zero-Trust inspection and persist audit telemetry."""
    audit_id = str(uuid.uuid4())
    decision = zero_trust_gateway.inspect(request=payload, audit_id=audit_id)

    log_entry = FirewallAuditLog(
        id=audit_id,
        prompt_preview=payload.prompt[:250],
        sanitized_prompt=decision.sanitized_prompt[:250],
        verdict=decision.verdict,
        owasp_category=decision.owasp_category,
        composite_risk_score=decision.composite_risk_score,
        pytorch_threat_prob=decision.pytorch_analysis.threat_probability,
        shannon_entropy=decision.pytorch_analysis.shannon_entropy,
        attention_top_tokens=decision.pytorch_analysis.top_attended_tokens,
        pinecone_max_similarity=decision.pinecone_match.cosine_similarity,
        matched_signature_id=decision.pinecone_match.matched_signature_id,
        pii_redacted_count=len(decision.pii_redacted_entities),
        ast_is_safe=decision.ast_verification.is_safe,
        ast_violations=decision.ast_verification.violations,
    )
    session.add(log_entry)
    await session.commit()
    return decision


@router.post(
    "/sandbox/verify-ast",
    response_model=ASTVerificationResult,
    summary="Statically verify Python code in the formal Abstract Syntax Tree (AST) sandbox",
)
async def verify_python_code_ast(
    code: str = Body(..., embed=True,
                     description="Python source code snippet to verify."),
) -> ASTVerificationResult:
    """Parse and inspect Python AST nodes for forbidden imports, dunder escapes, and infinite loops."""
    return ast_security_sandbox.verify_code(code)


@router.post(
    "/redteam/campaign",
    response_model=RedTeamCampaignResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Execute autonomous CrewAI Red-Team campaign and compile DSPy hardened system prompt",
)
async def run_redteam_arena_campaign(
    initial_system_prompt: str = Body(
        default="You are an enterprise AI assistant with access to internal MCP tools and Python execution.",
        embed=True,
    ),
    session: AsyncSession = Depends(get_db_session),
) -> RedTeamCampaignResponse:
    """Run all 6 CrewAI adversarial agents, compute OWASP resilience scores, and compile DSPy prompt."""
    campaign = redteam_arena.run_campaign(
        initial_system_prompt=initial_system_prompt)

    record = RedTeamCampaignRecord(
        id=campaign.campaign_id,
        campaign_name=campaign.campaign_name,
        total_attacks=campaign.total_attacks,
        blocked_attacks=campaign.blocked_attacks,
        defense_success_rate=campaign.defense_success_rate,
        initial_system_prompt=campaign.dspy_compilation.original_system_prompt,
        dspy_compiled_prompt=campaign.dspy_compilation.compiled_hardened_prompt,
        owasp_radar_scores=campaign.owasp_radar_scores,
        attack_results_log=[item.model_dump(
            mode="json") for item in campaign.attack_results],
    )
    session.add(record)
    await session.commit()
    return campaign


@router.get(
    "/telemetry/summary",
    summary="Retrieve aggregated Zero-Trust firewall audit statistics",
)
async def get_security_telemetry_summary(
    session: AsyncSession = Depends(get_db_session),
) -> dict[str, Any]:
    """Return total inspected payloads, blocked count, and recent audit logs."""
    stmt = select(FirewallAuditLog).order_by(
        FirewallAuditLog.created_at.desc())
    result = await session.execute(stmt)
    logs = list(result.scalars().all())

    blocked = sum(
        1
        for row in logs
        if row.verdict in {ThreatVerdict.BLOCKED_INJECTION, ThreatVerdict.BLOCKED_AST_VIOLATION}
    )
    pii_sanitized = sum(1 for row in logs if row.pii_redacted_count > 0)

    return {
        "total_inspected": len(logs),
        "total_blocked": blocked,
        "total_pii_sanitized": pii_sanitized,
        "recent_audits": [
            {
                "id": row.id[:8],
                "verdict": row.verdict.value,
                "owasp_category": row.owasp_category.value,
                "risk_score": row.composite_risk_score,
                "pytorch_prob": row.pytorch_threat_prob,
                "pinecone_sim": row.pinecone_max_similarity,
                "ast_safe": row.ast_is_safe,
            }
            for row in logs[:10]
        ],
    }
