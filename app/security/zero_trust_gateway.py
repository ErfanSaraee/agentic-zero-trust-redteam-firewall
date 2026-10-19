"""Unified Zero-Trust AI Firewall orchestrating PyTorch Neural Guard, Pinecone, PII Redaction, and AST Sandbox."""

from datetime import datetime, timezone
import uuid

from app.core.config import settings
from app.core.logging import get_logger
from app.models.security_audit import OWASPCategory, ThreatVerdict
from app.schemas.security import FirewallInspectRequest, FirewallInspectResponse
from app.security.ast_sandbox import ast_security_sandbox
from app.security.pinecone_threat_store import pinecone_threat_store
from app.security.pytorch_neural_guard import pytorch_neural_guard

logger = get_logger(__name__)


class ZeroTrustSecurityGateway:
    """Executes multi-layer inspection across PyTorch Self-Attention, Pinecone vectors, and Python AST."""

    def inspect(
        self,
        request: FirewallInspectRequest,
        audit_id: str | None = None,
    ) -> FirewallInspectResponse:
        """Inspect incoming prompt and optional generated code against all Zero-Trust layers."""
        sanitized_prompt, pii_entities = pytorch_neural_guard.redact_pii_and_secrets(
            request.prompt)
        pytorch_analysis, _ = pytorch_neural_guard.analyze(request.prompt)
        pinecone_match = pinecone_threat_store.query_threat_signature(
            prompt=request.prompt,
            generated_code=request.generated_code,
        )
        ast_result = ast_security_sandbox.verify_code(request.generated_code)

        # Compute composite risk score in [0.0, 1.0]
        ast_penalty = 0.95 if (
            ast_result.code_provided and not ast_result.is_safe) else 0.0
        pii_penalty = 0.55 if len(pii_entities) > 0 else 0.0
        obfuscation_penalty = 0.72 if pytorch_analysis.is_obfuscated_payload else 0.0

        composite_risk = max(
            pytorch_analysis.threat_probability,
            pinecone_match.cosine_similarity * 0.92,
            ast_penalty,
            pii_penalty,
            obfuscation_penalty,
        )
        composite_risk = round(min(max(composite_risk, 0.0), 1.0), 4)

        # Determine final enforcement verdict & OWASP category
        if ast_result.code_provided and not ast_result.is_safe:
            verdict = ThreatVerdict.BLOCKED_AST_VIOLATION
            owasp_cat = OWASPCategory.LLM05_IMPROPER_OUTPUT_HANDLING
        elif (
            composite_risk >= settings.NEURAL_THREAT_THRESHOLD
            or pinecone_match.is_vector_hit
            or pytorch_analysis.is_obfuscated_payload
        ):
            verdict = ThreatVerdict.BLOCKED_INJECTION
            if pinecone_match.owasp_category != OWASPCategory.NONE:
                owasp_cat = pinecone_match.owasp_category
            elif "prompt" in request.prompt.lower() and "reveal" in request.prompt.lower():
                owasp_cat = OWASPCategory.LLM07_SYSTEM_PROMPT_LEAKAGE
            else:
                owasp_cat = OWASPCategory.LLM01_PROMPT_INJECTION
        elif len(pii_entities) > 0:
            verdict = ThreatVerdict.SANITIZED_PII
            owasp_cat = OWASPCategory.LLM02_SENSITIVE_INFO_DISCLOSURE
        else:
            verdict = ThreatVerdict.SAFE_ALLOWED
            owasp_cat = OWASPCategory.NONE

        return FirewallInspectResponse(
            audit_id=audit_id or str(uuid.uuid4()),
            verdict=verdict,
            owasp_category=owasp_cat,
            composite_risk_score=composite_risk,
            sanitized_prompt=sanitized_prompt,
            pii_redacted_entities=pii_entities,
            pytorch_analysis=pytorch_analysis,
            pinecone_match=pinecone_match,
            ast_verification=ast_result,
            inspected_at=datetime.now(timezone.utc),
        )


zero_trust_gateway = ZeroTrustSecurityGateway()
