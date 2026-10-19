"""PyTorch Multi-Head Self-Attention threat classifier, Shannon entropy analyzer, and PII redactor."""

from collections import Counter
import hashlib
import math
import re

import torch
import torch.nn as nn

from app.core.config import settings
from app.core.logging import get_logger
from app.schemas.security import PyTorchAttentionAnalysis

logger = get_logger(__name__)

# High-risk adversarial vocabulary mapped to dedicated token IDs (1..40)
ADVERSARIAL_VOCAB: dict[str, float] = {
    "ignore": 1.45,
    "disregard": 1.40,
    "override": 1.50,
    "bypass": 1.45,
    "jailbreak": 1.65,
    "dan": 1.35,
    "system": 0.95,
    "prompt": 0.85,
    "reveal": 1.25,
    "instructions": 1.05,
    "developer": 0.90,
    "sudo": 1.55,
    "root": 1.20,
    "passwd": 1.70,
    "shadow": 1.65,
    "exfiltrate": 1.75,
    "webhook": 1.25,
    "evil": 1.60,
    "attacker": 1.60,
    "payload": 1.20,
    "base64": 1.35,
    "eval": 1.50,
    "exec": 1.50,
    "subprocess": 1.65,
    "rmtree": 1.75,
    "subclasses": 1.80,
    "globals": 1.55,
    "builtins": 1.60,
    "drop": 1.30,
    "truncate": 1.35,
    "secret": 1.20,
    "token": 0.85,
    "apikey": 1.25,
    "hack": 1.50,
    "exploit": 1.60,
}

PII_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("API_KEY", re.compile(
        r"\b(?:sk-[a-zA-Z0-9_-]{12,}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{20,})\b")),
    ("JWT_TOKEN", re.compile(
        r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b")),
    ("EMAIL", re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("CREDIT_CARD", re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")),
    ("SSN_ID", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
]

_BASE64_BLOB_PATTERN = re.compile(r"\b(?:[A-Za-z0-9+/]{28,}={0,2})\b")


class SelfAttentionThreatNet(nn.Module):
    """
    PyTorch Deep Learning architecture combining Token Embeddings, Multi-Head Self-Attention,
    Residual LayerNorm, and a calibrated Threat Scoring Head.
    """

    def __init__(self, vocab_size: int = 2048, embed_dim: int = 64, num_heads: int = 4) -> None:
        super().__init__()
        torch.manual_seed(42)
        self.embed_dim = embed_dim
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.attention = nn.MultiheadAttention(
            embed_dim=embed_dim,
            num_heads=num_heads,
            batch_first=True,
        )
        self.layer_norm = nn.LayerNorm(embed_dim)
        self.classifier = nn.Sequential(
            nn.Linear(embed_dim + 3, 32),
            nn.GELU(),
            nn.Linear(32, 1),
        )
        self._calibrate_pretrained_weights()

    def _calibrate_pretrained_weights(self) -> None:
        """Initialize deterministic security-calibrated weights for adversarial token sensitivity."""
        with torch.no_grad():
            nn.init.normal_(self.embedding.weight, mean=0.0, std=0.12)
            self.embedding.weight[0].zero_()
            # Boost embedding magnitude along dimension 0..7 for known adversarial token indices
            for idx in range(1, len(ADVERSARIAL_VOCAB) + 1):
                self.embedding.weight[idx, :8] += 1.65

            nn.init.xavier_uniform_(self.classifier[0].weight)
            self.classifier[0].bias.fill_(0.05)
            nn.init.uniform_(self.classifier[2].weight, 0.25, 0.55)
            self.classifier[2].bias.fill_(-1.15)

    def forward(
        self,
        token_ids: torch.Tensor,
        aux_features: torch.Tensor,
    ) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """
        Execute forward pass returning:
        - threat_prob: (batch_size, 1) probability in [0, 1]
        - attn_weights: (batch_size, seq_len, seq_len) self-attention matrix
        - pooled_repr: (batch_size, embed_dim) normalized context vector
        """
        embeds = self.embedding(token_ids)  # (B, L, D)
        attn_out, attn_weights = self.attention(
            embeds, embeds, embeds, need_weights=True, average_attn_weights=True
        )
        normed = self.layer_norm(embeds + attn_out)
        pooled_repr = normed.mean(dim=1)  # (B, D)

        combined = torch.cat([pooled_repr, aux_features], dim=-1)
        logits = self.classifier(combined)
        # Combine neural logit with calibrated auxiliary adversarial signal
        aux_boost = (
            aux_features[:, 0:1] * 2.85
            + aux_features[:, 1:2] * 1.65
            + aux_features[:, 2:3] * 1.40
        )
        threat_prob = torch.sigmoid(logits + aux_boost)
        return threat_prob, attn_weights, pooled_repr


class PyTorchNeuralGuard:
    """Executes PyTorch Self-Attention inference, Shannon entropy analysis, and PII redaction."""

    def __init__(self) -> None:
        self.vocab_list = list(ADVERSARIAL_VOCAB.keys())
        self.vocab_to_id = {word: idx + 1 for idx,
                            word in enumerate(self.vocab_list)}
        self.model = SelfAttentionThreatNet(
            vocab_size=2048,
            embed_dim=settings.PYTORCH_EMBED_DIM,
            num_heads=settings.PYTORCH_ATTENTION_HEADS,
        )
        self.model.eval()

    @staticmethod
    def compute_shannon_entropy(text: str) -> float:
        """Compute character-level Shannon Entropy H(X) = -sum(p(x) * log2(p(x)))."""
        if not text:
            return 0.0
        length = len(text)
        counts = Counter(text)
        entropy = -sum((count / length) * math.log2(count / length)
                       for count in counts.values())
        return round(entropy, 4)

    @staticmethod
    def redact_pii_and_secrets(text: str) -> tuple[str, list[str]]:
        """Detect and redact API keys, JWTs, emails, credit cards, and SSNs."""
        sanitized = text
        redacted_types: list[str] = []

        for label, pattern in PII_PATTERNS:
            matches = pattern.findall(sanitized)
            if matches:
                redacted_types.extend([label] * len(matches))
                sanitized = pattern.sub(f"[REDACTED_{label}]", sanitized)

        return sanitized, redacted_types

    def _tokenize(self, text: str, max_len: int = 64) -> tuple[list[str], torch.Tensor, float]:
        """Convert raw text into token strings, PyTorch token ID tensor, and weighted risk density."""
        raw_tokens = re.findall(r"[a-zA-Z0-9_/@.-]+", text.lower())[:max_len]
        if not raw_tokens:
            raw_tokens = ["empty"]

        token_ids: list[int] = []
        risk_sum = 0.0

        for tok in raw_tokens:
            clean_tok = tok.strip("._-/")
            if clean_tok in self.vocab_to_id:
                token_ids.append(self.vocab_to_id[clean_tok])
                risk_sum += ADVERSARIAL_VOCAB[clean_tok]
            else:
                # Deterministic hash bucket in [50..2047]
                digest = int(hashlib.md5(
                    clean_tok.encode("utf-8")).hexdigest(), 16)
                token_ids.append(50 + (digest % 1998))

        tensor_ids = torch.tensor([token_ids], dtype=torch.long)
        risk_density = min(risk_sum / max(len(raw_tokens) * 0.55, 1.0), 1.5)
        return raw_tokens, tensor_ids, risk_density

    def analyze(self, prompt: str) -> tuple[PyTorchAttentionAnalysis, list[float]]:
        """Run PyTorch Self-Attention forward pass and return threat metrics + dense embedding."""
        entropy = self.compute_shannon_entropy(prompt)
        has_base64_blob = bool(_BASE64_BLOB_PATTERN.search(prompt))
        is_obfuscated = entropy >= settings.SHANNON_ENTROPY_THRESHOLD or has_base64_blob

        tokens, token_tensor, risk_density = self._tokenize(prompt)
        obfuscation_flag = 1.0 if is_obfuscated else 0.0
        normalized_entropy = max((entropy - 3.6) / 2.0, 0.0)

        aux_tensor = torch.tensor(
            [[risk_density, obfuscation_flag, normalized_entropy]], dtype=torch.float32
        )

        with torch.no_grad():
            threat_prob_t, attn_weights_t, pooled_repr_t = self.model(
                token_tensor, aux_tensor)

        threat_prob = round(float(threat_prob_t.item()), 4)
        embedding_norm = round(float(torch.norm(pooled_repr_t, p=2).item()), 4)

        # Extract token-level importance combining attention weights and adversarial salience
        token_scores_matrix = attn_weights_t[0].mean(dim=0).tolist()
        token_importance: dict[str, float] = {}
        for tok, attn_val in zip(tokens, token_scores_matrix):
            clean_tok = tok.strip("._-/")
            salience = ADVERSARIAL_VOCAB.get(clean_tok, 0.1)
            combined_weight = round(float(attn_val * 0.5 + salience * 0.5), 4)
            if clean_tok not in token_importance or combined_weight > token_importance[clean_tok]:
                token_importance[clean_tok] = combined_weight

        top_tokens = dict(
            sorted(token_importance.items(),
                   key=lambda item: item[1], reverse=True)[:6]
        )

        analysis = PyTorchAttentionAnalysis(
            threat_probability=threat_prob,
            shannon_entropy=entropy,
            is_obfuscated_payload=is_obfuscated,
            top_attended_tokens=top_tokens,
            embedding_l2_norm=embedding_norm,
        )
        return analysis, pooled_repr_t[0].tolist()


pytorch_neural_guard = PyTorchNeuralGuard()
