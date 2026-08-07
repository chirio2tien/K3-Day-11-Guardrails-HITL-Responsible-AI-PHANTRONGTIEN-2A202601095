"""
OWASP Top 10 for LLM Applications (2025) — lab controls.

Maps each LLM0x risk to a deterministic helper used by the VinBank pipeline.
Reference: https://owasp.org/www-project-top-10-for-large-language-model-applications/
"""
from __future__ import annotations

import base64
import binascii
import json
import re
from pathlib import Path

from agents.security_boundary import (
    ExternalContent,
    assess_external_content,
    contains_secret,
    normalize_for_security,
)

# ---------------------------------------------------------------------------
# LLM10 — Unbounded Consumption
# ---------------------------------------------------------------------------
MAX_INPUT_CHARS = 2000
MAX_OUTPUT_CHARS = 4000

# ---------------------------------------------------------------------------
# LLM03 — Supply Chain: only these top-level packages are expected
# ---------------------------------------------------------------------------
ALLOWED_REQUIREMENT_PACKAGES = frozenset({
    "google-genai",
    "google-adk",
    "nemoguardrails",
    "langchain-google-genai",
    "pytest",
    "jsonschema",
    "python-dotenv",
})

# ---------------------------------------------------------------------------
# LLM07 — System Prompt Leakage markers (instruction / policy disclosure)
# ---------------------------------------------------------------------------
_PROMPT_LEAK_PATTERNS = (
    r"you\s+are\s+a\s+helpful\s+customer\s+service\s+assistant\s+for\s+vinbank",
    r"internal\s+note\s*:",
    r"never\s+reveal\s+internal\s+system\s+details",
    r"system\s+(?:prompt|instruction)\s*(?:is|=|:)",
    r"my\s+(?:system\s+)?(?:prompt|instructions?)\s*(?:is|=|:|says)",
)

# ---------------------------------------------------------------------------
# LLM05 — Improper Output Handling (unsafe markup / script sinks)
# ---------------------------------------------------------------------------
_UNSAFE_OUTPUT_PATTERNS = (
    r"<script\b",
    r"javascript\s*:",
    r"on\w+\s*=\s*['\"]",
    r"data:text/html",
)

# ---------------------------------------------------------------------------
# LLM09 — Misinformation: known false numeric claims vs lab ground truth
# ---------------------------------------------------------------------------
_FALSE_RATE_CLAIMS = (
    (r"5\.5\s*%", "savings_12m_false_5.5"),
    (r"savings[^\n.]{0,40}0\s*%", "savings_zero_false"),
)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def load_ground_truth() -> dict:
    """Load lab ground truth used for LLM09 misinformation checks."""
    path = _repo_root() / "data" / "pii_hallucination_samples.json"
    with path.open(encoding="utf-8") as f:
        return json.load(f).get("ground_truth", {})


# ===== LLM10 ===============================================================

def exceeds_input_budget(text: str, limit: int = MAX_INPUT_CHARS) -> bool:
    """True if the request is too large (resource / cost amplification)."""
    return len(text or "") > limit


def clamp_output(text: str, limit: int = MAX_OUTPUT_CHARS) -> str:
    """Hard-cap reply length (LLM10)."""
    if len(text or "") <= limit:
        return text
    return (text or "")[:limit] + "\n…[truncated for size]"


# ===== LLM01 (+ encoded injection) ========================================

def decode_obfuscated_payloads(text: str) -> str:
    """Expand base64 / hex blobs so later detectors see the plaintext.

    Defends LLM01 (obfuscated injection) and LLM02 (encoded secret exfil).
    """
    if not text:
        return ""
    pieces = [text]

    for b64 in re.findall(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])", text):
        try:
            decoded = base64.b64decode(b64, validate=False).decode("utf-8", errors="ignore")
            if decoded and decoded.isprintable():
                pieces.append(decoded)
        except (binascii.Error, ValueError):
            pass

    for hex_blob in re.findall(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){8,}(?![0-9a-fA-F])", text):
        try:
            decoded = bytes.fromhex(hex_blob).decode("utf-8", errors="ignore")
            if decoded and decoded.isprintable():
                pieces.append(decoded)
        except ValueError:
            pass

    return "\n".join(pieces)


# ===== LLM04 + LLM08 — untrusted / retrieved content ======================

def validate_untrusted_document(source: str, text: str, *, trusted: bool = False) -> dict:
    """Treat email/RAG/web as data (LLM04 poisoning, LLM08 retrieval abuse).

    Returns ``{"allowed": bool, "reason": str}``.
    """
    decision = assess_external_content(
        ExternalContent(source=source, text=text or "", trusted=trusted)
    )
    expanded = decode_obfuscated_payloads(text or "")
    if contains_secret(expanded):
        return {
            "allowed": False,
            "reason": "retrieved content contains protected secrets (LLM04/LLM08)",
        }
    if not decision.allowed:
        return {"allowed": False, "reason": f"{decision.reason} (LLM04/LLM08)"}
    return {"allowed": True, "reason": decision.reason}


def extract_embedded_documents(user_text: str) -> list[tuple[str, str]]:
    """Pull obvious email/RAG blocks out of a user message for provenance checks."""
    docs: list[tuple[str, str]] = []
    patterns = [
        (r"(?is)(?:email|e-mail)\s*(?:content|body)?\s*:\s*(.+)$", "email"),
        (r"(?is)(?:document|rag|retrieved)\s*(?:content|text)?\s*:\s*(.+)$", "rag"),
        (r"(?is)<<<EXTERNAL>>>(.*?)<<<END>>>", "external"),
    ]
    for pattern, source in patterns:
        for match in re.finditer(pattern, user_text or ""):
            docs.append((source, match.group(1).strip()))
    return docs


# ===== LLM03 — Supply Chain ==============================================

def check_supply_chain(requirements_path: str | Path | None = None) -> dict:
    """Verify top-level requirements stay on the lab allowlist (LLM03)."""
    path = Path(requirements_path) if requirements_path else _repo_root() / "requirements.txt"
    unknown: list[str] = []
    declared: list[str] = []
    if not path.exists():
        return {"ok": False, "declared": [], "unknown": ["missing requirements.txt"]}

    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        name = re.split(r"[<>=!~\[]", line, maxsplit=1)[0].strip().lower()
        declared.append(name)
        if name not in ALLOWED_REQUIREMENT_PACKAGES:
            unknown.append(name)

    return {"ok": len(unknown) == 0, "declared": declared, "unknown": unknown}


# ===== LLM05 / LLM07 / LLM09 — output-side ================================

def detect_prompt_leakage(text: str) -> bool:
    """LLM07: reply looks like it is dumping the system prompt / internal notes."""
    normalized = normalize_for_security(text or "")
    return any(re.search(p, normalized, re.IGNORECASE) for p in _PROMPT_LEAK_PATTERNS)


def detect_unsafe_output_markup(text: str) -> bool:
    """LLM05: block script/HTML sinks before a UI ever renders the reply."""
    return any(re.search(p, text or "", re.IGNORECASE) for p in _UNSAFE_OUTPUT_PATTERNS)


def detect_misinformation(text: str, ground_truth: dict | None = None) -> list[str]:
    """LLM09: flag known false rate claims against lab ground truth."""
    gt = ground_truth if ground_truth is not None else load_ground_truth()
    issues: list[str] = []
    normalized = normalize_for_security(text or "")

    true_12m = gt.get("rates", {}).get("savings_apy_12m_percent")
    if true_12m is not None:
        # Claim a different 12-month savings APY than ground truth.
        for match in re.finditer(
            r"(?i)(?:12[-\s]?month|12m|một\s*năm|12\s*tháng)[^\n.%]{0,40}"
            r"(\d+(?:\.\d+)?)\s*%",
            normalized,
        ):
            try:
                claimed = float(match.group(1))
            except ValueError:
                continue
            if abs(claimed - float(true_12m)) > 0.05:
                issues.append(f"false_savings_12m:{claimed}")

    for pattern, name in _FALSE_RATE_CLAIMS:
        if re.search(pattern, normalized, re.IGNORECASE):
            # Only flag 5.5% if it is presented as the 12m savings rate context.
            if name == "savings_12m_false_5.5" and not re.search(
                r"(?i)(savings|tiết\s*kiệm|12)", normalized
            ):
                continue
            issues.append(name)

    for forbidden in gt.get("must_never_appear_in_customer_reply", []):
        if forbidden and forbidden.lower() in normalized.lower():
            issues.append(f"forbidden_secret:{forbidden}")

    return issues


def harden_output(text: str) -> dict:
    """Composite output gate for LLM02/05/07/09 (+ encoded LLM02).

    Returns ``{safe, issues, redacted}`` compatible with content_filter shape.
    """
    issues: list[str] = []
    working = text or ""

    # Expand obfuscation before secret/leak checks.
    expanded = decode_obfuscated_payloads(working)
    if contains_secret(expanded) and not contains_secret(working):
        issues.append("encoded_secret_exfiltration")
        working = (
            "I cannot share internal system details. How else can I help "
            "with your VinBank account or banking needs?"
        )

    if detect_prompt_leakage(expanded):
        issues.append("system_prompt_leakage")
        working = (
            "I cannot share internal system details. How else can I help "
            "with your VinBank account or banking needs?"
        )

    if detect_unsafe_output_markup(working):
        issues.append("unsafe_output_markup")
        working = re.sub(r"<[^>]+>", "", working)
        working = re.sub(r"(?i)javascript\s*:", "", working)

    misinfo = detect_misinformation(expanded)
    if misinfo:
        issues.extend(misinfo)
        working = (
            "I want to make sure I give you accurate VinBank rates. "
            "Please check the official schedule or ask a specialist for "
            "the current savings APY."
        )

    working = clamp_output(working)
    return {
        "safe": len(issues) == 0,
        "issues": issues,
        "redacted": working,
    }


# ===== LLM06 — Excessive Agency helper ====================================

def agency_requires_hitl(action_type: str, high_risk_actions: list[str] | tuple[str, ...]) -> bool:
    """LLM06: side-effecting actions never auto-execute."""
    return action_type in set(high_risk_actions)


def owasp_control_matrix() -> list[dict]:
    """Human-readable map used in the student report."""
    return [
        {"id": "LLM01", "risk": "Prompt Injection", "control": "normalize + layered regex + decode obfuscation + input plugin"},
        {"id": "LLM02", "risk": "Sensitive Information Disclosure", "control": "PII/secret redaction + encoded-secret detection + egress block"},
        {"id": "LLM03", "risk": "Supply Chain", "control": "requirements allowlist check (check_supply_chain)"},
        {"id": "LLM04", "risk": "Data and Model Poisoning", "control": "validate_untrusted_document / assess_external_content"},
        {"id": "LLM05", "risk": "Improper Output Handling", "control": "strip script/HTML sinks before delivery"},
        {"id": "LLM06", "risk": "Excessive Agency", "control": "HITL for HIGH_RISK_ACTIONS + is_egress_allowed"},
        {"id": "LLM07", "risk": "System Prompt Leakage", "control": "detect_prompt_leakage + protected agent without secrets"},
        {"id": "LLM08", "risk": "Vector and Embedding Weaknesses", "control": "RAG/email provenance gate before context use"},
        {"id": "LLM09", "risk": "Misinformation", "control": "ground-truth rate checks + LLM-as-Judge"},
        {"id": "LLM10", "risk": "Unbounded Consumption", "control": "MAX_INPUT_CHARS + rate limiter + output clamp + monitoring"},
    ]
