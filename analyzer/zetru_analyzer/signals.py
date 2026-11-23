"""Signal IDs the server may emit, their fallback severities (concept §6.6, catalogue v1) and the typed
evidence schema (§11.2). Tier-dependent severities use the low-tier (stricter) value as fallback."""

from __future__ import annotations

import re

FALLBACK = {
    "ANALYSIS_PARTIAL": "info",
    "AUTH_DMARC_FAIL_ENFORCED": "danger",
    "AUTH_DMARC_FAIL_NONE": "caution",
    "AUTH_DKIM_PARTIAL_L": "caution",
    "AUTH_DKIM_BODY_MODIFIED": "info",
    "AUTH_REPLAY_SUSPECT": "caution",
    "ID_LOOKALIKE_BRAND": "danger",
    "ID_BRAND_NOT_OFFICIAL": "caution",
    "ID_DOMAIN_NEW": "caution",
    "ID_DOMAIN_DISPOSABLE": "caution",
    "LINK_LOOKALIKE": "danger",
    "LINK_UGC_HOSTING": "caution",
    "LINK_DOMAIN_NEW": "caution",
    "LINK_FEED_HIT": "danger",
    "ATT_EXECUTABLE": "danger",
    "ATT_MACRO": "danger",
    "ATT_ENCRYPTED": "danger",
    "ATT_HTML_SVG_ACTIVE": "danger",
    "ATT_TYPE_MISMATCH": "danger",
    "ATT_ARCHIVE_RISKY": "danger",
    "ATT_ARCHIVE_OPAQUE": "caution",
    "ATT_PDF_ACTIVE": "caution",
    "PHONE_CALLBACK_LURE": "danger",
    "ACCT_WORD_OBFUSCATION": "caution",
    "BULK_RFC8058_SIGNED": "info",
    "MIME_MALFORMED": "info",
    "MIME_LIMITS": "caution",
    "MIME_HIDDEN_TEXT": "caution",
    "MIME_PARTS_DIFFER": "info",
    "FEED_SENDER_HIT": "danger",
    "CLS_CAT_PHISHING": "caution",
    "CLS_CAT_SCAM": "caution",
    "CLS_CAT_SPAM": "caution",
    "CLS_ASKS_CREDENTIALS": "caution",
    "CLS_ASKS_PAYMENT": "caution",
    "CLS_BANK_CHANGE": "caution",
    "CLS_URGENCY": "info",
    "CLS_SECRECY": "info",
    "CLS_IMPERSONATION": "info",
    "CLS_ASKS_CALLBACK": "info",
    "CLS_SHARED_DOC_LURE": "info",
    "CLS_CODE_OR_COMMAND": "danger",
    "CLS_EXTORTION": "danger",
    "CLS_ABSTAIN": "info",
}

NOUL_SIGNALS = {
    "asks_credentials": "CLS_ASKS_CREDENTIALS",
    "asks_payment": "CLS_ASKS_PAYMENT",
    "asks_bank_change": "CLS_BANK_CHANGE",
    "urgency_pressure": "CLS_URGENCY",
    "asks_secrecy": "CLS_SECRECY",
    "impersonates_brand_or_authority": "CLS_IMPERSONATION",
    "asks_callback": "CLS_ASKS_CALLBACK",
    "asks_code_or_command": "CLS_CODE_OR_COMMAND",
    "extortion": "CLS_EXTORTION",
    "shared_document_lure": "CLS_SHARED_DOC_LURE",
}
CATEGORY_SIGNALS = {"phishing": "CLS_CAT_PHISHING", "scam_fraud": "CLS_CAT_SCAM", "spam": "CLS_CAT_SPAM"}
SIGNAL_THRESHOLD = 0.80
MAX_SIGNALS = 64
MAX_PER_ID = 8

_ID = re.compile(r"[A-Z][A-Z0-9_]{2,47}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_PART = re.compile(r"[0-9]{1,4}(?:\.[0-9]{1,4}){0,24}")
_DOMAIN = re.compile(r"[a-z0-9_.\-\[\]:]{1,253}")
_KEY = re.compile(r"[a-z0-9][a-z0-9_-]{0,47}")


def validate_evidence(evidence: dict) -> dict | None:
    """Returns a cleaned evidence object or None if any field is malformed."""
    if not isinstance(evidence, dict):
        return None
    out: dict = {}
    for key, value in evidence.items():
        if key in ("domain", "ref_domain"):
            if not isinstance(value, str) or not _DOMAIN.fullmatch(value):
                return None
        elif key == "url_sha256":
            if not isinstance(value, str) or not _HEX64.fullmatch(value):
                return None
        elif key == "part":
            if not isinstance(value, str) or not _PART.fullmatch(value):
                return None
        elif key in ("feed", "brand"):
            if not isinstance(value, str) or not _KEY.fullmatch(value):
                return None
        elif key == "p":
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 1:
                return None
            value = round(float(value), 4)
        elif key in ("count", "age_days"):
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 10_000_000:
                return None
        else:
            return None
        out[key] = value
    return out


def validate_signal(sig: dict) -> dict | None:
    if not isinstance(sig, dict):
        return None
    sid = sig.get("id")
    if not isinstance(sid, str) or not _ID.fullmatch(sid) or sid not in FALLBACK:
        return None
    evidence = validate_evidence(sig.get("evidence") or {})
    if evidence is None:
        return None
    out = {"id": sid, "fallback_severity": FALLBACK[sid]}
    if evidence:
        out["evidence"] = evidence
    return out


class SignalSet:
    """Collects signals, de-duplicates identical (id, evidence) pairs and enforces the response limits."""

    def __init__(self) -> None:
        self._items: list[dict] = []
        self._seen: set[str] = set()
        self._per_id: dict[str, int] = {}

    def add(self, sid: str, **evidence) -> None:
        sig = validate_signal({"id": sid, "evidence": {k: v for k, v in evidence.items() if v is not None}})
        if sig is None:
            raise ValueError(f"invalid signal {sid}")
        key = repr(sorted(sig.items(), key=lambda kv: kv[0]))
        if key in self._seen or len(self._items) >= MAX_SIGNALS or self._per_id.get(sid, 0) >= MAX_PER_ID:
            return
        self._seen.add(key)
        self._per_id[sid] = self._per_id.get(sid, 0) + 1
        self._items.append(sig)

    def ids(self) -> set[str]:
        return {s["id"] for s in self._items}

    def has(self, sid: str) -> bool:
        return sid in self._per_id

    def items(self) -> list[dict]:
        return list(self._items)
