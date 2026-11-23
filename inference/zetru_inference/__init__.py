"""Zetru inference: typed-decision service `/v1/systemone` (concept §9)."""

SERVICE_VERSION = "1.0.0"
CANONICAL_QUESTIONS = (
    "category", "asks_credentials", "asks_payment", "asks_bank_change", "urgency_pressure", "asks_secrecy",
    "impersonates_brand_or_authority", "asks_callback", "asks_code_or_command", "extortion",
    "shared_document_lure", "risk_score",
)
CATEGORY_LABELS = ("legit", "newsletter_bulk", "spam", "scam_fraud", "phishing")
RISK_LEVELS = ("none", "low", "elevated", "high")
