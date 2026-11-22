"""Canonical state rendering `state-1` for typed decisions (concept §9.2) and the fixed question set.

Details fixed here (documented in DECISIONS.md):
- tokens are whitespace-separated words; [SUBJECT] ≤ 30, [BODY-HEAD] ≤ 250, [BODY-TAIL] ≤ 80 tokens of
  the body after the head, [OCR] ≤ 60;
- in the body, link positions are marked with `[LINK]` (anchor text stays, URLs are replaced);
- the server does not know the contact history, so `first-contact` is never emitted; `bulk` is added
  when List-Id, List-Unsubscribe or Precedence bulk/list headers are present.
"""

from __future__ import annotations

import re

from . import STATE_VERSION

HEAD_TOKENS = 250
TAIL_TOKENS = 80
SUBJECT_TOKENS = 30
OCR_TOKENS = 60
MAX_LINKS = 8
MAX_ATTACH = 5

_URL = re.compile(r"(?i)\b(?:https?://|www\.)\S+")
_QUOTE_HEADER = re.compile(
    r"(?im)^(?:on .{3,200} wrote:|am .{3,200} schrieb .{0,200}:|-{2,}\s*(?:original message|ursprüngliche nachricht|"
    r"forwarded message|weitergeleitete nachricht)\s*-{2,}|von:\s.+\n\s*gesendet:|from:\s.+\n\s*sent:)")

QUESTIONS = [
    {"id": "category", "type": "choice", "instructions": "What kind of message is this?",
     "criteria": ["legit", "newsletter_bulk", "spam", "scam_fraud", "phishing"]},
    {"id": "asks_credentials", "type": "noul", "instructions": "Does the message ask the recipient to enter, confirm or "
     "update login data, card data or personal data (not merely to confirm an e-mail address after sign-up)?", "criteria": None},
    {"id": "asks_payment", "type": "noul", "instructions": "Does it ask the recipient to pay, transfer money or buy vouchers?",
     "criteria": None},
    {"id": "asks_bank_change", "type": "noul", "instructions": "Does it announce or request new bank details for payments?",
     "criteria": None},
    {"id": "urgency_pressure", "type": "noul", "instructions": "Does it set a short deadline or threaten consequences?",
     "criteria": None},
    {"id": "asks_secrecy", "type": "noul", "instructions": "Does it ask for secrecy or to avoid normal channels?", "criteria": None},
    {"id": "impersonates_brand_or_authority", "type": "noul",
     "instructions": "Does it present itself as a well-known company, bank or public authority?", "criteria": None},
    {"id": "asks_callback", "type": "noul", "instructions": "Does it ask the recipient to call a phone number?", "criteria": None},
    {"id": "asks_code_or_command", "type": "noul", "instructions": "Does it ask to enter a code on a login page, approve an "
     "app, paste a command or install remote-access software?", "criteria": None},
    {"id": "extortion", "type": "noul", "instructions": "Does it threaten to publish compromising material or demand money "
     "under threat?", "criteria": None},
    {"id": "shared_document_lure", "type": "noul", "instructions": "Is its main content a generic invitation to open a shared "
     "document or voicemail?", "criteria": None},
    {"id": "risk_score", "type": "score", "instructions": "Overall risk of the text",
     "criteria": ["none", "low", "elevated", "high"]},
]
QUESTION_IDS = [q["id"] for q in QUESTIONS]


def _clip_tokens(text: str, n: int) -> str:
    return " ".join(text.split()[:n])


def strip_quotes_and_signature(text: str) -> str:
    lines = []
    for line in text.splitlines():
        if line.lstrip().startswith(">"):
            continue
        if line.rstrip() in ("--", "-- ", "__"):
            break
        lines.append(line)
    body = "\n".join(lines)
    m = _QUOTE_HEADER.search(body)
    if m:
        body = body[: m.start()]
    return body


def body_tokens(state_text: str) -> list[str]:
    cleaned = _URL.sub(" [LINK] ", strip_quotes_and_signature(state_text))
    cleaned = re.sub(r"(?:\s*\[LINK\]\s*){2,}", " [LINK] ", cleaned)
    out = []
    # Sentence boundaries survive as tokens ending in punctuation; line breaks become ' / ' separators
    # so that list items and headings stay separate sentences for the rule tier.
    for line in cleaned.splitlines():
        words = line.split()
        if not words:
            continue
        if out and not out[-1].endswith((".", "!", "?", ":", "/")):
            out.append("/")
        out.extend(words)
    return out


def render(display_name: str, from_domain: str | None, flags: list[str], auth: str, subject: str,
           body: list[str], links: list[tuple[str, str, bool]], attach: list[str], ocr: str | None) -> str:
    head = body[:HEAD_TOKENS]
    tail = body[HEAD_TOKENS:][-TAIL_TOKENS:] if len(body) > HEAD_TOKENS else []
    lines = [
        f"[FROM] {_clip_tokens(display_name, 12) or '-'} | {from_domain or '-'} | flags: {', '.join(flags) or '-'}",
        f"[AUTH] {auth}",
        f"[SUBJECT] {_clip_tokens(subject, SUBJECT_TOKENS)}",
        f"[BODY-HEAD] {' '.join(head)}",
    ]
    link_items = []
    for text, domain, mismatch in links[:MAX_LINKS]:
        item = f"{_clip_tokens(text, 8) or '-'} → {domain}"
        if mismatch:
            item += " [MISMATCH]"
        link_items.append(item)
    lines.append("[LINKS] " + ("; ".join(link_items) if link_items else "-"))
    lines.append("[ATTACH] " + (", ".join(attach[:MAX_ATTACH]) if attach else "-"))
    lines.append("[OCR] " + (_clip_tokens(ocr, OCR_TOKENS) if ocr else "-"))
    lines.append("[BODY-TAIL] " + (" ".join(tail) if tail else "-"))
    return "\n".join(lines)


def state_version() -> str:
    return STATE_VERSION
