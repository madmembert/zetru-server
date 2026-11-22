"""Runs the crafted corpus (server/tests/corpus) through the full pipeline with the real rule tier."""

import json
import os
import re

import pytest
from helpers import CORPUS_DIR, LocalBroker, ids, run_pipeline

from zetru_analyzer import signals as catalogue
from zetru_analyzer.packs import default_packs
from zetru_analyzer.supervisor import validate_result

SEVERITY = {"info": 0, "caution": 1, "danger": 2}
CASES = sorted(f[:-4] for f in os.listdir(CORPUS_DIR) if f.endswith(".eml"))


def load(name):
    with open(os.path.join(CORPUS_DIR, name + ".eml"), "rb") as handle:
        raw = handle.read()
    with open(os.path.join(CORPUS_DIR, name + ".json"), "r", encoding="utf-8") as handle:
        sidecar = json.load(handle)
    return raw, sidecar


def run_case(name):
    raw, sidecar = load(name)
    cfg = sidecar.get("broker", {})
    broker = LocalBroker(dns=cfg.get("dns"), listed=cfg.get("listed"), popular=cfg.get("popular", ()),
                         disposable=cfg.get("disposable", ()), ages=cfg.get("ages"))
    return raw, sidecar, run_pipeline(raw, broker, sidecar.get("meta"))


def test_corpus_is_present():
    assert len(CASES) >= 20


@pytest.mark.parametrize("name", CASES)
def test_corpus_case(name):
    raw, sidecar, result = run_case(name)
    found = ids(result)
    missing = set(sidecar.get("expect", [])) - found
    assert not missing, f"missing {sorted(missing)}; got {sorted(found)}"
    unexpected = set(sidecar.get("forbid", [])) & found
    assert not unexpected, f"forbidden {sorted(unexpected)}"
    if "max_severity" in sidecar:
        worst = max((SEVERITY[catalogue.FALLBACK[s]] for s in found), default=0)
        assert worst <= SEVERITY[sidecar["max_severity"]], sorted(found)
    if "auth" in sidecar:
        assert result["auth"]["dkim"][0]["result"] == sidecar["auth"]["dkim_result"]
        assert result["auth"]["dmarc"]["result"] == sidecar["auth"]["dmarc_result"]
    # Every result must pass the supervisor's strict schema validation unchanged.
    assert validate_result(result) is not None
    assert all(s["id"] in catalogue.FALLBACK for s in result["signals"])


def _words(text: str) -> set:
    return {w for w in re.findall(r"[A-Za-zÄÖÜäöüß]{6,}", text)}


@pytest.mark.parametrize("name", CASES)
def test_result_contains_no_mail_text(name):
    """§11.2: no text taken from the mail. Domains (evidence, auth) are the only mail-derived strings allowed."""
    raw, _, result = run_case(name)
    blob = re.sub(r"[a-z0-9_.-]+\.[a-z0-9-]{2,}", " ", json.dumps(result))
    vocabulary = {"legit", "newsletter_bulk", "phishing", "scam_fraud", "unverifiable", "quarantine", "absent",
                  "abstained", "partial", "failed", "skipped", "category", "extortion", "fallback_severity",
                  "evidence", "signals", "decisions", "probabilities", "distribution", "expected", "backend",
                  "model_version", "calibrated", "abstain", "completeness", "attachments", "domain_age", "classifier"}
    vocabulary |= {b.key for b in default_packs().brands}  # evidence.brand holds brand-pack keys
    text_words = {w.lower() for w in _words(raw.decode("utf-8", "replace"))} - vocabulary
    leaked = {w for w in text_words if re.search(r"(?i)\b" + re.escape(w) + r"\b", blob)}
    assert leaked == set()
