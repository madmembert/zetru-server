"""URL canonicalisation contract with the app (concept §11.4).

`contract/url-canonicalization.json` lists inputs and the canonical form the server produces
(`null` = rejected). The app's LinkCanonicalizer test checks the same file, so `url_sha256` values
computed on the device and on the server agree byte for byte.

Regenerate the expected values from this implementation (after a deliberate change, then update
the app's copy with its scripts/sync-server-contract.py):
    ZETRU_WRITE_CONTRACT=1 .venv/bin/python -m pytest -q analyzer/tests/test_contract_vectors.py
"""
import json
import os
from pathlib import Path

from zetru_analyzer import urls

CONTRACT = Path(__file__).resolve().parents[2] / "contract" / "url-canonicalization.json"


def canonical(url: str) -> str | None:
    """The canonical URL string, as the app computes it (None = rejected)."""
    result = urls.canonicalize(url)
    return result[0] if result else None


def load() -> dict:
    with open(CONTRACT, encoding="utf-8") as handle:
        return json.load(handle)


def test_contract_vectors_match_the_server_implementation():
    document = load()
    vectors = document["vectors"]
    assert len(vectors) >= 100
    if os.environ.get("ZETRU_WRITE_CONTRACT") == "1":
        for vector in vectors:
            vector["canonical"] = canonical(vector["input"])
        CONTRACT.write_text(json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    mismatches = [(v["input"][:80], v.get("canonical"), canonical(v["input"]))
                  for v in vectors if canonical(v["input"]) != v.get("canonical")]
    assert mismatches == []


def test_contract_inputs_are_unique():
    inputs = [v["input"] for v in load()["vectors"]]
    assert len(inputs) == len(set(inputs))
