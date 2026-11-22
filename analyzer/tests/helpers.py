"""Shared test helpers (kept out of conftest.py so the three service test suites can run together)."""

import hashlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)
# The inference package is used in-process so corpus tests exercise the real rule tier.
sys.path.insert(0, os.path.join(SERVER, "inference"))

from zetru_analyzer import domains, packs, pipeline  # noqa: E402

CORPUS_DIR = os.path.join(SERVER, "tests", "corpus")
NOW = 1795348800  # 2026-11-22


class LocalBroker:
    """In-process stand-in for the supervisor: fake DNS/feeds/ages, real rule tier for typed decisions."""

    def __init__(self, dns=None, listed=None, popular=(), disposable=(), ages=None, decide=True, now=NOW):
        self.dns = dns or {}
        self.listed = listed or {}
        self.popular = set(popular)
        self.disposable = set(disposable)
        self.ages = ages or {}
        self.decide_enabled = decide
        self.now = now
        self.calls = []
        self._router = None

    def router(self):
        if self._router is None:
            from zetru_inference.router import Router

            self._router = Router.from_env({})
        return self._router

    def request(self, *, dns=None, feeds=None, ages=None, decide=None):
        self.calls.append({"dns": dns, "feeds": feeds, "ages": ages, "decide": decide})
        out = {}
        if dns is not None:
            out["dns"] = {n: self.dns.get(n, {"status": "nxdomain", "txt": []}) for n in dns}
        if feeds is not None:
            results = []
            for item in feeds:
                host = item["host"]
                labels = host.split(".")
                cands = [".".join(labels[i:]) for i in range(len(labels) - 1)] or [host]
                listed = sorted({f for c in cands for f in self.listed.get(c, [])})
                results.append({"listed": listed, "popular": (item.get("reg") in self.popular or host in self.popular),
                                "disposable": any(c in self.disposable for c in cands)})
            out["feeds"] = results
            out["feeds_status"] = "ok"
        if ages is not None:
            res = {}
            for d in ages:
                if d in self.ages:
                    value = self.ages[d]
                    if value is None:
                        res[d] = {"status": "unknown", "registered_on": None}
                    elif value == "error":
                        res[d] = {"status": "error", "registered_on": None}
                    else:
                        res[d] = {"status": "ok", "registered_on": self.now - int(value) * 86400}
                else:
                    res[d] = {"status": "ok", "registered_on": self.now - 4000 * 86400}
            out["ages"] = res
        if decide is not None:
            if not self.decide_enabled:
                out["decide"] = {"status": "error"}
            else:
                answers = self.router().decide(decide["state"], decide["questions"], None, decide["policy"]["backends"])
                out["decide"] = {"status": "ok", "answers": [a.to_json() for a in answers]}
        return out


def make_meta(raw: bytes, **extra) -> dict:
    meta = {"schema": 1, "mail_sha256": hashlib.sha256(raw).hexdigest(), "account_ref": "0" * 32, "mode": "auto",
            "locale": "de", "catalog_version": 1}
    meta.update(extra)
    return meta


def run_pipeline(raw: bytes, broker=None, meta_extra=None, backends=("rules",), now=NOW):
    ctx = pipeline.Context(meta=make_meta(raw, **(meta_extra or {})), policy={"backends": list(backends)},
                           psl=domains.bundled_psl(), packs=packs.default_packs(), now=now)
    return pipeline.analyze(raw, ctx, broker or LocalBroker(now=now))


def ids(result) -> set:
    return {s["id"] for s in result["signals"]}
