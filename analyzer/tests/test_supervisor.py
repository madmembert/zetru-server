"""Supervisor: real zygote + forked workers end to end, budget enforcement, and a fake (hostile) worker."""

import asyncio
import dataclasses
import hashlib
import json
import uuid

import pytest
from helpers import LocalBroker

from zetru_analyzer import ipc, state
from zetru_analyzer.config import Config
from zetru_analyzer.supervisor import (AnalysisTimeout, Budget, Busy, Supervisor, Unavailable, allowed_dns_names,
                                       validate_result)

RAW = ("From: Anna <anna@sender.example>\r\nTo: bob@example.org\r\nSubject: Hallo\r\n\r\n"
       "Hallo Bob, wollen wir am Samstag zusammen frühstücken gehen? Ich hätte gegen zehn Uhr Zeit und würde "
       "das Café am Markt vorschlagen. Liebe Grüße, Anna\r\n").encode()
POLICY = {"backends": ["rules"], "max_mail_bytes": 20_971_520}


def meta(raw=RAW):
    return {"schema": 1, "mail_sha256": hashlib.sha256(raw).hexdigest(), "account_ref": "0" * 32, "mode": "auto",
            "locale": "de", "catalog_version": 1}


def make_supervisor(tmp_path, **env):
    local = LocalBroker()

    async def resolver(name):
        return "nxdomain", []

    async def inference(doc):
        return local.request(decide=doc)["decide"]

    async def ages(domain):
        return {"status": "unknown", "registered_on": None}

    cfg = Config.from_env({"ZETRU_FEEDS_DIR": str(tmp_path), **env})
    return Supervisor(cfg, resolver=resolver, inference=inference, ages=ages)


def test_end_to_end_with_forked_worker(tmp_path):
    async def run():
        sup = make_supervisor(tmp_path)
        await sup.start()
        try:
            status, resp = await sup.analyze(meta(), RAW, POLICY)
        finally:
            sup.zygote.stop()
        return status, resp

    status, resp = asyncio.run(run())
    assert status == 200
    assert resp["schema"] == 1 and resp["mail_sha256"] == meta()["mail_sha256"]
    uuid.UUID(resp["analysis_id"])
    assert resp["completeness"]["feeds"] == "failed" and resp["completeness"]["complete"] is False
    assert [s["id"] for s in resp["signals"]] == ["ANALYSIS_PARTIAL"]   # no feeds published: never "complete"
    assert {f["id"] for f in resp["feeds"]} == {"psl", "certpl", "majestic", "disposable"}
    assert len(resp["decisions"]) == len(state.QUESTIONS) and len(resp["campaign_bands"]) == 4
    assert len(json.dumps(resp)) < 256 * 1024


def test_busy_when_workers_and_queue_are_full(tmp_path):
    async def run():
        sup = make_supervisor(tmp_path, ZETRU_WORKERS="1", ZETRU_QUEUE="0")
        await sup.start()
        try:
            results = await asyncio.gather(sup.analyze(meta(), RAW, POLICY), sup.analyze(meta(), RAW, POLICY),
                                           return_exceptions=True)
        finally:
            sup.zygote.stop()
        return results

    results = asyncio.run(run())
    assert sum(isinstance(r, Busy) for r in results) == 1
    assert sum(isinstance(r, tuple) and r[0] == 200 for r in results) == 1


def test_dns_name_policy():
    names = ["_dmarc.example.com", "example.com", "s1._domainkey.example.com", "exfil-data.attacker.example",
             "_dmarc.UPPER.example", "bad name", "x" * 300]
    assert allowed_dns_names(names) == ["_dmarc.example.com", "example.com", "s1._domainkey.example.com"]


def test_broker_enforces_budgets_and_ignores_worker_policy(tmp_path):
    seen = []

    async def resolver(name):
        return "nxdomain", []

    async def inference(doc):
        seen.append(doc)
        return {"answers": []}

    async def ages(domain):
        return {"status": "ok", "registered_on": 1}

    async def run():
        sup = Supervisor(Config.from_env({"ZETRU_FEEDS_DIR": str(tmp_path)}), resolver=resolver,
                         inference=inference, ages=ages)
        budget = Budget()
        names = [f"_dmarc.d{i}.example" for i in range(30)]
        reply = await sup.broker({"t": "req", "dns": names, "feeds": [{"host": f"h{i}.example"} for i in range(45)],
                                  "ages": [f"a{i}.example" for i in range(9)],
                                  "decide": {"state": "x", "questions": [{"id": "evil"}],
                                             "policy": {"backends": ["jev"]}}}, budget, {"backends": ["rules"]})
        second = await sup.broker({"t": "req", "decide": {"state": "x"}}, budget, {"backends": ["rules"]})
        return reply, second

    reply, second = asyncio.run(run())
    statuses = [v["status"] for v in reply["dns"].values()]
    assert statuses.count("nxdomain") == 25 and statuses.count("denied") == 5
    assert reply["feeds_status"] == "partial" and sum(1 for r in reply["feeds"] if r.get("skipped")) == 5
    assert len(reply["ages"]) == 6
    assert seen[0]["policy"] == {"backends": ["rules"]} and seen[0]["questions"] == state.QUESTIONS
    assert second["decide"] == {"status": "error"}   # one typed-decision call per mail


def test_validate_result_rejects_hostile_output():
    good = {"completeness": {k: "ok" for k in ("parse", "auth", "urls", "attachments", "domain_age", "feeds",
                                                 "classifier")},
            "signals": [{"id": "LINK_FEED_HIT", "fallback_severity": "danger", "evidence": {"domain": "x.example"}}],
            "decisions": [], "auth": {"dkim": [], "dmarc": None}, "campaign_bands": ["0000", "ffff", "1a2b", "3c4d"]}
    assert validate_result(good) is not None
    assert validate_result(good)["signals"][0]["fallback_severity"] == "danger"
    for mutate in (
        lambda r: r["signals"].append({"id": "NOT_IN_CATALOGUE"}),
        lambda r: r["signals"].append({"id": "LINK_FEED_HIT", "evidence": {"domain": "<script>"}}),
        lambda r: r["signals"].append({"id": "LINK_FEED_HIT", "evidence": {"text": "mail content"}}),
        lambda r: r["signals"].extend([{"id": "MIME_LIMITS"}] * 65),
        lambda r: r.update(campaign_bands=["xyz!", "0", "0", "0"]),
        lambda r: r["completeness"].update(parse="great"),
        lambda r: r["auth"]["dkim"].append({"d": "a b", "s": "s", "result": "pass"}),
        lambda r: r["decisions"].append({"id": "category", "type": "choice", "backend": "rules",
                                         "model_version": "x", "p_yes": 7}),
    ):
        bad = json.loads(json.dumps(good))
        mutate(bad)
        assert validate_result(bad) is None


class FakeZygote:
    """Replaces the zygote: the 'worker' is a coroutine speaking the IPC protocol on the other socket end."""

    def __init__(self, behaviour, exit_reason="ok"):
        self.behaviour = behaviour
        self.exit_reason = exit_reason

    def alive(self):
        return True

    def stop(self):
        pass

    async def spawn(self, job_id, worker_end):
        loop = asyncio.get_running_loop()
        exited = loop.create_future()
        sock = worker_end.dup()

        async def run():
            reader, writer = await asyncio.open_unix_connection(sock=sock)
            try:
                await self.behaviour(reader, writer)
            finally:
                writer.close()
                exited.set_result({"op": "exit", "id": job_id, "reason": self.exit_reason})

        loop.create_task(run())
        return exited


async def _read_job(reader):
    msg, blob = await ipc.read_frame(reader, ipc.MAX_TO_WORKER)
    assert msg["t"] == "job" and blob == RAW
    return msg


def run_with(tmp_path, behaviour, exit_reason="ok", timeout="20"):
    async def run():
        sup = make_supervisor(tmp_path)
        sup.config = dataclasses.replace(sup.config, request_timeout_s=float(timeout))
        sup.zygote = FakeZygote(behaviour, exit_reason)
        return await sup.analyze(meta(), RAW, POLICY)

    return asyncio.run(run())


def test_worker_garbage_result_becomes_failure_result(tmp_path):
    async def behaviour(reader, writer):
        await _read_job(reader)
        writer.write(ipc.encode({"t": "result", "result": {"signals": "everything is fine"}}))
        await writer.drain()

    status, resp = run_with(tmp_path, behaviour)
    assert status == 200 and resp["completeness"]["parse"] == "failed"
    assert {s["id"] for s in resp["signals"]} >= {"MIME_MALFORMED", "MIME_LIMITS", "ANALYSIS_PARTIAL"}


def test_silent_worker_times_out(tmp_path):
    async def behaviour(reader, writer):
        await _read_job(reader)
        await asyncio.sleep(5)

    with pytest.raises(AnalysisTimeout):
        run_with(tmp_path, behaviour, timeout="0.5")


def test_worker_killed_on_wall_clock_is_a_resource_failure(tmp_path):
    # PY-05: a mail that exhausts the worker's CPU or wall clock gets a 200 with a caution, not "retry later".
    async def behaviour(reader, writer):
        await _read_job(reader)

    status, resp = run_with(tmp_path, behaviour, exit_reason="timeout")
    assert status == 200 and resp["completeness"]["parse"] == "failed"
    assert {"MIME_MALFORMED", "MIME_LIMITS"} <= {s["id"] for s in resp["signals"]}


def test_worker_crash_without_result_is_resource_failure(tmp_path):
    async def behaviour(reader, writer):
        await _read_job(reader)

    status, resp = run_with(tmp_path, behaviour, exit_reason="signal")
    assert status == 200 and "MIME_LIMITS" in {s["id"] for s in resp["signals"]}


def test_worker_internal_error_is_a_resource_failure(tmp_path):
    # PY-01: an exception the mail triggers must never become 503 analyzer_unavailable.
    async def behaviour(reader, writer):
        await _read_job(reader)
        writer.write(ipc.encode({"t": "error", "kind": "internal", "stage": "analyze", "error_class": "KeyError"}))
        await writer.drain()

    status, resp = run_with(tmp_path, behaviour)
    assert status == 200 and "MIME_MALFORMED" in {s["id"] for s in resp["signals"]}


def test_worker_sandbox_failure_is_unavailable(tmp_path):
    async def behaviour(reader, writer):
        await _read_job(reader)
        writer.write(ipc.encode({"t": "error", "kind": "sandbox", "stage": "sandbox", "error_class": "SandboxError"}))
        await writer.drain()

    with pytest.raises(Unavailable):
        run_with(tmp_path, behaviour)


def test_worker_cannot_exceed_dns_budget_across_requests(tmp_path):
    replies = []

    async def behaviour(reader, writer):
        await _read_job(reader)
        for _ in range(3):
            writer.write(ipc.encode({"t": "req", "dns": [f"_dmarc.x{i}.example" for i in range(20)]}))
            await writer.drain()
            reply, _ = await ipc.read_frame(reader, ipc.MAX_FROM_WORKER)
            replies.append(reply)
        writer.write(ipc.encode({"t": "result", "result": {"bad": True}}))
        await writer.drain()

    run_with(tmp_path, behaviour)
    resolved = sum(1 for r in replies for v in r["dns"].values() if v["status"] != "denied")
    assert resolved == 25


def test_url_check(tmp_path):
    from test_framing_ipc_feeds import publish

    publish(str(tmp_path), "certpl", ["evil.example"])
    sup = make_supervisor(tmp_path)
    sup.feeds.reload()
    out = sup.url_check([{"host": "login.evil.example", "url_sha256": "a" * 64},
                         {"host": "good.example", "url_sha256": "b" * 64}])
    assert out["results"][0]["hit"] and out["results"][0]["signal"]["id"] == "LINK_FEED_HIT"
    assert out["results"][0]["signal"]["evidence"] == {"domain": "login.evil.example", "feed": "certpl",
                                                       "url_sha256": "a" * 64}
    assert out["results"][1] == {"url_sha256": "b" * 64, "hit": False, "signal": None}
