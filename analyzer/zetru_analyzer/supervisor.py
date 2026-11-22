"""Supervisor: admission control, zygote management, brokering of DNS/feeds/ages/typed decisions with
per-mail budgets, validation of everything a worker returns, and response assembly.

The supervisor never parses mail content. It is a single-threaded asyncio program (no executor threads),
so starting the zygote with exec is the only process creation it performs.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import socket
import subprocess
import sys
import time
import uuid
from urllib.parse import quote

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver

from . import CATALOG_VERSION, SERVER_VERSION, framing, httpclient, ipc, logs, pipeline, state
from .config import Config
from .domains import normalize_domain
from .feeds import FeedStore
from .signals import FALLBACK, MAX_SIGNALS, validate_evidence, validate_signal

DNS_BUDGET = 25
FEED_BUDGET = 40
AGE_BUDGET = 6
MAX_RESPONSE = 256 * 1024
_NAME = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{1,63}$")
_STAGES = ("parse", "auth", "urls", "attachments", "domain_age", "feeds", "classifier")
_STAGE_VALUES = ("ok", "partial", "failed", "skipped", "abstained")
_BAND = re.compile(r"^[0-9a-f]{4}$")


class AnalysisTimeout(Exception):
    pass


class Unavailable(Exception):
    pass


class Busy(Exception):
    pass


class Budget:
    def __init__(self) -> None:
        self.dns = 0
        self.feeds = 0
        self.ages = 0
        self.decide = 0


def allowed_dns_names(names: list[str]) -> list[str]:
    """Only TXT names of the shapes the analysis needs: `_dmarc.<d>`, `<s>._domainkey.<d>` and `<d>` itself
    when `_dmarc.<d>` is part of the same batch (non-existence check for the np tag)."""
    dmarc_targets = {n[len("_dmarc."):] for n in names if isinstance(n, str) and n.startswith("_dmarc.")}
    out = []
    for name in names:
        if not isinstance(name, str) or not _NAME.match(name):
            continue
        if name.startswith("_dmarc.") or "._domainkey." in name or name in dmarc_targets:
            out.append(name)
    return out


class Zygote:
    def __init__(self, config: Config):
        self.config = config
        self.proc: subprocess.Popen | None = None
        self.ctrl: socket.socket | None = None
        self.reader_task: asyncio.Task | None = None
        self.spawned: dict[int, asyncio.Future] = {}
        self.exits: dict[int, asyncio.Future] = {}
        self.ready: asyncio.Future | None = None

    def start(self) -> None:
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        env = dict(os.environ)
        env["ZETRU_ZYGOTE_FD"] = str(child.fileno())
        env["ZETRU_FEEDS_DIR"] = self.config.feeds_dir
        env["ZETRU_SANDBOX"] = self.config.sandbox
        self.proc = subprocess.Popen([sys.executable, "-m", "zetru_analyzer.zygote"], pass_fds=(child.fileno(),),
                                     env=env, close_fds=True, cwd=os.path.dirname(os.path.dirname(__file__)))
        child.close()
        parent.setblocking(False)
        self.ctrl = parent
        loop = asyncio.get_running_loop()
        self.ready = loop.create_future()
        self.reader_task = loop.create_task(self._read())
        logs.info("zygote_started", pid_role="zygote")

    async def _read(self) -> None:
        loop = asyncio.get_running_loop()
        while self.ctrl is not None:
            try:
                data = await loop.sock_recv(self.ctrl, 4096)
            except (OSError, asyncio.CancelledError):
                break
            if not data:
                break
            try:
                msg = json.loads(data)
            except ValueError:
                continue
            job_id = msg.get("id")
            if msg.get("op") == "ready":
                if self.ready is not None and not self.ready.done():
                    self.ready.set_result(True)
            elif msg.get("op") in ("spawned", "spawn_failed"):
                fut = self.spawned.pop(job_id, None)
                if fut and not fut.done():
                    fut.set_result(msg["op"] == "spawned")
            elif msg.get("op") == "exit":
                fut = self.exits.pop(job_id, None)
                if fut and not fut.done():
                    fut.set_result(msg)
        for fut in list(self.spawned.values()) + list(self.exits.values()) + [self.ready]:
            if fut is not None and not fut.done():
                fut.set_result(None)

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    async def spawn(self, job_id: int, worker_end: socket.socket) -> asyncio.Future:
        if not self.alive() or self.ctrl is None or self.ready is None:
            raise Unavailable("zygote")
        try:
            if not await asyncio.wait_for(asyncio.shield(self.ready), 30.0):
                raise Unavailable("zygote")
        except asyncio.TimeoutError:
            raise Unavailable("zygote") from None
        loop = asyncio.get_running_loop()
        spawned = loop.create_future()
        exited = loop.create_future()
        self.spawned[job_id] = spawned
        self.exits[job_id] = exited
        socket.send_fds(self.ctrl, [json.dumps({"op": "spawn", "id": job_id}).encode()], [worker_end.fileno()])
        try:
            ok = await asyncio.wait_for(spawned, 3.0)
        except asyncio.TimeoutError:
            ok = False
        if not ok:
            self.exits.pop(job_id, None)
            raise Unavailable("spawn")
        return exited

    def stop(self) -> None:
        if self.ctrl is not None:
            self.ctrl.close()
            self.ctrl = None
        if self.proc is not None and self.proc.poll() is None:
            self.proc.kill()
            try:
                self.proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass


class Supervisor:
    def __init__(self, config: Config, feeds: FeedStore | None = None, resolver=None, inference=None, ages=None):
        self.config = config
        self.feeds = feeds or FeedStore(config.feeds_dir)
        self.zygote = Zygote(config)
        self.slots = asyncio.Semaphore(config.workers)
        self.waiting = 0
        self.active = 0
        self.next_id = 1
        self._resolver = resolver          # injectable for tests: async (name) -> (status, [txt])
        self._inference = inference        # injectable: async (doc) -> dict
        self._ages = ages                  # injectable: async (domain) -> dict
        self._dns = None
        self._backend_cache: tuple[float, list] = (0.0, [])
        self._psl_version = None

    # Lifecycle ------------------------------------------------------------------------------------------
    async def start(self) -> None:
        self.feeds.reload()
        psl = self.feeds.feeds.get("psl")
        self._psl_version = psl.info.version if psl else None
        self.zygote.start()
        asyncio.get_running_loop().create_task(self._maintenance())

    async def _maintenance(self) -> None:
        while True:
            await asyncio.sleep(30)
            try:
                changed = self.feeds.reload()
                psl = self.feeds.feeds.get("psl")
                version = psl.info.version if psl else None
                if not self.zygote.alive() or ("psl" in changed and version != self._psl_version):
                    self._psl_version = version
                    old = self.zygote
                    self.zygote = Zygote(self.config)
                    self.zygote.start()
                    await asyncio.sleep(20)  # in-flight workers of the old zygote finish (15 s wall clock)
                    old.stop()
            except Exception as exc:  # maintenance must never stop
                logs.error("maintenance_error", error_class=type(exc).__name__)

    # Outside lookups ------------------------------------------------------------------------------------
    def _dns_resolver(self):
        if self._dns is None:
            try:
                address = httpclient.resolve(self.config.resolver_host, 53)
            except (OSError, httpclient.HttpError):
                return None
            resolver = dns.asyncresolver.Resolver(configure=False)
            resolver.nameservers = [address]
            resolver.timeout = self.config.dns_timeout_s
            resolver.lifetime = self.config.dns_timeout_s
            self._dns = resolver
        return self._dns

    async def _txt(self, name: str) -> dict:
        if self._resolver is not None:
            status, records = await self._resolver(name)
            return {"status": status, "txt": records}
        resolver = self._dns_resolver()
        if resolver is None:
            return {"status": "error", "txt": []}
        try:
            answer = await resolver.resolve(name, dns.rdatatype.TXT, raise_on_no_answer=True)
            records = []
            for rdata in answer:
                records.append(b"".join(rdata.strings).decode("latin-1")[:8192])
            return {"status": "ok", "txt": records[:10]}
        except dns.resolver.NXDOMAIN:
            return {"status": "nxdomain", "txt": []}
        except dns.resolver.NoAnswer:
            return {"status": "nodata", "txt": []}
        except (dns.exception.DNSException, OSError):
            return {"status": "error", "txt": []}

    async def _age(self, domain: str) -> dict:
        if self._ages is not None:
            return await self._ages(domain)
        try:
            status, doc = await httpclient.request_json(
                "GET", f"{self.config.lookup_url}/internal/v1/age?domain={quote(domain, safe='')}",
                timeout=self.config.age_timeout_s)
        except httpclient.HttpError:
            return {"status": "error", "registered_on": None}
        if status != 200 or doc.get("status") not in ("ok", "unknown", "error"):
            return {"status": "error", "registered_on": None}
        registered = doc.get("registered_on")
        if registered is not None and (isinstance(registered, bool) or not isinstance(registered, int)):
            registered = None
        return {"status": doc["status"], "registered_on": registered}

    async def _decide(self, doc: dict) -> dict:
        try:
            if self._inference is not None:
                result = await self._inference(doc)
            else:
                status, result = await httpclient.request_json("POST", f"{self.config.inference_url}/v1/systemone",
                                                               doc, timeout=self.config.inference_timeout_s)
                if status != 200:
                    return {"status": "error"}
        except httpclient.HttpError:
            return {"status": "error"}
        answers = []
        for ans in result.get("answers") or []:
            clean = validate_answer(ans)
            if clean is None:
                return {"status": "error"}
            answers.append(clean)
        return {"status": "ok", "answers": answers}

    async def broker(self, req: dict, budget: Budget, policy: dict) -> dict:
        reply: dict = {"t": "resp"}
        tasks = {}
        if "dns" in req:
            names = req["dns"] if isinstance(req["dns"], list) else []
            allowed = set(allowed_dns_names(names))
            dns_out: dict = {}
            for name in names[:64]:
                if not isinstance(name, str):
                    continue
                if name in allowed and budget.dns < DNS_BUDGET:
                    budget.dns += 1
                    tasks[("dns", name)] = self._txt(name)
                else:
                    dns_out[name[:253]] = {"status": "denied", "txt": []}
            reply["dns"] = dns_out
        if "feeds" in req:
            items = req["feeds"] if isinstance(req["feeds"], list) else []
            results = []
            partial = False
            for item in items[:FEED_BUDGET * 2]:
                host = normalize_domain(item.get("host")) if isinstance(item, dict) else None
                reg = normalize_domain(item.get("reg")) if isinstance(item, dict) and item.get("reg") else None
                if host is None or budget.feeds >= FEED_BUDGET:
                    partial = True
                    results.append({"listed": [], "popular": False, "disposable": False, "skipped": True})
                    continue
                budget.feeds += 1
                results.append(self.feeds.lookup(host, reg))
            reply["feeds"] = results
            reply["feeds_status"] = "partial" if partial else "ok"
        if "ages" in req:
            domains = req["ages"] if isinstance(req["ages"], list) else []
            reply["ages"] = {}
            for domain in domains[:AGE_BUDGET * 2]:
                clean = normalize_domain(domain) if isinstance(domain, str) else None
                if clean is None or clean != domain or budget.ages >= AGE_BUDGET:
                    continue
                budget.ages += 1
                tasks[("age", clean)] = self._age(clean)
        if req.get("decide") is not None:
            doc = req["decide"]
            if budget.decide >= 1 or not isinstance(doc, dict) or not isinstance(doc.get("state"), str) \
                    or len(doc["state"]) > 64 * 1024 or not policy.get("backends"):
                reply["decide"] = {"status": "error"}
            else:
                budget.decide += 1
                # Questions and backends come from the supervisor and the tenant policy, never from the worker.
                tasks[("decide", "")] = self._decide({"state": doc["state"], "state_version": state.state_version(),
                                                       "language_hint": None, "questions": state.QUESTIONS,
                                                       "policy": {"backends": policy["backends"]}})
        if tasks:
            results = await asyncio.gather(*tasks.values(), return_exceptions=True)
            for (kind, key), value in zip(tasks.keys(), results):
                if isinstance(value, BaseException):
                    value = {"status": "error", "txt": []} if kind == "dns" else {"status": "error"}
                if kind == "dns":
                    reply["dns"][key] = value
                elif kind == "age":
                    reply["ages"][key] = value
                else:
                    reply["decide"] = value
        return reply

    # Jobs -----------------------------------------------------------------------------------------------
    async def analyze(self, meta: dict, raw: bytes, policy: dict) -> tuple[int, dict]:
        capacity = self.config.workers + self.config.queue
        if self.active + self.waiting >= capacity:
            raise Busy()
        deadline = time.monotonic() + self.config.request_timeout_s
        self.waiting += 1
        try:
            try:
                await asyncio.wait_for(self.slots.acquire(), max(0.1, deadline - time.monotonic()))
            except asyncio.TimeoutError:
                raise AnalysisTimeout() from None
        finally:
            self.waiting -= 1
        self.active += 1
        try:
            remaining = deadline - time.monotonic()
            try:
                result = await asyncio.wait_for(self._run_worker(meta, raw, policy), max(0.1, remaining))
            except asyncio.TimeoutError:
                raise AnalysisTimeout() from None
        finally:
            self.active -= 1
            self.slots.release()
        return 200, self.finalize(meta, result)

    async def _run_worker(self, meta: dict, raw: bytes, policy: dict) -> dict:
        job_id = self.next_id
        self.next_id += 1
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            exited = await self.zygote.spawn(job_id, child)
        finally:
            child.close()
        reader, writer = await asyncio.open_unix_connection(sock=parent, limit=ipc.MAX_FROM_WORKER)
        budget = Budget()
        try:
            writer.write(ipc.encode({"t": "job", "meta": meta, "policy": policy, "now": int(time.time())}, raw))
            await writer.drain()
            while True:
                try:
                    msg, _ = await ipc.read_frame(reader, ipc.MAX_FROM_WORKER)
                except (asyncio.IncompleteReadError, ipc.ProtocolError, ConnectionError):
                    break
                kind = msg.get("t")
                if kind == "req":
                    reply = await self.broker(msg, budget, policy)
                    writer.write(ipc.encode(reply))
                    await writer.drain()
                elif kind == "result":
                    result = validate_result(msg.get("result"))
                    if result is None:
                        logs.error("worker_result_invalid", stage="validate")
                        return pipeline.failure_result("resources")
                    return result
                elif kind == "error":
                    error_kind = msg.get("kind")
                    if error_kind == "resources":
                        return pipeline.failure_result("resources")
                    if error_kind == "sandbox":
                        raise Unavailable("sandbox")
                    raise Unavailable("internal")
                else:
                    break
        finally:
            writer.close()
        # Channel closed without a result: ask the zygote how the worker ended.
        try:
            info = await asyncio.wait_for(exited, 2.0)
        except asyncio.TimeoutError:
            info = None
        if info and info.get("reason") == "timeout":
            raise AnalysisTimeout()
        return pipeline.failure_result("resources")

    def finalize(self, meta: dict, result: dict) -> dict:
        now = int(time.time())
        completeness = dict(result["completeness"])
        if completeness.get("parse") != "failed":
            completeness["feeds"] = self.feeds.completeness(now)
        ok = all(completeness[s] == "ok" or (s == "domain_age" and completeness[s] == "partial") for s in _STAGES)
        completeness["complete"] = ok
        signals = list(result["signals"])
        if not ok and not any(s["id"] == "ANALYSIS_PARTIAL" for s in signals) and len(signals) < MAX_SIGNALS:
            signals.append({"id": "ANALYSIS_PARTIAL", "fallback_severity": FALLBACK["ANALYSIS_PARTIAL"]})
        response = {
            "schema": 1,
            "analysis_id": str(uuid.uuid4()),
            "mail_sha256": meta["mail_sha256"],
            "analyzed_at": now,
            "server_version": SERVER_VERSION,
            "catalog_version": CATALOG_VERSION,
            "completeness": completeness,
            "signals": signals[:MAX_SIGNALS],
            "decisions": result["decisions"],
            "auth": result["auth"],
            "feeds": self.feeds.states(now),
            "campaign_bands": result["campaign_bands"],
        }
        if len(json.dumps(response)) > MAX_RESPONSE - 4096:
            response["decisions"] = []
        return response

    def url_check(self, items: list[dict]) -> dict:
        results = []
        for item in items:
            host = normalize_domain(item["host"])
            listed = []
            if host is not None:
                listed = self.feeds.lookup(host, None)["listed"]
            listed = listed + [f for f in self.feeds.url_hash_listed(item["url_sha256"]) if f not in listed]
            signal = None
            if listed and host is not None:
                signal = validate_signal({"id": "LINK_FEED_HIT", "evidence": {
                    "domain": host, "feed": listed[0], "url_sha256": item["url_sha256"]}})
            results.append({"url_sha256": item["url_sha256"], "hit": bool(listed), "signal": signal})
        return {"results": results, "feeds": self.feeds.states()}

    async def backends(self) -> list:
        cached_at, cached = self._backend_cache
        if time.monotonic() - cached_at < 60 and cached:
            return cached
        try:
            status, doc = await httpclient.request_json("GET", f"{self.config.inference_url}/healthz", timeout=1.5)
            backends = []
            if status == 200:
                for b in doc.get("backends") or []:
                    if isinstance(b, dict) and isinstance(b.get("id"), str):
                        notice = b.get("licence_notice")
                        backends.append({"id": b["id"][:32], "enabled": bool(b.get("enabled")),
                                         "calibrated": bool(b.get("calibrated")),
                                         "licence_notice": notice[:300] if isinstance(notice, str) else None})
            self._backend_cache = (time.monotonic(), backends)
            return backends
        except httpclient.HttpError:
            return cached

    async def health(self) -> dict:
        return {"status": "ok" if self.zygote.alive() else "degraded", "feeds": self.feeds.states(),
                "backends": await self.backends()}


# Validation of worker output -------------------------------------------------------------------------------

def validate_answer(ans) -> dict | None:
    if not isinstance(ans, dict):
        return None
    qid = ans.get("id")
    if not isinstance(qid, str) or not re.match(r"^[a-z][a-z0-9_]{0,63}$", qid):
        return None
    if ans.get("type") not in ("choice", "noul", "score"):
        return None
    out = {"id": qid, "type": ans["type"]}
    for key in ("p_yes", "expected"):
        value = ans.get(key)
        if value is not None and (isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 100):
            return None
        out[key] = None if value is None else float(value)
    if out["p_yes"] is not None and out["p_yes"] > 1:
        return None
    probs = ans.get("probabilities")
    if probs is not None:
        if not isinstance(probs, dict) or len(probs) > 16 or not all(
                isinstance(k, str) and len(k) <= 32 and isinstance(v, (int, float)) and not isinstance(v, bool)
                and 0 <= v <= 1 for k, v in probs.items()):
            return None
        probs = {k: float(v) for k, v in probs.items()}
    out["probabilities"] = probs
    dist = ans.get("distribution")
    if dist is not None:
        if not isinstance(dist, list) or len(dist) > 16 or not all(
                isinstance(v, (int, float)) and not isinstance(v, bool) and 0 <= v <= 1 for v in dist):
            return None
        dist = [float(v) for v in dist]
    out["distribution"] = dist
    backend = ans.get("backend")
    version = ans.get("model_version")
    if backend not in framing.KNOWN_BACKENDS or not isinstance(version, str) or len(version) > 64:
        return None
    abstain = ans.get("abstain")
    if abstain is not None and (not isinstance(abstain, str) or not re.match(r"^[a-z_0-9]{1,40}$", abstain)):
        return None
    out.update({"backend": backend, "model_version": version, "calibrated": bool(ans.get("calibrated")),
                "abstain": abstain})
    return out


def validate_result(result) -> dict | None:
    """Strict schema check of a worker result (a compromised worker must not shape the response freely)."""
    if not isinstance(result, dict):
        return None
    comp = result.get("completeness")
    if not isinstance(comp, dict) or any(comp.get(s) not in _STAGE_VALUES for s in _STAGES):
        return None
    signals = result.get("signals")
    if not isinstance(signals, list) or len(signals) > MAX_SIGNALS:
        return None
    clean_signals = []
    for sig in signals:
        clean = validate_signal(sig)
        if clean is None or clean["id"] == "ANALYSIS_PARTIAL" and clean.get("evidence"):
            return None
        clean_signals.append(clean)
    decisions = result.get("decisions")
    if not isinstance(decisions, list) or len(decisions) > 32:
        return None
    clean_decisions = []
    for dec in decisions:
        clean = validate_answer(dec)
        if clean is None:
            return None
        clean_decisions.append(clean)
    auth = result.get("auth")
    if not isinstance(auth, dict) or not isinstance(auth.get("dkim"), list) or len(auth["dkim"]) > 3:
        return None
    dkim = []
    for entry in auth["dkim"]:
        if not isinstance(entry, dict) or entry.get("result") not in ("pass", "fail", "unverifiable"):
            return None
        if validate_evidence({"domain": entry.get("d")}) is None or not isinstance(entry.get("s"), str) \
                or not re.match(r"^[a-z0-9_.-]{1,63}$", entry["s"]):
            return None
        dkim.append({"d": entry["d"], "s": entry["s"], "result": entry["result"], "aligned": bool(entry.get("aligned")),
                     "l_partial": bool(entry.get("l_partial"))})
    dmarc = auth.get("dmarc")
    if dmarc is not None:
        if not isinstance(dmarc, dict) or validate_evidence({"domain": dmarc.get("domain")}) is None \
                or dmarc.get("policy") not in ("none", "quarantine", "reject", "absent") \
                or dmarc.get("result") not in ("pass", "fail", "none"):
            return None
        dmarc = {"domain": dmarc["domain"], "policy": dmarc["policy"], "testing": bool(dmarc.get("testing")),
                 "result": dmarc["result"]}
    bands = result.get("campaign_bands")
    if bands is not None and (not isinstance(bands, list) or len(bands) != 4
                              or not all(isinstance(b, str) and _BAND.match(b) for b in bands)):
        return None
    return {"completeness": {s: comp[s] for s in _STAGES}, "signals": clean_signals, "decisions": clean_decisions,
            "auth": {"dkim": dkim, "dmarc": dmarc}, "campaign_bands": bands}
