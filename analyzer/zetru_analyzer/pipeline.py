"""Analysis of one mail (runs inside the sandboxed worker). All outside information — DNS TXT records,
feed lookups, domain ages and typed decisions — is requested through a `Broker` in two batched rounds;
the supervisor performs and budgets them. The result never contains text taken from the mail.

Failure rules (security review PY-01, PY-02, PY-05, PY-09; DECISIONS.md "Security review"):
- every stage runs under `_Stage`: an unexpected exception marks that stage `failed`, adds `MIME_MALFORMED`
  and `MIME_LIMITS`, and the remaining stages still run. Content can therefore never turn a mail into an
  "analyzer unavailable" error, and a crash never makes a mail look better than "incomplete with a caution";
- links are never dropped silently: every distinct host is kept (at most 10 URLs each); a mail with more than
  1,000 distinct URL candidates is `urls: partial` with `MIME_LIMITS`; a feed or domain-age budget that cannot
  cover every host/domain makes the result `urls: partial`;
- attachment inspection stops when the worker has used 6 s of CPU (`attachments: partial` + `MIME_LIMITS`).
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Protocol

from . import attachments, dkimverify, dmarc, htmltext, logs, lookalike, mimeparse, rawmail, simhash, state, urls
from .domains import PublicSuffixList, is_subdomain_or_equal, normalize_domain
from .packs import Packs
from .signals import CATEGORY_SIGNALS, NOUL_SIGNALS, SIGNAL_THRESHOLD, SignalSet
from .textpatterns import find_phones, has_amount, normalize_visible, obfuscated_words

MAX_DKIM_SIGNATURES = 3
FEED_BUDGET = 40
AGE_BUDGET = 6
MAX_LINK_AGE_DOMAINS = 5
MAX_LINK_CANDIDATES = 1000      # distinct raw URL strings canonicalised per mail
MAX_URLS_PER_HOST = 10          # further URLs of a host add nothing: every check is per host or domain
MAX_TEXT_URLS = 500
NEW_DOMAIN_DAYS = 30
REPLAY_SECONDS = 24 * 3600
ATTACHMENT_CPU_BUDGET_S = 6.0   # worker CPU seconds after which no further attachment is inspected
PHONE_WINDOW_CHARS = 100_000    # callback check: phone numbers in the first and last 100,000 characters


class Broker(Protocol):
    def request(self, *, dns: list[str] | None = None, feeds: list[dict] | None = None,
                ages: list[str] | None = None, decide: dict | None = None) -> dict:
        ...


@dataclass
class Context:
    meta: dict
    policy: dict
    psl: PublicSuffixList
    packs: Packs
    now: int = field(default_factory=lambda: int(time.time()))


def empty_completeness() -> dict:
    return {"parse": "ok", "auth": "ok", "urls": "ok", "attachments": "ok", "domain_age": "ok",
            "feeds": "ok", "classifier": "ok", "complete": False}


def failure_result(reason: str) -> dict:
    """Result for a mail that could not be parsed or crashed the worker (no trust can be derived)."""
    sigs = SignalSet()
    sigs.add("MIME_MALFORMED")
    if reason == "resources":
        sigs.add("MIME_LIMITS")
    completeness = {"parse": "failed", "auth": "skipped", "urls": "skipped", "attachments": "skipped",
                    "domain_age": "skipped", "feeds": "skipped", "classifier": "skipped", "complete": False}
    return {"completeness": completeness, "signals": sigs.items(), "decisions": [],
            "auth": {"dkim": [], "dmarc": None}, "campaign_bands": None}


_WORSE = {"ok": 0, "skipped": 0, "abstained": 1, "partial": 2, "failed": 3}


def _mark(comp: dict, stage: str, value: str) -> None:
    """Sets a stage to `value` unless it is already worse."""
    if _WORSE.get(value, 0) >= _WORSE.get(comp.get(stage, "ok"), 0):
        comp[stage] = value


class _Stage:
    """Context manager around one analysis stage: an exception inside marks the stage, adds MIME_MALFORMED and
    MIME_LIMITS, is logged with class and stage only, and is suppressed so that the next stage runs."""

    def __init__(self, comp: dict, sigs: SignalSet, stage: str, value: str = "failed"):
        self.comp, self.sigs, self.stage, self.value = comp, sigs, stage, value

    def __enter__(self) -> "_Stage":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        if exc_type is None or not issubclass(exc_type, Exception):
            return False
        _mark(self.comp, self.stage, self.value)
        self.sigs.add("MIME_MALFORMED")
        self.sigs.add("MIME_LIMITS")
        logs.error("stage_failed", stage=self.stage, error_class=exc_type.__name__)
        return True


def _provider_dkim_passes(headers: list[rawmail.RawHeader]) -> set[str]:
    """Domains the topmost Authentication-Results header reports as DKIM pass. Used only to attribute a
    failing signature to modification in the store (AUTH_DKIM_BODY_MODIFIED), never to raise trust."""
    top = rawmail.first(headers, "authentication-results")
    if top is None:
        return set()
    out = set()
    for clause in top.value().split(";"):
        if re.match(r"\s*dkim\s*=\s*pass\b", clause, re.I):
            m = re.search(r"header\.(?:d|i)\s*=\s*@?([A-Za-z0-9.\-_]+)", clause)
            if m:
                d = normalize_domain(m.group(1))
                if d:
                    out.add(d)
    return out


def _is_list_mail(mail: mimeparse.ParsedMail) -> bool:
    if any(mail.has_header(h) for h in ("list-id", "list-unsubscribe", "list-post", "mailing-list")):
        return True
    return any(v.strip().lower() in ("bulk", "list", "junk") for v in mail.header_values("precedence"))


def _delivery_time(mail: mimeparse.ParsedMail, meta: dict) -> int | None:
    if isinstance(meta.get("received_at"), int):
        return meta["received_at"]
    top = rawmail.first(mail.headers, "received")
    if top is None:
        return None
    from email.utils import parsedate_to_datetime

    value = top.value().rsplit(";", 1)
    if len(value) != 2:
        return None
    try:
        return int(parsedate_to_datetime(value[1].strip()).timestamp())
    except (TypeError, ValueError, IndexError, OverflowError):
        return None


class _LinkCollector:
    """Canonicalises URL candidates once each, unwraps redirectors and keeps every distinct host (at most
    MAX_URLS_PER_HOST URLs per host). `overflow` is set when candidates beyond MAX_LINK_CANDIDATES are left."""

    def __init__(self, psl: PublicSuffixList, packs: Packs):
        self.psl, self.packs = psl, packs
        self.links: list[urls.Link] = []
        self.unwrapped_of: dict[str, urls.Link] = {}
        self._seen_urls: set[str] = set()
        self._by_raw: dict[str, urls.Link | None] = {}
        self._per_host: dict[str, int] = {}
        self.overflow = False

    def add(self, raw, source: str, anchor_text: str = "", hidden: bool = False) -> urls.Link | None:
        if not isinstance(raw, str):
            return None
        if raw in self._by_raw:
            return self._by_raw[raw]
        if len(self._by_raw) >= MAX_LINK_CANDIDATES:
            self.overflow = True
            return None
        link = urls.make_link(raw, source, self.psl, anchor_text, hidden)
        self._by_raw[raw] = link
        if link is not None:
            self._keep(link)
        return link

    def _room(self, host: str) -> bool:
        count = self._per_host.get(host, 0)
        if count >= MAX_URLS_PER_HOST:
            return False
        self._per_host[host] = count + 1
        return True

    def _keep(self, link: urls.Link) -> None:
        if link.url in self._seen_urls:
            return
        self._seen_urls.add(link.url)
        if self._room(link.host):
            self.links.append(link)
        unwrapped = urls.unwrap(link.url, link.host, self.packs)
        if unwrapped and unwrapped[0] not in self._seen_urls:
            canonical, host, is_ip = unwrapped
            self._seen_urls.add(canonical)
            inner = urls.Link(url=canonical, host=host, reg_domain=None if is_ip else self.psl.registrable_domain(host),
                              url_sha256=urls.url_sha256(canonical), source="unwrapped",
                              anchor_text=link.anchor_text, hidden=link.hidden, is_ip=is_ip, via=link.host)
            if self._room(host):
                self.links.append(inner)
                self.unwrapped_of[link.url] = inner


def _link_priority(link: urls.Link, packs: Packs) -> int:
    """Order for the feed and age budgets: what the reader can act on first, infrastructure last."""
    if packs.is_esp_tracker(link.host) or packs.official_brand(link.host, link.reg_domain) is not None:
        return 3
    if link.hidden:
        return 2
    if link.source in ("qr", "form", "unwrapped"):
        return 0
    return 1


def _ordered_hosts(links: list[urls.Link], packs: Packs) -> list[urls.Link]:
    """The first link of every host, highest priority first, document order within a priority."""
    first: dict[str, tuple[int, int, urls.Link]] = {}
    for index, link in enumerate(links):
        priority = _link_priority(link, packs)
        known = first.get(link.host)
        if known is None or priority < known[0]:
            first[link.host] = (priority, known[1] if known else index, link)
    return [entry[2] for entry in sorted(first.values(), key=lambda e: (e[0], e[1]))]


def analyze(raw: bytes, ctx: Context, broker: Broker) -> dict:
    cpu_start = time.process_time()
    try:
        mail = mimeparse.parse(raw)
    except mimeparse.ParseError:
        return failure_result("parse")
    psl, packs = ctx.psl, ctx.packs
    sigs = SignalSet()
    comp = empty_completeness()
    if mail.limits_exceeded or mail.text_truncated:
        comp["parse"] = "partial"
    if mail.limits_exceeded:
        sigs.add("MIME_LIMITS")

    # Sender ----------------------------------------------------------------------------------------------
    sender = mail.from_addr
    from_domain = sender.domain if sender else None
    from_org = psl.registrable_domain(from_domain) if from_domain else None
    display = sender.display if sender else ""
    local = sender.local if sender else ""
    # More or fewer than one From field or mailbox (e.g. an unsigned From placed above a signed one): no
    # signature is aligned and DMARC is reported as failed (RFC 7489 §6.6.1, RFC 6376 §8.15; PY-13).
    sender_malformed = mail.sender_malformed
    if sender_malformed:
        sigs.add("MIME_MALFORMED")

    # Visible text, hidden text ------------------------------------------------------------------------------
    html_results: list[htmltext.HtmlResult] = []
    plain = ""
    visible_raw = state_text = visible = ""
    with _Stage(comp, sigs, "parse", "partial"):
        html_results = [htmltext.extract(h) for h in mail.html_texts]
        plain = "\n".join(mail.plain_texts)
        if html_results:
            visible_raw = "\n".join(r.raw_visible for r in html_results)
            state_text = "\n".join(r.state_text for r in html_results)
        else:
            visible_raw = plain
            state_text = plain
        visible = normalize_visible(visible_raw)
        hidden = sum(r.hidden_chars for r in html_results)
        preheader = sum(r.preheader_hidden_chars for r in html_results)
        shown = sum(r.visible_chars for r in html_results)
        if hidden > 200 or (hidden >= 20 and hidden > preheader and hidden / max(1, hidden + shown) > 0.30):
            sigs.add("MIME_HIDDEN_TEXT", count=hidden)

    # Links ---------------------------------------------------------------------------------------------------
    collector = _LinkCollector(psl, packs)
    with _Stage(comp, sigs, "urls"):
        html_domains: set[str] = set()
        for r in html_results:
            for a in r.anchors:
                link = collector.add(a.href, "html", a.text, a.hidden)
                if link:
                    html_domains.add(link.reg_domain or link.host)
            for u in r.other_urls:
                collector.add(u, "form")
        plain_domains: set[str] = set()
        text_urls = urls.extract_from_text(plain, MAX_TEXT_URLS + 1)
        if len(text_urls) > MAX_TEXT_URLS:
            collector.overflow = True
        for u in text_urls[:MAX_TEXT_URLS]:
            link = collector.add(u, "text")
            if link:
                plain_domains.add(link.reg_domain or link.host)
        for payload in (ctx.meta.get("qr_payloads") or [])[:5]:
            collector.add(payload, "qr")
        if collector.overflow:
            _mark(comp, "urls", "partial")
            sigs.add("MIME_LIMITS")
        if html_domains and plain_domains:
            html_cmp = {d for d in html_domains if not packs.is_esp_tracker(d)}
            plain_cmp = {d for d in plain_domains if not packs.is_esp_tracker(d)}
            if html_cmp and plain_cmp and not (html_cmp & plain_cmp):
                sigs.add("MIME_PARTS_DIFFER", count=len(html_cmp ^ plain_cmp))
    links = collector.links
    unwrapped_of = collector.unwrapped_of

    # Round 1: DKIM keys, DMARC records, feed lookups -------------------------------------------------------
    all_sigs: list[dkimverify.Signature] = []
    chosen: list[dkimverify.Signature] = []
    walk: list[str] = []
    dns_names: list[str] = []
    sender_domains: list[str] = []
    feed_items: list[dict] = []
    with _Stage(comp, sigs, "auth"):
        all_sigs = dkimverify.parse_signatures(mail.headers)

        def is_aligned_psl(d: str) -> bool:
            return bool(from_org) and (d == from_org or d.endswith("." + from_org))

        chosen = sorted(all_sigs, key=lambda s: (0 if is_aligned_psl(s.d) else 1, s.index))[:MAX_DKIM_SIGNATURES]
        dns_names = [s.key_name for s in chosen]
        walk = dmarc.tree_walk(from_domain) if from_domain else []
        dns_names += ["_dmarc." + n for n in walk]
        if from_domain:
            dns_names.append(from_domain)
        dns_names = list(dict.fromkeys(dns_names))
    with _Stage(comp, sigs, "urls"):
        rp_domain = None
        if mail.return_path:
            rp_domain = normalize_domain(mail.return_path.rpartition("@")[2])
        sender_domains = [d for d in dict.fromkeys([from_domain, rp_domain] + [s.d for s in chosen]) if d]
        for d in sender_domains:
            feed_items.append({"host": d, "reg": psl.registrable_domain(d)})
        for link in _ordered_hosts([l for l in links if not l.is_ip], packs):
            if link.host in sender_domains:
                continue
            if len(feed_items) >= FEED_BUDGET:
                _mark(comp, "urls", "partial")
                break
            feed_items.append({"host": link.host, "reg": psl.registrable_domain(link.host)})
    round1 = broker.request(dns=dns_names, feeds=feed_items)
    dns_results: dict = round1.get("dns") or {}
    feed_results: list = round1.get("feeds") or []
    if round1.get("feeds_status") == "partial":
        _mark(comp, "urls", "partial")

    def txt(name: str) -> tuple[str, list[str]]:
        entry = dns_results.get(name) or {}
        return entry.get("status", "error"), list(entry.get("txt") or [])

    # DKIM and DMARC ------------------------------------------------------------------------------------------
    dkim_results: list[tuple[dkimverify.Signature, dkimverify.SigResult]] = []
    dmarc_obj = None
    outcome = None
    auth_dkim: list[dict] = []
    aligned_pass = False
    with _Stage(comp, sigs, "auth"):
        provider_passes = _provider_dkim_passes(mail.headers)
        dns_trouble = False
        for s in chosen:
            status, records = txt(s.key_name)
            if status not in ("ok", "nxdomain", "nodata"):
                dns_trouble = True
            dkim_results.append((s, dkimverify.verify(s, mail.headers, mail.body_raw, records, status, now=ctx.now)))
        modified = {r.d for _, r in dkim_results if r.result == "fail" and r.d in provider_passes}

        policy = None
        if from_domain:
            lookups = {n: txt("_dmarc." + n) for n in walk}
            exists_status, _ = txt(from_domain)
            from_exists = None if exists_status not in ("ok", "nodata", "nxdomain") else exists_status != "nxdomain"
            policy = dmarc.discover(from_domain, lookups, from_exists)
            outcome = dmarc.evaluate(from_domain, policy, psl, [(r.d, r.result) for _, r in dkim_results],
                                     mail.return_path, modified)
            if policy.status == "temperror":
                dns_trouble = True
            result = "fail" if sender_malformed else outcome.result
            dmarc_obj = {"domain": from_domain, "policy": policy.published, "testing": policy.testing,
                         "result": result}
            if outcome.signal and not sender_malformed:
                sigs.add(outcome.signal, domain=from_domain)
        else:
            comp["auth"] = "skipped"
        if dns_trouble and comp["auth"] == "ok":
            comp["auth"] = "partial"
        if dns_names and all(txt(n)[0] in ("denied", "error") for n in dns_names) and comp["auth"] != "skipped":
            comp["auth"] = "failed"

        org_for_align = (policy.org_domain if policy and policy.org_domain else None) or from_org

        def aligned(d: str) -> bool:
            return not sender_malformed and bool(org_for_align) and (d == org_for_align or d.endswith("." + org_for_align))

        for s, r in dkim_results:
            is_aligned = aligned(r.d)
            auth_dkim.append({"d": r.d, "s": r.s, "result": r.result, "aligned": is_aligned, "l_partial": r.l_partial})
            if r.result == "pass" and is_aligned:
                aligned_pass = True
                if r.l_partial:
                    sigs.add("AUTH_DKIM_PARTIAL_L", domain=r.d)
                signed = set(s.h)
                lu = rawmail.first(mail.headers, "list-unsubscribe")
                lup = rawmail.first(mail.headers, "list-unsubscribe-post")
                if ({"list-unsubscribe", "list-unsubscribe-post"} <= signed and lu is not None and lup is not None
                        and "list-unsubscribe=one-click" in lup.value().lower().replace(" ", "")
                        and "<https:" in lu.value().lower()):
                    sigs.add("BULK_RFC8058_SIGNED", domain=r.d)
            if r.d in modified:
                sigs.add("AUTH_DKIM_BODY_MODIFIED", domain=r.d)
        # Replay: a valid signature much older than delivery, user not addressed, not a list mail.
        delivered = _delivery_time(mail, ctx.meta)
        if mail.delivered_to and delivered and not _is_list_mail(mail):
            addressed = {a.addr.lower() for a in mail.to_cc}
            if mail.delivered_to not in addressed:
                for s, r in dkim_results:
                    if r.result == "pass" and s.t is not None and delivered - s.t > REPLAY_SECONDS:
                        sigs.add("AUTH_REPLAY_SUSPECT", domain=r.d)
                        break

    # Feeds ----------------------------------------------------------------------------------------------------
    popular: set[str] = set()
    with _Stage(comp, sigs, "urls"):
        for item, res in zip(feed_items, feed_results):
            if not isinstance(res, dict):
                continue
            host = item["host"]
            if res.get("popular"):
                popular.add(item.get("reg") or host)
            for feed_id in res.get("listed") or []:
                if host in sender_domains:
                    sigs.add("FEED_SENDER_HIT", domain=host, feed=feed_id)
                for link in links:
                    if link.host == host:
                        sigs.add("LINK_FEED_HIT", domain=host, feed=feed_id, url_sha256=link.url_sha256)
                        break
            if res.get("disposable") and host == from_domain:
                sigs.add("ID_DOMAIN_DISPOSABLE", domain=from_domain)
        if len(feed_results) < len(feed_items):
            _mark(comp, "urls", "partial")

    # Identity: brand look-alikes and brand names from unofficial senders ------------------------------------
    with _Stage(comp, sigs, "auth"):
        if from_domain:
            hit = lookalike.brand_lookalike(from_domain, psl, packs)
            if hit:
                sigs.add("ID_LOOKALIKE_BRAND", domain=from_domain, ref_domain=hit.ref_domain, brand=hit.brand)
            mentioned = packs.brands_mentioned(display, local)
            if mentioned and not any(b.is_official_sender(from_domain, from_org) for b in mentioned):
                sigs.add("ID_BRAND_NOT_OFFICIAL", domain=from_domain, brand=mentioned[0].key)

    # Links: look-alikes and user-generated hosting -----------------------------------------------------------
    with _Stage(comp, sigs, "urls"):
        flagged_lookalike: set[str] = set()
        checked_hosts: set[str] = set()
        flagged_ugc: set[str] = set()
        for link in links:
            if link.is_ip:
                continue
            domain = link.reg_domain or link.host
            if domain not in flagged_lookalike and link.host not in checked_hosts:
                checked_hosts.add(link.host)
                hit = lookalike.brand_lookalike(link.host, psl, packs)
                if hit:
                    flagged_lookalike.add(domain)
                    sigs.add("LINK_LOOKALIKE", domain=domain, ref_domain=hit.ref_domain, brand=hit.brand,
                             url_sha256=link.url_sha256)
            if packs.is_ugc(link.host) and link.host not in flagged_ugc:
                flagged_ugc.add(link.host)
                sigs.add("LINK_UGC_HOSTING", domain=link.host, url_sha256=link.url_sha256)

    # Attachments ---------------------------------------------------------------------------------------------
    attach_labels: list[str] = []
    with _Stage(comp, sigs, "attachments"):
        for part in mail.parts:
            if part.is_body_text:
                continue
            if time.process_time() - cpu_start > ATTACHMENT_CPU_BUDGET_S:
                _mark(comp, "attachments", "partial")
                sigs.add("MIME_LIMITS")
                break
            try:
                report = attachments.inspect(part.path, part.filename, part.content_type, part.payload, packs)
            except Exception as exc:  # inspect guards its own steps; this is the last line of defence
                report = attachments.AttachmentReport(path=part.path, real_type="unknown", label="unknown",
                                                      partial=True, failed=True)
                logs.error("stage_failed", stage="attachment", error_class=type(exc).__name__)
            if report.partial:
                _mark(comp, "attachments", "partial")
            if report.failed:
                sigs.add("MIME_LIMITS", part=part.path)   # an attachment the server could not finish is a caution
            if part.disposition == "attachment" or part.filename or report.signals:
                attach_labels.append(report.label)
            for sid, evidence in report.signals.items():
                sigs.add(sid, part=part.path, **evidence)

    # Word obfuscation ------------------------------------------------------------------------------------------
    with _Stage(comp, sigs, "parse", "partial"):
        brand_terms = frozenset(t for b in packs.brands for t in (b.key, *b.labels) if t.isalpha() and len(t) >= 4)
        obfuscated = obfuscated_words(visible_raw + "\n" + mail.subject + "\n" + display, brand_terms)
        if obfuscated:
            brand_hit = next((b.key for b in packs.brands for t in obfuscated if t in (b.key, *b.labels)), None)
            sigs.add("ACCT_WORD_OBFUSCATION", count=len(obfuscated), brand=brand_hit)

    # Round 2: domain ages and typed decisions -----------------------------------------------------------------
    age_domains: list[str] = []
    sender_age_domain = None
    decide = None
    ocr = ctx.meta.get("ocr_text") if isinstance(ctx.meta.get("ocr_text"), str) else None
    with _Stage(comp, sigs, "domain_age"):
        if from_org and from_org not in popular and not packs.is_freemail(from_domain) \
                and packs.official_brand(from_domain, from_org) is None:
            sender_age_domain = from_org
            age_domains.append(from_org)
        link_age: list[str] = []
        for link in sorted(links, key=lambda l: (1 if l.hidden else 0)):   # visible first, then document order
            d = link.reg_domain
            if (not d or d in popular or d in age_domains or d in link_age or packs.is_ugc(link.host)
                    or packs.is_shortener(link.host) or packs.is_esp_tracker(link.host)
                    or packs.official_brand(link.host, d) is not None):
                continue
            link_age.append(d)
        if len(link_age) > MAX_LINK_AGE_DOMAINS:
            # Not every link domain gets an age lookup: the result cannot be complete.
            _mark(comp, "urls", "partial")
            _mark(comp, "domain_age", "partial")
        age_domains = (age_domains + link_age[:MAX_LINK_AGE_DOMAINS])[:AGE_BUDGET]
    with _Stage(comp, sigs, "classifier"):
        flags = []
        if packs.is_freemail(from_domain):
            flags.append("freemail")
        if any(psl.registrable_domain(a.domain) != from_org for a in mail.reply_to if a.domain) and mail.reply_to:
            flags.append("replyto-differs")
        if _is_list_mail(mail):
            flags.append("bulk")
        auth_word = "aligned-pass" if aligned_pass else (
            "fail" if sender_malformed or (outcome and outcome.result == "fail") else "none")
        state_links = []
        for link in links:
            if link.source not in ("html", "qr", "text") or link.hidden:
                continue
            final = unwrapped_of.get(link.url, link)
            shown_domain = urls.domain_in_text(link.anchor_text) if link.anchor_text else None
            target = final.reg_domain or final.host
            mismatch = bool(shown_domain) and (psl.registrable_domain(shown_domain) or shown_domain) != target \
                and not packs.is_esp_tracker(link.host)
            text = link.anchor_text if link.source == "html" else ("QR" if link.source == "qr" else "")
            state_links.append((re.sub(r"(?i)https?://", "", text), target, mismatch))
            if len(state_links) >= state.MAX_LINKS:
                break
        rendered = state.render(display, from_domain, flags, auth_word, mail.subject, state.body_tokens(state_text),
                                state_links, list(dict.fromkeys(attach_labels)), ocr)
        backends = [b for b in (ctx.policy.get("backends") or []) if isinstance(b, str)]
        if backends:
            decide = {"state": rendered, "state_version": state.state_version(), "language_hint": None,
                      "questions": state.QUESTIONS, "policy": {"backends": backends}}
    if decide is None and comp["classifier"] == "ok":
        comp["classifier"] = "skipped"
    round2 = broker.request(ages=age_domains, decide=decide)

    # Domain ages ------------------------------------------------------------------------------------------------
    with _Stage(comp, sigs, "domain_age"):
        ages: dict = round2.get("ages") or {}
        statuses = []
        for d in age_domains:
            entry = ages.get(d) or {}
            status = entry.get("status", "error")
            statuses.append(status)
            registered = entry.get("registered_on")
            if status != "ok" or not isinstance(registered, int) or registered > ctx.now + 86400:
                continue
            age_days = max(0, (ctx.now - registered) // 86400)
            if age_days < NEW_DOMAIN_DAYS:
                if d == sender_age_domain:
                    sigs.add("ID_DOMAIN_NEW", domain=from_domain, age_days=age_days)
                else:
                    url_hash = next((l.url_sha256 for l in links if l.reg_domain == d), None)
                    sigs.add("LINK_DOMAIN_NEW", domain=d, age_days=age_days, url_sha256=url_hash)
        if any(s not in ("ok", "unknown") for s in statuses):
            _mark(comp, "domain_age", "failed")   # lookup errors: a missing answer must not count as complete
        elif any(s == "unknown" for s in statuses):
            _mark(comp, "domain_age", "partial")  # registry returned no date (allowed for completeness)

    # Typed decisions ---------------------------------------------------------------------------------------------
    decisions_out: list[dict] = []
    answers_by_id: dict[str, dict] = {}
    if decide is not None:
        with _Stage(comp, sigs, "classifier"):
            result = round2.get("decide") or {}
            if result.get("status") != "ok":
                comp["classifier"] = "failed"
            else:
                abstained = False
                for ans in result.get("answers") or []:
                    decision = {k: ans.get(k) for k in ("id", "type", "p_yes", "probabilities", "distribution",
                                                         "expected", "backend", "model_version", "calibrated", "abstain")}
                    decisions_out.append(decision)
                    answers_by_id[decision["id"]] = decision
                    if decision.get("abstain") and decision["abstain"] != "state_truncated_over_50pct":
                        abstained = True
                        continue
                    p_yes = decision.get("p_yes")
                    if decision["id"] in NOUL_SIGNALS and isinstance(p_yes, (int, float)) and p_yes >= SIGNAL_THRESHOLD:
                        sigs.add(NOUL_SIGNALS[decision["id"]], p=float(p_yes))
                    if decision["id"] == "category" and isinstance(decision.get("probabilities"), dict):
                        for label, sid in CATEGORY_SIGNALS.items():
                            p = decision["probabilities"].get(label)
                            if isinstance(p, (int, float)) and p >= SIGNAL_THRESHOLD:
                                sigs.add(sid, p=float(p))
                if abstained:
                    _mark(comp, "classifier", "abstained")
                    sigs.add("CLS_ABSTAIN")

    # Callback lure: phone number + callback request + (brand or charge) from a sender that is not the brand.
    with _Stage(comp, sigs, "classifier"):
        callback = answers_by_id.get("asks_callback", {})
        callback_p = callback.get("p_yes") if not callback.get("abstain") else None
        if isinstance(callback_p, (int, float)) and callback_p >= SIGNAL_THRESHOLD:
            phone_text = visible + "\n" + (ocr or "")
            if len(phone_text) > 2 * PHONE_WINDOW_CHARS:   # the state shows the head and the tail of the text
                phone_text = phone_text[:PHONE_WINDOW_CHARS] + "\n" + phone_text[-PHONE_WINDOW_CHARS:]
            if find_phones(phone_text):
                mentioned = packs.brands_mentioned(mail.subject + "\n" + display + "\n" + phone_text[:20000])
                unofficial = [b for b in mentioned if not b.is_official_sender(from_domain, from_org)]
                charge = has_amount(phone_text)
                weak_sender = packs.is_freemail(from_domain) or not aligned_pass
                if (mentioned and len(unofficial) == len(mentioned)) or (charge and weak_sender):
                    sigs.add("PHONE_CALLBACK_LURE", brand=unofficial[0].key if unofficial else None)

    # Campaign fingerprint -------------------------------------------------------------------------------------
    bands = None
    with _Stage(comp, sigs, "parse", "partial"):
        link_domains = [l.reg_domain for l in links if l.reg_domain]
        bands = simhash.bands(visible, link_domains)

    comp["complete"] = False  # set by the supervisor after merging feed state
    return {"completeness": comp, "signals": sigs.items(), "decisions": decisions_out,
            "auth": {"dkim": auth_dkim, "dmarc": dmarc_obj}, "campaign_bands": bands}


def is_official_link(host: str, packs: Packs) -> bool:
    return any(is_subdomain_or_equal(host, d) for d in packs.all_official)
