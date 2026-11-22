"""Analysis of one mail (runs inside the sandboxed worker). All outside information — DNS TXT records,
feed lookups, domain ages and typed decisions — is requested through a `Broker` in two batched rounds;
the supervisor performs and budgets them. The result never contains text taken from the mail."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Protocol

from . import attachments, dkimverify, dmarc, htmltext, lookalike, mimeparse, rawmail, simhash, state, urls
from .domains import PublicSuffixList, is_subdomain_or_equal, normalize_domain
from .packs import Packs
from .signals import CATEGORY_SIGNALS, NOUL_SIGNALS, SIGNAL_THRESHOLD, SignalSet
from .textpatterns import find_phones, has_amount, normalize_visible, obfuscated_words

MAX_DKIM_SIGNATURES = 3
FEED_BUDGET = 40
AGE_BUDGET = 6
MAX_LINK_AGE_DOMAINS = 5
MAX_LINKS = 200
NEW_DOMAIN_DAYS = 30
REPLAY_SECONDS = 24 * 3600


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


def analyze(raw: bytes, ctx: Context, broker: Broker) -> dict:
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

    # Visible text, hidden text, links ------------------------------------------------------------------
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

    links: list[urls.Link] = []
    seen_urls: set[str] = set()
    unwrapped_of: dict[str, urls.Link] = {}

    def add_link(link: urls.Link | None) -> None:
        if link is None or link.url in seen_urls or len(links) >= MAX_LINKS:
            return
        seen_urls.add(link.url)
        links.append(link)
        unwrapped = urls.unwrap(link.url, link.host, packs)
        if unwrapped and unwrapped[0] not in seen_urls and len(links) < MAX_LINKS:
            canonical, host, is_ip = unwrapped
            seen_urls.add(canonical)
            inner = urls.Link(url=canonical, host=host, reg_domain=None if is_ip else psl.registrable_domain(host),
                              url_sha256=urls.url_sha256(canonical), source="unwrapped",
                              anchor_text=link.anchor_text, hidden=link.hidden, is_ip=is_ip, via=link.host)
            links.append(inner)
            unwrapped_of[link.url] = inner

    html_domains: set[str] = set()
    for r in html_results:
        for a in r.anchors:
            link = urls.make_link(a.href, "html", psl, a.text, a.hidden)
            if link:
                html_domains.add(link.reg_domain or link.host)
            add_link(link)
        for u in r.other_urls:
            add_link(urls.make_link(u, "form", psl))
    plain_domains: set[str] = set()
    for u in urls.extract_from_text(plain):
        link = urls.make_link(u, "text", psl)
        if link:
            plain_domains.add(link.reg_domain or link.host)
        add_link(link)
    for payload in (ctx.meta.get("qr_payloads") or [])[:5]:
        add_link(urls.make_link(payload, "qr", psl))
    if html_domains and plain_domains:
        html_cmp = {d for d in html_domains if not packs.is_esp_tracker(d)}
        plain_cmp = {d for d in plain_domains if not packs.is_esp_tracker(d)}
        if html_cmp and plain_cmp and not (html_cmp & plain_cmp):
            sigs.add("MIME_PARTS_DIFFER", count=len(html_cmp ^ plain_cmp))

    # Round 1: DKIM keys, DMARC records, feed lookups -------------------------------------------------------
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

    rp_domain = None
    if mail.return_path:
        rp_domain = normalize_domain(mail.return_path.rpartition("@")[2])
    sender_domains = [d for d in dict.fromkeys([from_domain, rp_domain] + [s.d for s in chosen]) if d]
    feed_items: list[dict] = []
    for d in sender_domains:
        feed_items.append({"host": d, "reg": psl.registrable_domain(d)})
    link_hosts = list(dict.fromkeys(l.host for l in links if not l.is_ip))
    for host in link_hosts:
        if len(feed_items) >= FEED_BUDGET:
            comp["urls"] = "partial"
            break
        if host not in sender_domains:
            feed_items.append({"host": host, "reg": psl.registrable_domain(host)})
    round1 = broker.request(dns=dns_names, feeds=feed_items)
    dns_results: dict = round1.get("dns") or {}
    feed_results: list = round1.get("feeds") or []
    if round1.get("feeds_status") == "partial":
        comp["urls"] = "partial"

    def txt(name: str) -> tuple[str, list[str]]:
        entry = dns_results.get(name) or {}
        return entry.get("status", "error"), list(entry.get("txt") or [])

    # DKIM ---------------------------------------------------------------------------------------------------
    provider_passes = _provider_dkim_passes(mail.headers)
    dkim_results: list[tuple[dkimverify.Signature, dkimverify.SigResult]] = []
    dns_trouble = False
    for s in chosen:
        status, records = txt(s.key_name)
        if status not in ("ok", "nxdomain", "nodata"):
            dns_trouble = True
        dkim_results.append((s, dkimverify.verify(s, mail.headers, mail.body_raw, records, status, now=ctx.now)))
    modified = {r.d for _, r in dkim_results if r.result == "fail" and r.d in provider_passes}

    # DMARC ---------------------------------------------------------------------------------------------------
    dmarc_obj = None
    policy = None
    outcome = None
    if from_domain:
        lookups = {n: txt("_dmarc." + n) for n in walk}
        exists_status, _ = txt(from_domain)
        from_exists = None if exists_status not in ("ok", "nodata", "nxdomain") else exists_status != "nxdomain"
        policy = dmarc.discover(from_domain, lookups, from_exists)
        outcome = dmarc.evaluate(from_domain, policy, psl, [(r.d, r.result) for _, r in dkim_results],
                                 mail.return_path, modified)
        if policy.status == "temperror":
            dns_trouble = True
        dmarc_obj = {"domain": from_domain, "policy": policy.published, "testing": policy.testing,
                     "result": outcome.result}
        if outcome.signal:
            sigs.add(outcome.signal, domain=from_domain)
    else:
        comp["auth"] = "skipped"
    if dns_trouble and comp["auth"] == "ok":
        comp["auth"] = "partial"
    if dns_names and all(txt(n)[0] in ("denied", "error") for n in dns_names) and comp["auth"] != "skipped":
        comp["auth"] = "failed"

    org_for_align = (policy.org_domain if policy and policy.org_domain else None) or from_org

    def aligned(d: str) -> bool:
        return bool(org_for_align) and (d == org_for_align or d.endswith("." + org_for_align))

    auth_dkim = []
    aligned_pass = False
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
        comp["urls"] = "partial"

    # Identity: brand look-alikes and brand names from unofficial senders ------------------------------------
    if from_domain:
        hit = lookalike.brand_lookalike(from_domain, psl, packs)
        if hit:
            sigs.add("ID_LOOKALIKE_BRAND", domain=from_domain, ref_domain=hit.ref_domain, brand=hit.brand)
        mentioned = packs.brands_mentioned(display, local)
        if mentioned and not any(b.is_official_sender(from_domain, from_org) for b in mentioned):
            sigs.add("ID_BRAND_NOT_OFFICIAL", domain=from_domain, brand=mentioned[0].key)

    # Links: look-alikes and user-generated hosting -----------------------------------------------------------
    flagged_lookalike: set[str] = set()
    flagged_ugc: set[str] = set()
    for link in links:
        if link.is_ip:
            continue
        domain = link.reg_domain or link.host
        if domain not in flagged_lookalike:
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
    for part in mail.parts:
        if part.is_body_text:
            continue
        try:
            report = attachments.inspect(part.path, part.filename, part.content_type, part.payload, packs)
        except Exception:
            comp["attachments"] = "partial"
            continue
        if part.disposition == "attachment" or part.filename or report.signals:
            attach_labels.append(report.label)
        for sid, evidence in report.signals.items():
            sigs.add(sid, part=part.path, **evidence)

    # Word obfuscation ------------------------------------------------------------------------------------------
    brand_terms = frozenset(t for b in packs.brands for t in (b.key, *b.labels) if t.isalpha() and len(t) >= 4)
    obfuscated = obfuscated_words(visible_raw + "\n" + mail.subject + "\n" + display, brand_terms)
    if obfuscated:
        brand_hit = next((b.key for b in packs.brands for t in obfuscated if t in (b.key, *b.labels)), None)
        sigs.add("ACCT_WORD_OBFUSCATION", count=len(obfuscated), brand=brand_hit)

    # Round 2: domain ages and typed decisions -----------------------------------------------------------------
    age_domains: list[str] = []
    sender_age_domain = None
    if from_org and from_org not in popular and not packs.is_freemail(from_domain) \
            and packs.official_brand(from_domain, from_org) is None:
        sender_age_domain = from_org
        age_domains.append(from_org)
    link_age: list[str] = []
    for link in links:
        d = link.reg_domain
        if (not d or d in popular or d in age_domains or d in link_age or packs.is_ugc(link.host)
                or packs.is_shortener(link.host) or packs.is_esp_tracker(link.host)
                or packs.official_brand(link.host, d) is not None):
            continue
        if len(link_age) < MAX_LINK_AGE_DOMAINS:
            link_age.append(d)
    age_domains = (age_domains + link_age)[:AGE_BUDGET]

    flags = []
    if packs.is_freemail(from_domain):
        flags.append("freemail")
    if any(psl.registrable_domain(a.domain) != from_org for a in mail.reply_to if a.domain) and mail.reply_to:
        flags.append("replyto-differs")
    if _is_list_mail(mail):
        flags.append("bulk")
    auth_word = "aligned-pass" if aligned_pass else ("fail" if outcome and outcome.result == "fail" else "none")
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
    ocr = ctx.meta.get("ocr_text") if isinstance(ctx.meta.get("ocr_text"), str) else None
    rendered = state.render(display, from_domain, flags, auth_word, mail.subject, state.body_tokens(state_text),
                            state_links, list(dict.fromkeys(attach_labels)), ocr)
    backends = [b for b in (ctx.policy.get("backends") or []) if isinstance(b, str)]
    decide = None
    if backends:
        decide = {"state": rendered, "state_version": state.state_version(), "language_hint": None,
                  "questions": state.QUESTIONS, "policy": {"backends": backends}}
    round2 = broker.request(ages=age_domains, decide=decide)

    # Domain ages ------------------------------------------------------------------------------------------------
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
        comp["domain_age"] = "failed"  # lookup errors: a missing answer must not count as complete
    elif any(s == "unknown" for s in statuses):
        comp["domain_age"] = "partial"  # registry returned no date (allowed for completeness)

    # Typed decisions ---------------------------------------------------------------------------------------------
    decisions_out: list[dict] = []
    answers_by_id: dict[str, dict] = {}
    if decide is None:
        comp["classifier"] = "skipped"
    else:
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
                comp["classifier"] = "abstained"
                sigs.add("CLS_ABSTAIN")

    # Callback lure: phone number + callback request + (brand or charge) from a sender that is not the brand.
    callback = answers_by_id.get("asks_callback", {})
    callback_p = callback.get("p_yes") if not callback.get("abstain") else None
    if isinstance(callback_p, (int, float)) and callback_p >= SIGNAL_THRESHOLD:
        phone_text = visible + "\n" + (ocr or "")
        if find_phones(phone_text):
            mentioned = packs.brands_mentioned(mail.subject + "\n" + display + "\n" + phone_text[:20000])
            unofficial = [b for b in mentioned if not b.is_official_sender(from_domain, from_org)]
            charge = has_amount(phone_text)
            weak_sender = packs.is_freemail(from_domain) or not aligned_pass
            if (mentioned and len(unofficial) == len(mentioned)) or (charge and weak_sender):
                sigs.add("PHONE_CALLBACK_LURE", brand=unofficial[0].key if unofficial else None)

    # Campaign fingerprint -------------------------------------------------------------------------------------
    link_domains = [l.reg_domain for l in links if l.reg_domain]
    bands = simhash.bands(visible, link_domains)

    comp["complete"] = False  # set by the supervisor after merging feed state
    return {"completeness": comp, "signals": sigs.items(), "decisions": decisions_out,
            "auth": {"dkim": auth_dkim, "dmarc": dmarc_obj}, "campaign_bands": bands}


def is_official_link(host: str, packs: Packs) -> bool:
    return any(is_subdomain_or_equal(host, d) for d in packs.all_official)
