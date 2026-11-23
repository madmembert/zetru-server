# Analyzer, inference and updater: implementation decisions

Where the concept left a choice open, it was resolved with the maxim "trust only when really sure; inform
without alarm". Items marked **deviation** differ from the letter of the concept.

## Process model and sandbox

1. **Zygote started with exec, not fork** of the supervisor. The supervisor holds the feed mirrors (Majestic
   ~8 MB as hashes, CERT Polska); a forked worker would inherit that address space and count it against
   `RLIMIT_AS`. The zygote imports and warms up everything (codecs, `cryptography`, packs, confusables, PSL) so
   workers never import or open files after the sandbox is applied.
2. **"Pipe" = pre-created AF_UNIX stream socket pair**, passed to the zygote with SCM_RIGHTS. It is bidirectional
   and needs no `socket()`/`connect()` after hardening. The zygote control channel is a datagram socket pair.
3. **Seccomp denies with EPERM** (not kill) for the listed syscalls so failures surface as Python errors and are
   reported; a wrong architecture or the x32 ABI kills the process. In addition to the concept's list the filter
   blocks `socketpair`, `bind`, `listen`, `accept*`, `execveat`, `process_vm_readv/writev`, the new mount API,
   `umount2`, `io_uring_*` (would bypass per-syscall filtering), `creat` and `openat2` (its flags are in a struct
   BPF cannot read), and since the security review (S6) every signal syscall, process creation, file-system changes,
   SysV/POSIX IPC, keyrings, memfd, bpf and `prctl`. `PR_SET_DUMPABLE 0` and `PR_SET_PDEATHSIG` are set too.
4. **On Linux the sandbox is mandatory**: if any step fails the worker reports `sandbox` and the request gets
   `503 analyzer_unavailable`. `ZETRU_SANDBOX=off` exists for local development only. On other platforms the
   sandbox is skipped with a logged warning.
5. **Outcome mapping** (changed by the security review, S1): everything a mail can make a worker do — an
   exception, `MemoryError`, `RecursionError`, a wall-clock kill (15 s), `SIGXCPU`, a crash without a result or a
   result failing schema validation — is answered `200` with `parse: failed` and `MIME_MALFORMED` + `MIME_LIMITS`
   (a mail that exhausts the sandbox is suspicious and must not lift the device's "not analysed" cap without a
   finding; §11.6: an unparseable mail is not an error). Only a sandbox failure is `503 analyzer_unavailable`
   (Retry-After 900), and only the supervisor's own 20 s deadline (queue wait included) is `504 analysis_timeout`.
   Previously a content-triggered exception gave 503 and a CPU-heavy mail 504, which let a sender keep the server
   away from their mail for good.
6. **DNS name policy**: only TXT names of the forms `_dmarc.<d>`, `<s>._domainkey.<d>` and `<d>` when
   `_dmarc.<d>` is in the same batch (DMARCbis `np` needs to know whether the From domain exists; TXT is the
   only allowed query type, NXDOMAIN on it answers that). Budget 25 names per mail; feed lookups 40; age lookups
   6; one inference call whose questions and backends come from the supervisor and the tenant policy, never
   from the worker.
7. **No threads in the supervisor** (custom asyncio HTTP client/server, dnspython's asyncio resolver, host names
   resolved synchronously with a 30 s cache) so the process model stays fork-safe.

## Signals the server emits

8. The server emits the catalogue's S and B signals it can evaluate without contact history, plus:
   `MIME_MALFORMED` (required by §11.6 for unparseable mail), `MIME_LIMITS` (the server's own parse limits),
   `ATT_EXECUTABLE` when the **content** is an executable (PE/ELF/Mach-O/LNK/MSI/ISO/VHD/OneNote) whatever the
   extension (the device judges extensions only), and `CLS_*` signals from decisions at p ≥ 0.80 (§9.7 says the
   app applies thresholds; emitting them as well is idempotent because the app unions by ID and keeps the
   decisions with probabilities). `ANALYSIS_PARTIAL` is added whenever `complete` is false.
9. **Not emitted by the server**: `AUTH_NONE` (SPF comes only from the provider's trusted A-R, which only the
   device can identify), contact/baseline/thread/combination signals, `BULK_CAMPAIGN_*` (gateway),
   `FEED_IP_HIT` (bring-your-own-key feeds only).
10. **Tier-dependent signals** (`LINK_UGC_HOSTING` "from tier ≤ C1", `ATT_ENCRYPTED`, `CLS_ASKS_*`) are emitted
    without knowing the tier; `fallback_severity` uses the stricter low-tier value. **Open issue for the app:**
    the merge step must apply the tier condition of `LINK_UGC_HOSTING`.
11. **Evidence for link-scoped signals** carries the domain (registrable domain for look-alike/new-domain,
    host for UGC and feed hits) plus the `url_sha256` of one example link; at most 8 entries per signal ID, 64 in
    total. The app should match affected links by domain.

## Authentication

12. **Own DKIM verifier** instead of dkimpy at runtime, to distinguish body-hash from signature failures, to see
    `l=` coverage and the signed header list (needed for `BULK_RFC8058_SIGNED`), and to treat `rsa-sha1`, keys
    under 1024 bits, expired `x=` and revoked keys as `unverifiable`. dkimpy (zlib licence) is used only in tests
    to sign and cross-check. PKCS#1 RSA key records are accepted.
13. **DMARC result `fail` only when DMARC must fail regardless of SPF** (the server never re-evaluates SPF): no
    aligned DKIM pass, no aligned signature that is merely unverifiable or modified in store, and a non-null
    Return-Path that is not aligned. Otherwise the result is `none` (not determinable). `t=y` softens one step;
    `pct`, `rf`, `ri` ignored; multiple records at one name count as none; a DNS error below the first record is
    a temporary error (auth `partial`, no signal).
14. **Organisational domain**: DMARCbis tree walk (psd=n / psd=y / fewest labels) when DMARC records exist;
    otherwise the Public Suffix List. A DKIM `d=` is aligned with the From org domain O when it equals O or is a
    subdomain of O (psd=n records below O on the `d=` side are not queried — documented simplification).
15. **`AUTH_DKIM_BODY_MODIFIED`** needs "valid at the provider": a failing signature whose `d=` the **topmost**
    Authentication-Results header reports as `dkim=pass`. That header is not authenticated on the server (the
    provider profile lives on the device); it is used only to downgrade a failure to "modified in store", never to
    raise trust. Residual risk: with a provider that adds no A-R an attacker could suppress the server's
    `AUTH_DMARC_FAIL_*`; the device's own evaluation is unaffected.
16. **`AUTH_REPLAY_SUSPECT`** (server version): a passing signature with `t=` more than 24 h before delivery
    (`received_at` or the top `Received` date) **and** the topmost `Delivered-To` not among To/Cc **and** no list
    headers. The device covers "Delivered-To differs from the account".
17. **`BULK_RFC8058_SIGNED`**: an aligned passing signature whose `h=` covers both List-Unsubscribe headers,
    `List-Unsubscribe-Post: List-Unsubscribe=One-Click` and an HTTPS unsubscribe URI.

## Content

18. **Visible text**: inline styles, `bgcolor`/`color` attributes and simple stylesheet selectors (`.c`, `#i`, `tag`,
    `tag.c`); rules inside `@media`/`@supports` are ignored (they may not apply). White text counts as hidden only
    against an explicit background colour (no assumed white default). Text inside `blockquote`/Gmail and Outlook
    quote containers is visible but excluded from the classifier state.
19. **`MIME_HIDDEN_TEXT`**: hidden > 200 non-space characters, or ≥ 20 hidden characters that are more than 30 % of
    all text and not just a preheader (hidden text before any visible text).
20. **`MIME_PARTS_DIFFER`** only when both alternatives contain links and their domain sets are disjoint (ignoring
    ESP click-trackers); "different" sets are common in legitimate mail (social links in HTML only).
21. **Canonical URL** (for `url_sha256`, must be implemented identically by the app): see `urls.py` docstring —
    TAB/CR/LF removed, scheme/host lowercased, IDNA A-labels (Python IDNA 2003 codec, punycode fallback), numeric
    IPv4 forms normalised, default port and fragment removed, empty path → `/`, userinfo/path/query unchanged,
    backslashes before the query become slashes. Only http/https are link URLs.
22. **Redirectors** (`packs/redirectors.json`) are unwrapped up to three levels; both the wrapper and the
    destination are checked. Shorteners are never unwrapped.
23. **Look-alikes** compare case-folded UTS #39 skeletons (`skeleton(casefold(skeleton(casefold(x))))`), because
    skeleton prototypes can be upper case (`0` → `O`). Rules 2–4 use explicit per-brand `labels`; `token_rule` is
    off for brands whose label is a common word or name (otto, sky, ups, gls, booking, …). **Regional groups**
    (Sparkasse, Volksbanken, EDEKA, Polizei, Verbraucherzentrale): `.de` domains whose registrable label matches the
    group pattern are "cannot judge" and never flagged by the server (hundreds of legitimate regional domains);
    the same tokens under other TLDs are flagged. Known false-positive risk kept per concept: rule 2 on 5-letter
    labels (e.g. `apply.com` vs `apple`).
24. **`ID_BRAND_NOT_OFFICIAL`**: display-name tokens (case-folded skeleton, whole words) or local-part tokens;
    acronyms (UPS, DPD, ING, …) only case-sensitive so "Ups" or a person named Otto do not match. Official =
    a listed sending domain or subdomain, an authority's government suffix (bund.de, state portals, gov.uk, .gov,
    europa.eu), or a regional group member. Freemail domains are never official senders.
25. **`PHONE_CALLBACK_LURE`**: phone number + `asks_callback` ≥ 0.80 + (a brand mentioned while the sender is
    official for none of the mentioned brands, **or** a charge amount while the sender is freemail or has no
    aligned DKIM pass). Ordinary service mails ("Bei Fragen … unter …") are suppressed in the rule tier.
26. **`ACCT_WORD_OBFUSCATION`**: words that spell a brand label or a sensitive term (Konto, Passwort, account, …)
    only after removing invisible characters or undoing digit/homoglyph substitutions; brand names that contain
    digits (O2, N26, CHECK24) are exempt.
27. **Attachments**: nested archives are decompressed in memory only when ≤ 20 MB and of a listable type (zip,
    tar, gzip); RAR/7z/CAB/bzip2/xz are `ATT_ARCHIVE_OPAQUE`. Type mismatch only for confidently detected content
    that the extension or a specific declared type cannot have (same-class images exempt; HTML in `.doc/.xls`
    allowed because legacy exports do this, but then scanned for active content). Double extension = a document
    extension followed by an executable or HTML extension.
28. **Encrypted PDFs**: `ATT_ENCRYPTED` only when the standard security handler requires a **user** password
    (checked for R2–R6 with the empty password) or a public-key handler is used. Permission-only encryption
    (common for statements and invoices) opens without a prompt and is not flagged; undeterminable cases are not
    flagged.
29. **HTML/SVG attachments** follow the concept literally: any external URL counts as active content.

## Canonical state `state-1` and decisions

30. Line breaks become ` / ` sentence separators, link positions `[LINK]` (URLs replaced), quoted replies and
    signatures removed; `flags` may contain `freemail`, `replyto-differs` and `bulk` (List headers or Precedence;
    needed for `newsletter_bulk`). `first-contact` is never emitted (the server has no history). BODY-TAIL holds the
    last ≤ 80 tokens after the 250-token head.
31. Abstaining answers carry `p_yes: null`; `CLS_ABSTAIN` is emitted and `classifier: "abstained"` set.

## Rule tier

32. Strong evidence requires two groups in the same or adjacent sentence and a call to action within one sentence
    before or after; payment instructions (IBAN, crypto wallet) count as calls to action for payment, bank-change,
    extortion and scam patterns; ClickFix key combinations for code/command.
33. Category order: phishing (credentials strong + impersonation ≥ moderate) → scam (extortion or scam story
    strong) → newsletter (bulk flag) → spam (commercial strong, no bulk flag) → weaker phishing/scam at 0.65 →
    legit 0.60. German patterns need native-speaker review (concept §16.7).

## Feeds and updater

34. Feed matching checks the host and every parent with ≥ 2 labels (CERT Polska recommends blocking subdomains);
    a listed child never makes its parent listed. Feeds are held as sorted 64-bit hashes in the supervisor.
35. The never-list guard also protects the **disposable** list (a poisoned entry like `gmail.com` would mark every
    Gmail sender). A release with more than max(10, 1 %) never-list hits is rejected as poisoned. Since the
    security review (S11) names of the static never-list protect their subdomains too, Majestic top-1,000 names
    protect only themselves, and the analyzer applies the static rule again at lookup time.
36. **Deviation**: staging of the normalised output happens on the feeds volume (`.tmp-<version>`) so the
    publish rename is atomic. Raw downloads are staged on the feeds volume too (`/feeds/.staging`,
    `ZETRU_STAGING_DIR`), not in the tmpfs: tmpfs pages count against the container's 512 MB limit (S14).
37. Majestic's "at most once per 24 h" counts every attempt, also failed or rejected ones.
38. Truncated downloads are rejected (Content-Length check): `http.client` does not raise when a body with a
    declared length ends early.
39. Missing feeds are reported in `feeds` with `age_s = 2147483647` and `stale: true`; with no blocklist at all
    `completeness.feeds = "failed"`, otherwise `"partial"` for any missing/stale feed.

## Packaging

40. **Deviation**: images are `python:3.12-slim-bookworm` multi-stage (binary wheels only, pip removed in the
    runtime) instead of `distroless/python3`, whose interpreter is the Debian one (3.11 on Debian 12), not the 3.12
    required here. Non-root uids 10002/10003/10005, read-only root FS compatible (bytecode precompiled,
    `PYTHONDONTWRITEBYTECODE=1`). Pin the base image by digest for releases.
41. Each service builds from its own directory (no shared `pylib`), matching the compose build contexts.

## Security review of the Python services (findings PY-01 … PY-26)

The review is in the session notes, not in the repository; the finding IDs are used in code comments. Guiding rule
for every fix: a parsing problem may make a result *incomplete* or add a *caution*, never make a mail look better;
one tenant's mail must not degrade service for others.

S1. **Content never becomes an outage (PY-01, PY-05).** `pipeline.analyze` runs every stage under a guard: an
    unexpected exception marks that stage `failed` (or `partial` for text-only stages), adds `MIME_MALFORMED` and
    `MIME_LIMITS` and the other stages still run. The supervisor maps worker errors and CPU/wall-clock kills to the
    `200` failure result (decision 5). A per-mail CPU budget of 6 s stops attachment inspection early
    (`attachments: partial` + `MIME_LIMITS`), so most heavy mails still get their auth and link results.
S2. **URL canonicalisation (PY-01).** A port must consist of ASCII digits; leading zeros are ignored and at most
    five significant digits are allowed — exactly the rule of `LinkCanonicalizer.swift`. Fullwidth or
    Arabic-Indic digits, which Python's `str.isdigit` accepted, are now rejected like the app rejects them. Input
    containing a lone surrogate (only Python strings can hold one) is rejected as a whole, whatever part of the URL
    it is in. Body text is decoded only with an allow-list of mail charsets; `punycode`, `idna`, `utf-7`,
    `unicode_escape` and anything unknown are decoded as UTF-8 with replacement.
S3. **Links (PY-02).** Every distinct host is kept; only URLs beyond 10 per host are skipped, which loses nothing
    because every link check works per host or per domain. Redirector destinations count as their own host. More than
    1,000 distinct URL candidates (or 500 URLs in plain text): `urls: partial` + `MIME_LIMITS` (1,000 hosts cost
    about 0.5 s of CPU on a laptop, a few seconds on a Raspberry Pi). Feed lookups go to
    QR/form/unwrapped links first, then visible links, hidden links, and ESP trackers/official brand hosts last; if
    the 40 lookups or the 5 link-domain age lookups do not cover everything, `urls` is `partial` (domain-age
    `partial` alone still counts as complete, so `urls` carries the incompleteness). No `MIME_LIMITS` for budget
    overflow: many link domains are normal for newsletters and must not raise a caution.
S4. **Canonical state size (PY-03).** Tokens are cut at 64 characters, controls and bidi/zero-width characters are
    removed and lone surrogates replaced; a state stays below ~36,000 characters, well inside the 64 KiB the
    supervisor and inference accept. The supervisor cuts an oversized state instead of refusing it. The analyzer
    sends JSON to inference as UTF-8 (escaped non-ASCII text could exceed the body limit), and inference accepts
    bodies up to 1 MiB.
S5. **Rule-tier evasion and cost (PY-03, PY-04, PY-16).** The two quadratic amount patterns are anchored
    (`(?<!\d)\d{1,9}…`); every pattern of a pack is timed against adversarial strings when the pack is loaded and
    a slow one stops the service from starting (rule packs are `rules-1.1.0` now). Text whose overall stop-word
    ratio is below 8 % (padding with foreign or nonsense words) is evaluated against the language of its densest
    40-token window; only strong findings are reported then, all other answers stay `unsupported_language`
    (rules only ever raise risk). A `suppress` pattern now cancels only matches it overlaps, so an injected
    "(newsletter)" no longer silences a credential request; the two callback suppressors were widened to the end of
    their clause so "Bei Fragen erreichen Sie uns unter …" stays neutral. Residual: a sender who writes the request
    *inside* a suppressor's phrase (e.g. starts the callback sentence with "If you have questions,") still
    suppresses it — inherent to suppression lists.
S6. **Sandbox (PY-07, PY-08).** Supervisor and zygote set `PR_SET_DUMPABLE 0` (their `/proc/<pid>` files then
    belong to root, so a compromised worker of the same uid cannot open `/proc/1/mem`, whatever the host's Yama
    setting). The supervisor ignores SIGINT (inherited by the zygote). The seccomp filter stays a **deny-list**,
    extended to signals, process creation, file-system changes, persistent IPC objects and `prctl`; an allow-list
    needs a traced run of the corpus on Linux/x86_64 and aarch64, which the macOS development setup cannot do — a
    wrong allow-list would make every worker fail. Converting is the recommended next step. A zygote that leaves two
    spawns in a row unanswered counts as dead and is replaced by the maintenance loop; `/internal/healthz` answers
    503 then, so the container health check sees it.
S7. **Attachments (PY-05, PY-09, PY-10, PY-15).** Each sub-analysis runs separately; an expected parse failure
    marks the report `partial`, an unexpected error also `failed`, which the pipeline reports as `MIME_LIMITS` with
    the part path (a caution) — signals found before the failure are kept. PDF names are found with literal searches
    plus a bounded pass over `#xx` escapes (at most 20,000 per buffer, else `partial`); stream inflation is bounded by
    output (16 MB), compressed input (64 MB, overlapping streams count again) and 2,000 streams (`partial` when
    hit). The ZIP end record is the outermost one whose comment reaches the end of the file; local headers that no
    listed entry covers make the archive opaque; unrecognised content with an archive extension or a ZIP end record
    is listed as ZIP, or reported opaque. OOXML macros are also found through `[Content_Types].xml` (VBA, macro-
    enabled and macro-sheet types) and through macro-enabled extensions (`docm`, `xlsm`, …).
S8. **DNS answers (PY-06).** TXT records are reduced to printable ASCII, at most 8 records of 2,048 characters per
    name; a broker reply is capped at 512 KiB (largest DNS answers become errors) and the worker accepts replies up to
    that size; a worker that goes away while the supervisor writes still gets an answer for its mail.
S9. **Multiple From fields (PY-13).** A mail with other than exactly one From field and one mailbox gets
    `MIME_MALFORMED`, no aligned signature, DMARC result `fail` (without an `AUTH_DMARC_FAIL_*` signal: the
    published policy says nothing about such a message) and `[AUTH] fail` in the state. A DKIM signature whose `h=`
    lists a displayed field (From, Sender, Reply-To, Subject, To, Cc) fewer times than the message contains it is
    `unverifiable` (`unsigned_instances`).
S10. **Optional inference tiers (PY-12, PY-24, PY-26).** One deadline per request (6 s, analyzer waits 8 s); `llm`,
    `openjev` and `jev` run in parallel on a 4-thread pool; any failure or late answer of an optional tier is
    ignored and the rule answers are returned; a failing encoder falls back to rules. The server handles at most
    8 requests at once (`ZETRU_INFERENCE_CONCURRENCY`) and answers 503 beyond that. Encoder: logits clamped, stable
    sigmoid, temperatures clamped to 0.05–100, release files must stay inside the release directory, and answers
    carry `state_truncated_over_50pct` when more of the state falls behind the 512-token window than inside it. The
    analyzer does **not** flag its own state-1 window (head 250 + tail 80 tokens): that window is the defined
    classifier input (§9.2), and the app counts every `abstain` value as an abstention. Remote backends (`remote =
    True`) need HTTPS unless the host is loopback.
S11. **Never-list (PY-11, PY-25).** See decision 35. Unguarded feeds (PSL, Majestic) are processed before guarded
    ones in every pass, so the first certpl release on a fresh volume is filtered with the Majestic top 1,000 when
    Majestic is reachable; if it is not, the static never-list still applies and the next run (5 min) re-filters.
S12. **Drain protection (PY-18).** Besides the previous release, a reference release is kept (`reference.json`, not
    pruned) and moves to the newest release once it is 24 h old; a release may not remove more than 50 % (or add more
    than 300 %) relative to either. A compromised source can therefore halve a list at most about once a day.
    `min_entries` of certpl (1,000) is unchanged: raising it needs the list's real size, which was not measured.
S13. **HTTP and IPC limits (PY-17, PY-19, PY-20, PY-21, PY-23).** `HARD_MAX_MAIL` is 20 MiB (the gateway's cap) and
    the worker's job-frame limit is derived from it. Analyze requests are admitted before the body is read; bodies
    being read count against workers + queue; at most 2 × capacity + 16 connections. POST endpoints need a valid
    tenant UUID; chunk sizes are 1–8 hex digits. Validators use `fullmatch` (a `$` accepted a trailing newline).
    A worker gets at most four broker round trips.
S14. **Supervisor blocking (PY-22).** Feeds are hashed, parsed and sorted in steps with `await asyncio.sleep(0)`
    between them; host names are still resolved synchronously (decision 7: no threads), but a failed resolution is
    cached for 5 s and a known address kept for 5 minutes while resolution fails; the resolver's address is looked up
    again after three consecutive timeouts. Updater: the attempt time is saved before a download starts, so a run
    killed for memory cannot loop; the previous release is compared as a sorted array of 64-bit hashes.

S15. **URL canonicalisation is a shared contract (concept §11.4).** `contract/url-canonicalization.json` holds 110
    inputs with the canonical form both sides must produce; `analyzer/tests/test_contract_vectors.py` checks this
    implementation, the app's LinkCanonicalizer test checks the same file. The first run found two old differences:
    IPv6 hosts were serialised with `str(ipaddress.IPv6Address)`, which prints IPv4-mapped addresses dotted from
    Python 3.13 on (`[::ffff:1.2.3.4]`) and hex before (`[::ffff:102:304]`), so `url_sha256` depended on the Python
    version of the machine; and zone IDs (`[fe80::1%25eth0]`) were accepted. `format_ipv6` now serialises like the
    app and WHATWG (hex pieces, first longest zero run compressed), and zone IDs are rejected.
