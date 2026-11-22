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
   BPF cannot read). `PR_SET_DUMPABLE 0` and `PR_SET_PDEATHSIG` are set too.
4. **On Linux the sandbox is mandatory**: if any step fails the worker reports `sandbox` and the request gets
   `503 analyzer_unavailable`. `ZETRU_SANDBOX=off` exists for local development only. On other platforms the
   sandbox is skipped with a logged warning.
5. **Outcome mapping**: wall-clock kill (15 s) or `SIGXCPU` → `504 analysis_timeout`; `MemoryError`,
   `RecursionError`, a crash without a result or a result failing schema validation → `200` with
   `parse: failed` and `MIME_MALFORMED` + `MIME_LIMITS` (a mail that exhausts the sandbox is suspicious and must
   not lift the device's "not analysed" cap without a finding); an internal exception (a bug) or sandbox failure
   → `503 analyzer_unavailable` with Retry-After 900, so the app keeps the mail at "not analysed" instead of
   presenting an incomplete analysis.
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
    Gmail sender). A release with more than max(10, 1 %) never-list hits is rejected as poisoned.
36. **Deviation**: staging of the normalised output happens on the feeds volume (`.tmp-<version>`) so the
    publish rename is atomic; raw downloads are staged in the tmpfs (`ZETRU_STAGING_DIR`).
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
