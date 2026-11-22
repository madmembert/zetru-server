# Gateway and lookup: decisions and deviations from the concept

Every point below is either a deviation from `docs/concept.md` / `docs/server-internal-api.md` or
a choice the documents leave open. Section numbers refer to the concept.

## Open issue for the app (must be reconciled before integration)

**Canonical string.** §4.4 defines the canonical string as six lines: `ZETRU1`, method, path with
query, timestamp, nonce, body hash. The gateway implements exactly that. The app's
`ios/ZetruKit/ServerClient/RequestSigning.swift` currently signs a seventh line (`meta`, empty when
there is no `Zetru-Meta` header), i.e. `…<hash>\n` with a trailing newline. Those signatures fail
with `bad_signature`. The concept says request metadata travels in the body, so the app should
drop the seventh line and the `Zetru-Meta` header. The gateway does not accept both forms on
purpose: one canonical form, no ambiguity.

## Storage

1. **Registry as a JSON file, not SQLite (§13.2).** Standard library only. Made robust by atomic
   writes (temp file, fsync, rename, directory fsync), a copy of the previous version in
   `registry.json.bak`, an exclusive `flock` around every read-modify-write (the CLI and the running
   server share the file), change detection on every device lookup (inode, size, mtime), so a CLI
   revocation applies to the next request, and strict validation on load (a corrupt file stops the
   gateway instead of unpairing everyone). The registry is small (households, small companies).
2. **Counters and quotas** are JSON files under `gateway-data/state/`, written atomically every
   5 minutes and on shutdown. A crash loses at most 5 minutes of counts. A corrupt counter file is
   moved aside and counting restarts (counters are advisory). The campaign file records a check
   value of `K_fp`; a file written under another key is discarded.
3. **Key layout.** `tls-state.json` holds the primary key pair, a pending "next" key pair, the
   signed pin set and the rotation state, so every rotation step is one atomic write. The backup
   key pair is `backup/tls.pem` and may be moved offline; its pin stays in `tls-state.json`.
   `identity.key` (Ed25519) and `fingerprint.key` (`K_fp`) are separate files. All files are 0600.

## Protocol details

4. **Error codes for cases §11.6 does not name.** Only the codes of §11.6 are ever sent:
   missing or malformed `Zetru-Device` → `401 unknown_device`; missing or non-numeric timestamp →
   `401 stale_timestamp`; missing or malformed nonce or content-hash header → `400 bad_request`;
   body hash mismatch → `401 bad_signature` (the signature covers the hash); unknown enrolment
   token → `403 forbidden`; device of another tenant in `DELETE /v1/devices/{id}` → `404 not_found`
   (no enumeration); unknown route or method → `404 not_found`; analyzer contract violation or
   unreachable analyzer → `503 analyzer_unavailable`; handler panic → `503 busy`. Body over the
   limit on `/v1/analyze` → `413 mail_too_large`, on other endpoints → `400 bad_request`.
5. **Nonce reserve and release.** The nonce is checked and recorded at step 3 of §4.4 (atomic, so
   two copies of a request cannot both pass). If the request then fails the body-hash or signature
   check, the nonce is released again. Only authenticated requests keep their nonce, so
   unauthenticated traffic cannot fill the cache or burn a nonce a genuine request still needs.
   A device has at most 2,048 live nonces (`429 rate_limited` beyond, only reachable with the
   device key).
6. **Response signatures without a usable nonce.** Every response is signed. It is bound to the
   request's `Zetru-Nonce` if that is syntactically valid (16 bytes, base64url, 22 characters),
   otherwise to the empty nonce. `POST /v1/enroll` accepts an optional `Zetru-Nonce`; the app
   should send one so that the enrolment response is bound to its request.
7. **Pin-set signature (additive field).** `pin_set` in `ServerInfo` carries
   `signature`: base64 Ed25519 by the identity key over
   `ZETRU1-PINSET\n<seq>\n<valid_from>\n<pin 1>\n…\n<pin n>`. The whole response is signed anyway;
   the separate signature lets the app store and re-verify the pin set on its own (§13.2 lists
   `pin_set.signature`).
8. **Rotation (§4.6).** `rotate-tls` creates the next key and publishes `[current, next, backup]`
   with `valid_from = now`. The current key keeps being served for the 30-day transition (apps
   that have not fetched the update yet would otherwise fail their pin check), then the gateway
   promotes the next key by itself (checked every 30 s) and publishes `[next, backup]`.
   `--complete` promotes early. `--activate-backup` (key loss) serves the backup key immediately,
   generates a new backup key and publishes `[old backup, new backup]`; a pending rotation is
   cancelled. Pairing codes issued during a transition carry all three pins.
9. **Enrolment.** The device key is base64 X9.63 (65 bytes, uncompressed, validated on the curve
   with `ecdsa.ParseUncompressedPublicKey`); `POST /v1/devices/rotate` takes the same format.
   `device_label` may be empty (≤ 40 characters, no control characters), `platform` must be
   `ios`, `app_version` is printable ASCII ≤ 32 and is not stored. The 5-per-minute limit is per
   TCP peer address, held in memory only; behind a reverse proxy it would apply to the proxy.
   Used or expired tokens are remembered for 24 hours so that the answer can be `token_used` or
   `token_expired`.
10. **Device list.** `GET /v1/devices` lists active devices only; `last_seen_day` is set at
    enrolment and updated at most once per device and day.

## Limits (§11.4)

11. Analyze: 30/min (pi) or 60/min (vps) per device, token bucket with that burst; daily quota
    3,000/10,000 per device and UTC day, `Retry-After` = seconds to the next UTC midnight. A tenant
    policy can override both (`0` = profile default). url/check: 60/min per device. Endpoints §11.4
    does not cover (server/info, report, devices, rotate, delete): 30/min per device. Reports:
    50 per device and day (§16 #18). A request the analyzer could not take (`503`) does not use
    quota.
12. **Memory.** The gateway holds an analyze body in RAM until it is authenticated (nothing may
    reach the analyzer before that, and nothing may touch the disk). At most workers + queue
    analyses (10 pi, 36 vps) are admitted at once, and their bodies share a budget of 96 MiB (pi)
    or 200 MiB (vps); beyond either limit the answer is `503 busy`. Residual risk: a member of a
    tenant who knows a device ID can occupy these slots with slow uploads for up to the 120 s read
    timeout.
13. `max_mail_bytes` in a tenant policy is capped at 20 MiB (the app never submits more).

## Campaign counters (§6.5, §6.6, §13.2)

14. **Capped sets of keyed hashes instead of HyperLogLog.** Per keyed band the gateway keeps the
    devices that saw it (64-bit keyed device hash, keyed tenant hash, last UTC day) and the devices
    that reported it. Sets hold at most 32 members; at most 5 reporters per tenant and band, so a
    single tenant cannot dominate. The thresholds need exact counts only up to 20 and a membership
    test ("reported by a device of the same tenant"), which a sketch cannot answer. Everything
    expires 30 days after its last day.
15. **Two of four bands must agree.** A mail matches a campaign only when at least two of its four
    16-bit bands carry the counts; the count used is the second-highest per-band value. With
    single-band matching an unrelated mail collides with one of k reported bands with probability
    ≈ 4k/65,536 (1.2 % for 50 reported fingerprints), which would put G2 gates on legitimate mail.
    Cost: near-duplicates that differ in three or more bands are not matched.
16. **Windows and precedence.** `BULK_CAMPAIGN_SEEN`: ≥ 5 distinct devices in the last 7 days and
    no reports. Reports count over the 30-day retention. Only the strongest campaign signal is
    added (CONFIRMED > REPORTED > SEEN), with `evidence.count` = the bucketed count. A `legit`
    report is recorded (one report per device and fingerprint) but does not count. The gateway
    removes any `BULK_CAMPAIGN_*` signal the analyzer sends.
17. **Scopes.** Every analysis counts in the tenant's own scope. Tenants with
    `cross_tenant_counting` also count in, and read from, the global scope. Tenant deletion removes
    the tenant scope, its mail references and reports, and its members from global sets.
18. **Hash inputs.** Band key = `HMAC-SHA256(K_fp, band_index ‖ band)` with a one-byte index and
    the two big-endian band bytes (as specified). Own additions use labelled inputs:
    `"tenant-band" ‖ tenant ‖ band key`, `"device" ‖ id`, `"tenant" ‖ id`,
    `"fingerprint" ‖ 4 band keys` (first 16 bytes, hex = `fingerprint.id`),
    `"report" ‖ device ‖ fingerprint id`; mail reference = `HMAC(K_fp, tenant ‖ mail_sha256 hex)`.
19. **Report matching.** `POST /v1/report` needs a mail reference of the same tenant whose
    fingerprint equals `fingerprint_id`; otherwise `404 not_found`. A repeated report by the same
    device returns `204` and counts once.

## Forwarding to the analyzer

20. `X-Zetru-Policy` is padded base64url (decodes with Python's `base64.urlsafe_b64decode`
    as is). `POST /internal/v1/url/check` receives `X-Zetru-Tenant` and `X-Zetru-Policy` too
    (additive). The gateway re-encodes the validated url/check request.
21. **Analyzer response checks.** The gateway signs what it returns, so it checks what it touches:
    JSON object ≤ 256 KB + 4 KB, `schema` 1, `mail_sha256` equal to the request's, `signals` an
    array of objects with a valid `id` and `fallback_severity`, at most 64. Violations →
    `503 analyzer_unavailable` with a logged error class. Invalid `campaign_bands` only drop the
    fingerprint (`null`). If 64 analyzer signals leave no room, a campaign signal replaces the last
    analyzer signal of lower severity or is dropped. Other fields pass through unchanged. For
    url/check every result must answer a requested hash and carry `hit`.
22. Analyzer `503` passes through as `503 busy` with the analyzer's `Retry-After` (1–3600 s, else
    30 s); `504` → `analysis_timeout`; `400` → `bad_request`; the gateway's own timeout is 22 s
    (`analysis_timeout`). Error messages are the gateway's fixed strings, never the analyzer's.
23. `server/info` reports the analyzer's backends and feeds (cached 60 s, 15 s after a failure);
    a backend is `enabled` only if the analyzer reports it enabled and the tenant policy lists it.
    If the analyzer is unreachable, the policy's backends are listed with `enabled: false` and
    `feeds` is empty.

## Logging and retention (§11.5, §14.2)

24. Request logs go to one file per UTC day in `gateway-data/logs/` (mode 0600); a file is deleted
    as soon as its day is no longer completely inside the 14-day retention. `ZETRU_REQUEST_LOG`
    selects `stdout` (Docker's size-capped log; retention then depends on traffic) or `off`.
    Fields: `ts`, `endpoint` (route template), `tenant`, `device` (IDs from the registry, never
    header values), `status`, `code` (the fixed error code), `dur` and `size` buckets.
25. `net/http` writes client addresses into its own error messages; the gateway replaces them with
    a fixed class and drops TLS handshake errors entirely. Error logs carry fixed messages and
    classes only, never decoder messages (they can quote request bytes).

## TLS (§4.3)

26. TLS 1.3 only; Go's TLS 1.3 suites are exactly the three listed in §4.3 (not configurable in
    Go). Session-ticket keys are random per process, so tickets never survive a restart. No client
    certificates. HTTP/2 and HTTP/1.1 via ALPN. The certificate is a self-signed P-256 certificate
    valid 20 years (only its key is pinned); its SANs are the hosts of the configured URLs.
27. HTTP timeouts: 10 s for headers, 120 s to read a request (a 20 MB mail over a slow uplink),
    150 s to write, 60 s idle, 16 KiB of headers.

## Operations

28. **CLI next to the server.** `pair`, `revoke`, `tenant …`, `rotate-tls` change files under the
    same locks the server uses; the server picks up registry changes on the next request and key
    changes within 30 s. Counters of a tenant deleted with the CLI are purged by the server within
    5 minutes (or at its next start).
29. **Healthcheck.** `zetru-gateway healthcheck` connects to the local gateway, requires a pinned
    key and a valid identity signature on `/healthz` (distroless has no curl).
30. **QR code.** Own encoder (byte mode, level M, versions 1–40). Verified module-for-module against
    libqrencode 4.1.1 for every version 1–40 (same mask forced), with an independent decoder
    (separate function-pattern map, ISO alignment and format tables, Reed–Solomon syndrome check)
    on 300 random payloads, and by parsing the terminal rendering back. Apple's decoders could not
    run in the development sandbox. `--qr ansi` forces black on white with escape codes;
    `--qr plain` suits dark terminals; the text link is always printed.
31. `init` only supports `trust = pin_only` (self-hosted). `ca_and_pin` belongs to the
    vendor-hosted milestone.

## Lookup service

32. The IANA bootstrap is fetched by the lookup service itself (HTTPS, daily, cached on the
    `lookup-cache` volume for up to 30 days); it does not mount the updater's feeds volume (§3.2
    gives it only `lookup-cache`). Only `https` base URLs on port 443 are used.
33. Supplementary map (`server/lookup/internal/rdap/supplement.json`, extendable with
    `ZETRU_RDAP_SUPPLEMENT`): `.de` and `.ch` → `unknown` without a query (their RDAP services
    return no registration event, checked 2026-11-23), `.io` → the registry operator's RDAP
    service. `.at` and `.eu` have no RDAP service in the bootstrap and are `unknown`.
34. Status mapping: registration event → `ok`; HTTP 404, no registration event, an implausible
    date (before 1985 or in the future), or no RDAP service for the TLD → `unknown`; anything
    else → `error`. `ok`/`unknown` are cached 30 days, registry errors 10 minutes; local rate
    limiting and the caller's deadline are not cached. The handler gives up after 2.8 s (the
    caller's timeout is 3 s).
35. Per-registry-host token bucket (default 1 request/s, burst 6 = the per-mail budget), waits of
    at most 1 s; HTTP 429 backs the host off for its `Retry-After` (≤ 15 minutes). Concurrent
    requests for the same domain share one upstream query.
36. Network guard: the dialer refuses anything but public unicast addresses on port 443 (checked on
    the resolved address), redirects only to `https` hosts that are RDAP servers in the bootstrap or
    the supplementary map, responses ≤ 512 KB, no proxy. Logs contain no domains.
