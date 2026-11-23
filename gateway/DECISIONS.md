# Gateway and lookup: decisions and deviations from the concept

Every point below is either a deviation from `docs/concept.md` / `docs/server-internal-api.md` or
a choice the documents leave open. Section numbers refer to the concept.

## Canonical string and response binding (resolved with the app, 2026-11-23)

The canonical string is the seven lines of §4.4: `ZETRU1`, method, path with query, `Zetru-Device`,
`Zetru-Timestamp`, `Zetru-Nonce`, `Zetru-Content-SHA256` (no trailing newline, no `Zetru-Meta`). The
response signature covers five lines, the last being the request binding (§4.5, GO-10 below). The
app's `RequestSigning.swift` was changed to exactly this in parallel; the cross-language contract is
checked in both directions by `internal/auth/contract_test.go` (Swift-signed request incl. its
binding; gateway-signed response fixture for the Swift test). The gateway accepts one canonical
form only: no ambiguity, no downgrade.

## Storage

1. **Registry as a JSON file, not SQLite (§13.2).** Standard library only. Made robust by atomic
   writes (temp file, fsync, rename, directory fsync), a copy of the previous version in
   `registry.json.bak`, an exclusive `flock` around every read-modify-write (the CLI and the running
   server share the file), change detection on every device lookup (inode, size, mtime), so a CLI
   revocation applies to the next request, and strict validation on load (a corrupt file stops the
   gateway instead of unpairing everyone). The registry is small (households, small companies).
2. **Counters and quotas** live under `gateway-data/state/` (`campaign.dat`, binary, see 37;
   `quota.json`), written atomically every 5 minutes and on shutdown. A crash loses at most
   5 minutes of counts. A corrupt counter file, or a campaign file written under another `K_fp`, is
   deleted and counting restarts (counters are advisory; a moved-aside copy would outlive the
   retention of §14.2, see 50).
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
5. **Nonce check, reserve and release.** The replay cache is consulted (read only) before the
   signature check and the nonce is recorded (atomic, so two copies of a request cannot both pass)
   right after a valid signature (see 40). If the request then fails the body check, the nonce is
   released again. Only authenticated requests keep their nonce; unsigned requests never record
   one, so they cannot fill the cache or burn a nonce a genuine request still needs. A device has at
   most 2,048 live nonces (`429 rate_limited` beyond, only reachable with the device key).
6. **Response signatures without a usable nonce.** Every response is signed. It is bound to the
   request's `Zetru-Nonce` if that is syntactically valid (16 bytes, base64url, 22 characters),
   otherwise to the empty nonce, and always to the request binding (§4.5). `POST /v1/enroll`
   accepts an optional `Zetru-Nonce`; the app should send one so that the enrolment response is
   bound to its request.
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
   `ios`, `app_version` is printable ASCII ≤ 32 and is not stored. Rate limits apply to unknown
   tokens only (see 47). Used or expired tokens are remembered for 24 hours so that the answer can
   be `token_used` or `token_expired`.
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
    analyses (10 pi, 36 vps) are admitted at once, at most half of them per tenant and 2 per
    device, and their bodies share a budget of 96 MiB (pi) or 200 MiB (vps); beyond any limit the
    answer is `503 busy`. A slot is taken only after the signature is verified (see 40 and 41).
13. `max_mail_bytes` in a tenant policy is capped at 20 MiB (the app never submits more).

## Campaign counters (§6.5, §6.6, §13.2)

14. **Capped sets of keyed hashes instead of HyperLogLog.** Per keyed band the gateway keeps the
    devices that saw it (64-bit keyed device hash, keyed tenant hash, last UTC day) and the devices
    that reported it, each as a slice of 20-byte members (not a map: it never exceeds 32 entries).
    Sets hold at most 32 members; at most 5 reporters per tenant and band, so a single tenant cannot
    dominate. The thresholds need exact counts only up to 20 and a membership
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
    JSON object ≤ 256 KB + 4 KB without duplicate or case-variant keys (see 45), `schema` 1,
    `mail_sha256` equal to the request's, `signals` an array of objects with a valid `id` and
    `fallback_severity`, at most 64, each re-encoded from what was validated. Violations →
    `503 analyzer_unavailable` with a logged error class. Invalid `campaign_bands` only drop the
    fingerprint (`null`). If 64 analyzer signals leave no room, a campaign signal replaces the last
    analyzer signal of lower severity or is dropped. Other fields pass through unchanged. For
    url/check every result must answer a requested hash and carry `hit`; the response is rebuilt
    from the validated values (feeds included), never forwarded as received.
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
    header values), `status`, `code` (the fixed error code), `dur` and `size` buckets; aggregated
    lines carry `count` instead of `tenant`, `device`, `dur` and `size` (see 42).
25. `net/http` writes client addresses into its own error messages; the gateway replaces them with
    a fixed class and drops TLS handshake errors entirely. Error logs carry fixed messages and
    classes only, never decoder messages (they can quote request bytes).

## TLS (§4.3)

26. TLS 1.3 only; Go's TLS 1.3 suites are exactly the three listed in §4.3 (not configurable in
    Go). Session-ticket keys are random per process, so tickets never survive a restart. No client
    certificates. HTTP/2 and HTTP/1.1 via ALPN. The certificate is a self-signed P-256 certificate
    valid 20 years (only its key is pinned); its SANs are the hosts of the configured URLs.
27. HTTP timeouts: 10 s for headers, 120 s to read a request (a 20 MB mail over a slow uplink),
    150 s to write, 60 s idle, 16 KiB of headers. Bodies must also make progress (see 41).
    HTTP/2: at most 32 concurrent streams per connection. Connections: see 46.

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
33. Supplementary map (`lookup/internal/rdap/supplement.json`, extendable with
    `ZETRU_RDAP_SUPPLEMENT`): `.de` and `.ch` → `unknown` without a query (their RDAP services
    return no registration event, checked 2026-11-23), `.io` → the registry operator's RDAP
    service. `.at` and `.eu` have no RDAP service in the bootstrap and are `unknown`.
34. Status mapping: registration event → `ok`; HTTP 404, no registration event, an implausible
    date (before 1985 or in the future), or no RDAP service for the TLD → `unknown`; anything
    else → `error`. `ok`/`unknown` are cached 30 days, registry errors 10 minutes; local rate
    limiting and the caller's deadline are not cached. The handler gives up after 2.8 s (the
    caller's timeout is 3 s). Cache bounds and concurrency: see 51.
35. Per-registry-host token bucket (default 1 request/s, burst 6 = the per-mail budget), waits of
    at most 1 s; HTTP 429 backs the host off for its `Retry-After` (≤ 15 minutes). Concurrent
    requests for the same domain share one upstream query.
36. Network guard: the dialer refuses anything but public unicast addresses on port 443 (checked on
    the resolved address), redirects only to `https` hosts that are RDAP servers in the bootstrap or
    the supplementary map, responses ≤ 512 KB, no proxy. Logs contain no domains. "Public" excludes
    every IANA special-purpose range that can lead elsewhere (see 52).

## Security review fixes (2026-11-23, findings GO-01 … GO-19)

37. **Campaign file: streamed binary records (GO-01).** `Save` built a full second copy of the
    store (base64 strings) and then one JSON buffer: about 4× the live heap, 511 MiB at the old caps
    against a 256 MB container. Now `state/campaign.dat` is a record format (header with a `K_fp`
    check value, one record per band, reference or report, SHA-256 trailer). `Save` copies only the
    key lists (32 bytes per entry) and encodes batches of 256 records under the lock, writing them
    to disk outside it; `Open` decodes record by record. Binary instead of streamed JSON: about a
    quarter of the size (SD-card wear, every 5 minutes), and a decoder without a token walk. The
    trailer detects a damaged file, which is then deleted. Measured at the pi caps in the worst
    case (every band with 32 seen and 32 reporters): live 65 MiB, file 59 MiB, `Save` allocates
    3 MiB and peaks at 69 MiB, `Open` peaks at 70 MiB (`TestSaveAndOpenMemoryAtTheCap`; limit
    asserted: 104 MiB = GOMEMLIMIT 200 MiB − 96 MiB body budget). Typical bands (2 members): live
    17 MiB. The old `campaign.json` is deleted at the first start; counting restarts once.
38. **Campaign caps per profile (GO-01).** `config.Profile` carries `CampaignMaxBands` and
    `CampaignMaxRefs`: pi 40,000 / 40,000, vps 120,000 / 120,000, sized from the measurement in 37.
    A file written under larger caps (profile switch) is trimmed while it loads, so loading never
    holds more than 110 % of the caps.
39. **Fair eviction instead of a fixed per-tenant cap (GO-05).** The review suggested a cap of
    `MaxBands / 8` per tenant. With one tenant (the household case) that would waste 7/8 of the
    capacity. Instead, when a cap is exceeded the store evicts down to 90 % by water filling: only
    the largest scopes lose entries, down to a common level, so a tenant (or the global scope)
    loses entries only while it holds more than the others, and one tenant alone may use
    everything. Inside a scope, bands without reporters go first, oldest first: a flood of
    sightings cannot erase reports. References and reports are evicted per tenant the same way.
    New global bands are limited to a tenth of the band cap per tenant and UTC day (existing global
    bands are always updated; beyond the allowance the tenant reads its own scope for the new
    bands). Reports may always create global bands: they are bounded by the 50-per-day report
    quota.
40. **Signature before body (GO-02, GO-08).** The signature covers `Zetru-Content-SHA256`, not the
    body, so the gateway verifies it before it reads the body and only then records the nonce and
    takes an analyze slot; the body is afterwards checked against the signed hash. §4.4 lists the
    checks in this order now. Effect: without the device key nobody can hold a slot, a nonce or
    body memory (the review's fixes, a pending-reservation cap and per-device slots, only limited
    this). The observable error codes are unchanged for every request a client can build (a body
    mismatch was already `bad_signature`). The extra cost for unauthenticated requests is one
    ECDSA verification, which the old order also spent after reading the body.
41. **Upload limits (GO-02).** For key holders (a paying tenant uploading slowly): at most 2
    concurrent analyze uploads per device and half of the slots per tenant; `Content-Length` is
    required for `/v1/analyze` (`400 bad_request` otherwise, the slot and budget are sized by it);
    every body must deliver 16 KiB per 5 s (read deadline moved forward through
    `http.ResponseController`, capped at the 120 s request deadline; reset to that deadline after
    the body, so it cannot fire while the analyzer works). On HTTP/1.x a response to a request
    whose body was not read carries `Connection: close`: net/http would otherwise first try to
    read up to 256 KiB of the body before answering, so a refused stalled upload would wait for its
    read timeout. Not on HTTP/2, where the stream is reset and the header would close the whole
    connection.
42. **Request log volume (GO-03).** Requests that do not authenticate are counted per minute,
    endpoint, status and code (one line per key with `count`, no tenant or device); this includes
    failures for a known device ID (anyone may send them) and `GET /healthz`. Authenticated requests
    and successful enrolments keep one line each. A daily file is capped at 50 MB; further lines
    are dropped and a closing `log_cap_reached` line counts them, so 15 files stay under 750 MB and
    the log cannot fill the volume that holds the registry and keys. Not done: a separate volume or
    tmpfs for logs (a tmpfs would count against the container's memory, a volume does not bound
    the size).
43. **Analyzer call detached from the client (GO-04).** The analyzer request uses
    `context.WithoutCancel(r.Context())` plus the 22 s timeout: a client that resets the stream
    after uploading neither gets its quota unit back nor skips the counter update, and the work it
    caused is counted. A cancelled context never refunds; refunds remain for analyzer `503` and an
    unreachable analyzer. url/check stays bound to the client (no quota, no counters).
44. **Replay window after a restart (GO-11).** During the first 2 × 120 s after the start, a request
    whose timestamp is before the start second is `401 stale_timestamp` (the app retries once with a
    fresh timestamp after syncing from `Date`). Second granularity: a request signed in the very
    second of the restart is not covered, which needs a broken TLS channel and a restart within
    that second.
45. **Strict JSON where bytes are forwarded (GO-07).** `encoding/json` matches keys to struct fields
    case-insensitively (the last one wins) while the app and Python read keys exactly. The gateway
    now refuses duplicate keys and keys equal under Unicode simple case folding (the same folding
    `encoding/json` uses, so `K` U+212A and `ſ` U+017F count) in: the analyzer's top-level response,
    every signal, the url/check response and its results and feeds, and the analyze meta JSON (which
    the analyzer re-reads). Signals and the url/check response are re-encoded from the validated
    values. Nested values the gateway does not interpret (evidence) pass through; the app validates
    them (§4.7).
46. **Connection limits (GO-12).** The listener admits at most `MaxConns` connections (pi 256, vps
    1,024; `Accept` waits for a free slot) and `MaxConnsPerAddr` per client key (pi 64, vps 128;
    further connections are closed at once); a client key is the IPv4 address or the IPv6 /64.
    Profile values rather than the review's 512/32: a pi has little memory per connection, and many
    devices behind one company NAT must still connect on vps. Registry: `mutate` no longer holds
    the in-memory lock across `flock`, parsing and fsync; it swaps the new state in after the
    write (still under the flock, so states are installed in write order). Unknown, used and
    expired enrolment tokens are answered from memory without the file lock.
47. **Enrolment rate limits (GO-13).** Charged only for unknown tokens: 5 per minute per client key
    (IPv4 address, IPv6 /64) and 60 per minute in total. A token the operator issued is never
    limited, so neither a NAT/userland proxy nor an address flood can block pairing. The per-key
    table still fails closed when full, which now only affects unknown tokens.
48. **Registry refresh under the lock (GO-09).** `refresh` reads and installs the file under the
    exclusive lock; `mutate` installs only after writing. A refresh can therefore never install a
    state older than one already installed. Chosen over a generation comparison because an operator
    who restores an older `registry.json` must still be picked up.
49. **Device labels (GO-18).** Bidi controls, zero-width and other format characters (Cf), line and
    paragraph separators and private-use characters are removed when a label is stored, listed by
    `GET /v1/devices` and printed by the CLI; control characters still make the enrolment
    `400 bad_request`. Removed, not refused (the review's suggestion): a device name may contain a
    zero-width joiner inside an emoji sequence, and refusing it would make pairing fail for it.
50. **No moved-aside files (GO-17).** Corrupt or foreign `campaign.dat`, `quota.json` and
    `rdap-cache.json` are deleted instead of renamed; leftovers of earlier versions
    (`*.discarded`, `*.corrupt`, `campaign.json`) are deleted at start. A moved-aside copy would
    hold data up to twice the retention period. After a tenant deletion `registry.json.bak` is
    rewritten from the new state.
51. **Lookup cache and concurrency (GO-15).** The cache is bounded at insert time (100,000 domains
    and 16 MiB of names; when full, expired entries and then the oldest are evicted down to 90 %,
    amortised over the inserts this frees). At most 32 lookups run at once; more get `503 busy` at
    once (the analyzer treats it as `unknown`). The cache file is written and read as a stream. The
    network split (GO-16) keeps everything but the analyzer away from the service.
52. **Lookup address guard (GO-14).** `netip`-based: IPv4-mapped addresses are judged as IPv4,
    zone-scoped addresses are refused, IPv6 must be in 2000::/3, and NAT64 (64:ff9b::/96,
    64:ff9b:1::/48), 6to4 (2002::/16), 2001::/23 (Teredo and other IETF assignments), discard,
    SRv6 and the IPv4/IPv6 documentation ranges are refused besides the private ones. Dual-stack is
    kept (no `tcp4`-only dialing): some registries serve RDAP over IPv6.
53. **Networks and gateway egress (GO-16).** `core` is replaced by `gw-analyzer`,
    `analyzer-inference` and `analyzer-lookup` (all internal). The published `edge` network cannot be
    internal; its bridge is named `zetru-edge` so that `deploy/gateway-egress-firewall.sh`
    can drop new connections from it in `DOCKER-USER` (forwarded) and `INPUT` (to the host). Not
    used: the bridge option that disables IP masquerading, because its interplay with published
    ports and the userland proxy could not be tested here; the script is the documented,
    reversible mechanism.
54. **Pinned build inputs (GO-06).** The Dockerfile frontend (`docker/dockerfile:1.29.0`), the Go
    build image (`golang:1.27.4-alpine3.24`), `distroless/static-debian12:nonroot` and
    `alpine:3.22.8` (resolver, backup/restore) are pinned by digest, resolved from the registries on
    2026-11-23; the resolver's `unbound`, `unbound-libs`, `drill` and `ldns` by version. Alpine keeps
    only the newest build of a package per branch, so a security update breaks the build until
    `deploy/pin-images.sh update` re-resolves the pins (a failed build is the point: no
    silent drift). `pin-images.sh check` fails on any unpinned reference in this repository; the gateway's
    `go test ./...` (`internal/deploycheck`) enforces it for the Go services, the resolver,
    `zetru-server` and the README. Longer term: signed, published images pulled by digest.
55. **Resolver (GO-19).** `ip-ratelimit: 100` (queries per second from the analyzer; vps peak 4
    workers × 25 queries per mail, above the review's 50, which a busy vps could reach legitimately)
    and `ratelimit: 20` per upstream zone bound the DNS channel of a compromised analyzer.
    `private-address` now also covers 0/8, 127/8, 192.0.0.0/24, 198.18/15, `::`, `::1`,
    `::ffff:0:0/96`, `64:ff9b::/96` and `fc00::/7`. The entrypoint runs `unbound-anchor` on every
    start (falling back to the build-time snapshot), and the README asks for a yearly rebuild.
