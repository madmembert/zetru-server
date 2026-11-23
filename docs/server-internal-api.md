# Zetru server: internal interfaces between containers

Binding companion to `docs/concept.md` §3.2 and §11. The public API (§11) is served only by the
`gateway`. Everything below is reachable only on the internal Docker networks and is never exposed.

## Ports and hosts

| Service | Host name | Port | Network |
|---|---|---|---|
| gateway | `gateway` | 8443 (TLS, published) | `edge`, `gw-analyzer` |
| analyzer | `analyzer` | 8081 (plain HTTP) | `gw-analyzer`, `analyzer-inference`, `analyzer-lookup`, `dns` |
| inference | `inference` | 8082 (plain HTTP) | `analyzer-inference` |
| lookup | `lookup` | 8083 (plain HTTP) | `analyzer-lookup`, `egress` |
| resolver (Unbound) | `resolver` | 53 UDP/TCP | `dns`, `egress` |
| updater | `updater` | none | `egress` |

All internal HTTP bodies are JSON (UTF-8) unless stated. Each internal service is reachable only on
the internal network it shares with its one caller: `gw-analyzer` (gateway → analyzer),
`analyzer-inference`, `analyzer-lookup`, `dns` (the compose file guarantees this); the services still
validate every input.

JSON objects the gateway validates and then signs or forwards (analyzer responses, signals in them,
url/check results, the meta JSON of an analyze request) must not contain duplicate keys or keys that
differ only in case (`"id"` next to `"ID"`); such a response is answered with
`503 analyzer_unavailable`, such a request with `400 bad_request`. The gateway re-encodes every
signal and the whole url/check response from the values it validated.

## gateway → analyzer

`POST http://analyzer:8081/internal/v1/analyze`

- Request body: exactly the public `/v1/analyze` body (4-byte big-endian meta length, meta JSON, raw
  message), already authenticated and size-checked by the gateway.
- Request headers: `X-Zetru-Tenant: <tenant uuid>`, `X-Zetru-Policy: <base64url(JSON)>` with
  `{"backends": ["rules", …], "max_mail_bytes": int}`.
- Response `200`: the public analyze response object of concept §11.2 **without** `fingerprint`,
  plus one internal field `campaign_bands`: an array of exactly 4 lowercase hex strings of 4 characters
  (the four 16-bit SimHash bands, §6.5) or `null` when no fingerprint could be computed. The gateway
  removes `campaign_bands`, computes `HMAC-SHA256(K_fp, band_index ‖ band)` per band, updates and reads
  the counters, adds `fingerprint` and any `BULK_CAMPAIGN_*` signals, then signs the response.
- Errors: `503 {"error":{"code":"busy",…}}` when the worker queue is full,
  `504 {"error":{"code":"analysis_timeout",…}}` after the 20 s hard timeout,
  `400 {"error":{"code":"bad_request",…}}` for broken framing. A mail that cannot be parsed is `200`
  with `completeness.parse = "failed"`.

`POST http://analyzer:8081/internal/v1/url/check`

- Body and response exactly as public `/v1/url/check` (§11.3), feed lookups only, no DNS.

`GET http://analyzer:8081/internal/healthz` → `{"status":"ok","feeds":[FeedState…],"backends":[…]}`.

## analyzer → inference

`POST http://inference:8082/v1/systemone` exactly as concept §11.3 (internal endpoint).
`GET http://inference:8082/healthz` → `{"status":"ok","backends":[{"id","enabled","calibrated","licence_notice"}]}`.

## analyzer → lookup

`GET http://lookup:8083/internal/v1/age?domain=<registrable domain>` →
`{"domain": string, "registered_on": int|null (Unix seconds), "status": "ok"|"unknown"|"error", "source": "rdap"|"cache"}`.
The lookup service caches results for 30 days (at most 100,000 domains and 16 MiB of names, oldest
evicted first), rate-limits per registry and never queries domains other than the one requested.
More than 32 lookups in progress are answered with `503 {"error":{"code":"busy",…}}` at once.
Timeout for the caller: 3 s (treat errors and timeouts as `unknown`).

## analyzer → resolver

DNS over UDP/TCP 53 to the host `resolver` (resolve its IP once at start-up through Docker DNS).
Query types allowed by the supervisor: TXT (DKIM keys, `_dmarc`), and nothing else in v1.

## Shared volumes

- `feeds` (written by `updater`, read-only for `analyzer`):
  `/feeds/<feed-id>/<version>/data…` plus `/feeds/<feed-id>/current.json` =
  `{"version": string, "fetched_at": int, "entries": int, "sha256": string, "licence": string,
  "commercial": bool, "attribution": string|null, "refresh_s": int, "path": "<version>/<file>"}`.
  The updater writes a new version directory, then replaces `current.json` atomically (write temp + rename).
  Feed IDs v1: `psl`, `iana-tlds`, `rdap-bootstrap`, `certpl`, `majestic`, `disposable`, plus the
  curated `zetru-*` packs shipped in the analyzer image.
- `models` (written by `updater`, read-only for `inference`): `/models/<backend>/<version>/…` plus
  `/models/<backend>/current.json`.
- `gateway-data` (gateway only): keys, registry, counters, request logs.
- `lookup-cache` (lookup only).

## Environment variables

| Variable | Used by | Meaning |
|---|---|---|
| `ZETRU_PROFILE` | all | `pi` or `vps` (concurrency defaults) |
| `ZETRU_ANALYZER_URL` | gateway | default `http://analyzer:8081` |
| `ZETRU_INFERENCE_URL` | analyzer | default `http://inference:8082` |
| `ZETRU_LOOKUP_URL` | analyzer | default `http://lookup:8083` |
| `ZETRU_RESOLVER_HOST` | analyzer | default `resolver` |
| `ZETRU_WORKERS` | analyzer | concurrent workers (pi 2, vps 4) |
| `ZETRU_QUEUE` | analyzer | queue length (pi 8, vps 32) |
| `ZETRU_ALLOW_NONCOMMERCIAL` | updater, inference | `1` enables non-commercial feeds/backends (default off) |
| `ZETRU_DATA_DIR` | gateway | default `/data` |
