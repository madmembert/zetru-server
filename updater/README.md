# updater

Downloads, validates and atomically publishes the default feeds (concept §6.7). Standard library only.

## Container

| Item | Value |
|---|---|
| Build | `docker build -t zetru/updater:1.0.0 updater` |
| Command | `python3 -m zetru_updater` (schedule loop); `python3 -m zetru_updater --once` processes due feeds once |
| Port | none |
| User | uid/gid 10005; `/feeds` and `/models` are created in the image owned by 10005 (fresh named volumes inherit it) |
| Networks | `egress` only (HTTPS to the manifest hosts) |
| Volumes | `feeds:/feeds` (rw), `models:/models` (rw, unused in v1: no model is released yet) |
| tmpfs | not needed: downloads are staged on the feeds volume in `/feeds/.staging` (`ZETRU_STAGING_DIR`), so the ~100 MB Majestic file does not count against the memory limit |
| Health | compose checks that `/feeds/psl/current.json` exists and is younger than 3 days |

## Environment

`ZETRU_FEEDS_DIR` (`/feeds`), `ZETRU_STAGING_DIR` (`/feeds/.staging`), `ZETRU_ALLOW_NONCOMMERCIAL` (`0`; a manifest entry
with `commercial: false` is refused unless `1`). Standard `HTTPS_PROXY` is honoured.

## Feeds (`zetru_updater/manifest.json`, verified 2026-11-22)

| ID | URL | Licence | Refresh |
|---|---|---|---|
| `psl` | https://publicsuffix.org/list/public_suffix_list.dat | MPL 2.0 | 24 h |
| `iana-tlds` | https://data.iana.org/TLD/tlds-alpha-by-domain.txt | IANA public data | 24 h |
| `rdap-bootstrap` | https://data.iana.org/rdap/dns.json | IANA public data | 24 h |
| `certpl` | https://hole.cert.pl/domains/v2/domains.txt | CERT Polska data usage policy: any use incl. commercial, no attribution required, no implied endorsement | 5 min |
| `majestic` | https://downloads.majestic.com/majestic_million.csv | CC BY 3.0 (attribution in current.json) | 24 h, never more often |
| `disposable` | https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/main/disposable_email_blocklist.conf | CC0 | 24 h |

## Pipeline

Allow-listed host, HTTPS only, redirects refused, size capped while streaming, truncated bodies rejected
(Content-Length check), conditional GET (ETag/Last-Modified) → parse and normalise (IDNA, lowercase) → syntax check
(≤ 5 % invalid lines), size and entry bounds, change ratio (reject > 50 % removed or > 300 % added, both against the
previous release and against a reference release that moves at most once per 24 h, `reference.json`), never-list
guard for `certpl` and `disposable` (static `never_list.txt` from the brand/freemail packs — the names and all their
subdomains —, Majestic top 1,000 — exact names only —, and public suffixes including wildcard rules; more than
max(10, 1 %) hits rejects the release as poisoned) → write `/<id>/.tmp-<version>/`, fsync, rename to
`/<id>/<version>/`, replace `current.json` atomically. Files 0644, directories 0755. Three versions plus the
reference are kept. A 304 or identical content only refreshes `fetched_at`. Failures back off exponentially (max =
refresh interval); the attempt time is saved before each download, so a killed run still counts. Unguarded feeds are
processed before guarded ones. A missing or stale feed is reported by the analyzer as `ANALYSIS_PARTIAL`, never as
clean.

`current.json`: `{"version","fetched_at","entries","sha256" (of the published file),"licence","commercial",
"attribution","refresh_s","path":"<version>/<file>"}`.

## Tests

From the repository root: `.venv/bin/python -m pytest updater/tests`.
