# analyzer

Parses and analyses one mail per sandboxed worker and returns signals (concept §3.2, §6, §11.2;
`docs/server-internal-api.md`). Python 3.12, image built from this directory.

## Container

| Item | Value |
|---|---|
| Build | `docker build -t zetru/analyzer:1.0.0 analyzer` (context = this directory) |
| Command | `python3 -m zetru_analyzer` |
| Port | 8081, plain HTTP, `core` network only |
| User | uid/gid 10002 (set in the image; compose also sets it) |
| Networks | `core` (gateway, inference, lookup) and `dns` (resolver). No other egress. |
| Volumes | `feeds:/feeds:ro` (written by the updater) |
| tmpfs | none needed: the service writes no files (the compose file still mounts `/tmp`; it can be dropped) |
| Health | `GET /internal/healthz` → `{"status","feeds","backends"}` |

## Endpoints

- `POST /internal/v1/analyze` — framed body of §11.2; headers `X-Zetru-Tenant`, `X-Zetru-Policy`
  (base64url JSON `{"backends":[…],"max_mail_bytes":int}`, `max_mail_bytes` ≤ 20 MiB). Response: §11.2 object
  without `fingerprint`, plus `campaign_bands` (4 × 4 hex chars or `null`). Errors: `400 bad_request` (also for a
  missing or malformed tenant UUID), `413 mail_too_large`, `503 busy` (Retry-After 30; decided before the body is
  read), `503 analyzer_unavailable` (Retry-After 900; only when the worker sandbox cannot be set up),
  `504 analysis_timeout` (the supervisor's 20 s deadline). Whatever a mail makes a worker do (exception, CPU or
  wall-clock kill, crash) is `200` with `parse: failed`, `MIME_MALFORMED` and `MIME_LIMITS`.
- `POST /internal/v1/url/check` — §11.3, feed lookups only; needs `X-Zetru-Tenant`.
- `GET /internal/healthz` — `503` with `"status":"degraded"` when the zygote is dead or hung.

## Environment

| Variable | Default | Meaning |
|---|---|---|
| `ZETRU_PROFILE` | `pi` | `pi` (2 workers, queue 8) or `vps` (4, 32) |
| `ZETRU_WORKERS` / `ZETRU_QUEUE` | profile | concurrent workers / waiting requests |
| `ZETRU_INFERENCE_URL` | `http://inference:8082` | typed decisions |
| `ZETRU_LOOKUP_URL` | `http://lookup:8083` | RDAP domain age |
| `ZETRU_RESOLVER_HOST` | `resolver` | Unbound (TXT queries only) |
| `ZETRU_FEEDS_DIR` | `/feeds` | feed volume |
| `ZETRU_ANALYZER_PORT` | `8081` | listen port |
| `ZETRU_SANDBOX` | `enforce` | `off` disables the worker sandbox (local development only) |

## Process model

`supervisor` (asyncio, no threads) → `zygote` (exec'd once, pre-imports everything, holds no feed data)
→ one forked `worker` per mail. Supervisor and zygote are not dumpable (`PR_SET_DUMPABLE 0`), so a worker cannot
open their `/proc/<pid>/mem`; the supervisor ignores SIGINT. The worker closes every inherited descriptor except
its socket, then applies `PR_SET_PDEATHSIG`, `PR_SET_DUMPABLE 0`, rlimits (AS 768 MB, CPU 10 s, NOFILE 32,
FSIZE 0, NPROC 0, CORE 0), `PR_SET_NO_NEW_PRIVS` and a seccomp-BPF filter (x86_64 and aarch64, architecture
checked, x32 rejected) that returns EPERM for sockets, process creation (execve, clone, fork, unshare, setns),
every signal syscall, ptrace/process_vm_*/kcmp/pidfd_*, file-system changes (mkdir, link, symlink, unlink,
rename, truncate, chmod, chown, xattr writes, utimes, creat, openat2 and open/openat with write/create flags),
SysV/POSIX IPC, keyrings, memfd, bpf, userfaultfd, perf_event_open, io_uring, mount and the new mount API, and
`prctl` (full list in `sandbox.py`). The zygote kills a worker after 15 s (CPU limit 10 s); the supervisor answers
`504` after 20 s. A zygote that leaves two spawns unanswered is replaced. All outside data (TXT records, feed lookups, domain ages, typed
decisions) is brokered by the supervisor with per-mail budgets (25 DNS names of the shapes `_dmarc.<d>`,
`<s>._domainkey.<d>`, `<d>`; 40 feed lookups; 6 age lookups; 1 inference call with the tenant's backends; at most
4 broker round trips; replies ≤ 512 KiB, TXT data reduced to printable ASCII). The supervisor validates every
worker result against a strict schema before it is returned.

Host requirement (defence in depth): `kernel.yama.ptrace_scope` ≥ 1 (Debian and Raspberry Pi OS ship 0; set it in
`/etc/sysctl.d/`). The analyzer does not rely on it, because supervisor and zygote are not dumpable.

## Curated packs

`zetru_analyzer/packs/`: `brands-de-en.json` (123 brands/authorities), `freemail.json`, `ugc-hosting.json`,
`shorteners.json`, `redirectors.json`, `esp-click-trackers.json`, `dangerous-extensions.json`. Entries that need
verification carry `review` notes. `data/` holds the bundled Public Suffix List (MPL 2.0, fallback when the feed
is missing) and Unicode `confusables.txt` (Unicode License v3).

## Tests

From the repository root: `.venv/bin/python -m pytest analyzer/tests` (needs `requirements-dev.txt`). The real seccomp
and `PR_SET_DUMPABLE` tests run only on Linux; run them there (x86_64 and aarch64) after changing `sandbox.py`.
`tests/test_review_analyzer.py` holds the regression tests of the security review. Design decisions:
`DECISIONS.md`.
