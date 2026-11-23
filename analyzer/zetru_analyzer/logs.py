"""Content-free logging (concept §11.5).

Only fixed event names, error classes, stages, status codes and coarse buckets are logged. Never mail
content, subjects, addresses, domains, URLs, hashes or evidence. Callers pass keyword fields; any field
that is not on the allow-list is dropped, and string values are restricted to a short safe alphabet so a
mistaken call cannot leak data.
"""

from __future__ import annotations

import json
import re
import sys
import time

_ALLOWED_FIELDS = frozenset({
    "event", "stage", "error_class", "status", "endpoint", "tenant", "duration_bucket", "size_bucket",
    "workers", "queue", "feed", "feed_status", "reason", "pid_role", "count", "arch", "backend",
})
_SAFE_VALUE = re.compile(r"[A-Za-z0-9_.:\-/]{0,64}")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def _clean(key: str, value):
    if isinstance(value, bool) or isinstance(value, int):
        return value
    if isinstance(value, float):
        return round(value, 3)
    if not isinstance(value, str):
        return "?"
    if key == "tenant":
        return value if _UUID.fullmatch(value) else "invalid"
    return value if _SAFE_VALUE.fullmatch(value) else "redacted"


def log(level: str, event: str, **fields) -> None:
    record = {"ts": int(time.time()), "level": level, "svc": "analyzer", "event": _clean("event", event)}
    for key, value in fields.items():
        if key in _ALLOWED_FIELDS:
            record[key] = _clean(key, value)
    try:
        sys.stderr.write(json.dumps(record, separators=(",", ":")) + "\n")
        sys.stderr.flush()
    except Exception:  # logging must never break request handling
        pass


def info(event: str, **fields) -> None:
    log("info", event, **fields)


def warning(event: str, **fields) -> None:
    log("warning", event, **fields)


def error(event: str, **fields) -> None:
    log("error", event, **fields)


def duration_bucket(seconds: float) -> str:
    for limit, name in ((0.5, "lt0.5s"), (1, "lt1s"), (2, "lt2s"), (6, "lt6s"), (20, "lt20s")):
        if seconds < limit:
            return name
    return "ge20s"


def size_bucket(n: int) -> str:
    for limit, name in ((16_384, "lt16k"), (262_144, "lt256k"), (1_048_576, "lt1m"), (5_242_880, "lt5m")):
        if n < limit:
            return name
    return "ge5m"
