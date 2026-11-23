"""Reading feeds published by the updater on the read-only `feeds` volume (server-internal-api.md).

Layout: /feeds/<feed-id>/<version>/<file> plus /feeds/<feed-id>/current.json. The data file's SHA-256 is
verified against current.json before use; a mismatch or any malformed field means "feed absent".
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass

_FEED_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,47}")
_REL_PATH = re.compile(r"[A-Za-z0-9_.-]{1,64}/[A-Za-z0-9_.-]{1,64}")
MAX_CURRENT_JSON = 16_384


@dataclass(frozen=True)
class FeedInfo:
    feed_id: str
    version: str
    fetched_at: int
    entries: int
    sha256: str
    licence: str
    commercial: bool
    attribution: str | None
    refresh_s: int
    data_path: str


def read_current(feeds_dir: str, feed_id: str, verify_hash: bool = True) -> FeedInfo | None:
    if not _FEED_ID.fullmatch(feed_id):
        return None
    feed_dir = os.path.join(feeds_dir, feed_id)
    try:
        with open(os.path.join(feed_dir, "current.json"), "rb") as handle:
            raw = handle.read(MAX_CURRENT_JSON + 1)
        if len(raw) > MAX_CURRENT_JSON:
            return None
        doc = json.loads(raw)
        rel = doc["path"]
        if not isinstance(rel, str) or not _REL_PATH.fullmatch(rel) or ".." in rel.split("/"):
            return None
        info = FeedInfo(
            feed_id=feed_id,
            version=str(doc["version"])[:64],
            fetched_at=int(doc["fetched_at"]),
            entries=int(doc["entries"]),
            sha256=str(doc["sha256"]).lower(),
            licence=str(doc["licence"])[:64],
            commercial=bool(doc["commercial"]),
            attribution=None if doc.get("attribution") is None else str(doc["attribution"])[:200],
            refresh_s=max(60, int(doc["refresh_s"])),
            data_path=os.path.join(feed_dir, rel),
        )
        real_dir = os.path.realpath(feed_dir)
        if not os.path.realpath(info.data_path).startswith(real_dir + os.sep):
            return None
        if verify_hash and sha256_file(info.data_path) != info.sha256:
            return None
        return info
    except (OSError, ValueError, KeyError, TypeError):
        return None


def sha256_file(path: str) -> str:
    out = ""
    for out in sha256_file_steps(path):
        pass
    return out


def sha256_file_steps(path: str):
    """Hashes in 1 MiB steps; yields "" after each step and the hex digest last (lets the supervisor's event
    loop run in between, PY-22)."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
            yield ""
    yield digest.hexdigest()


def current_mtime(feeds_dir: str, feed_id: str) -> float | None:
    try:
        return os.stat(os.path.join(feeds_dir, feed_id, "current.json")).st_mtime
    except OSError:
        return None
