"""Feed mirrors held by the supervisor (never by workers): blocklists, popularity and disposable domains.

Domains are stored as sorted 64-bit BLAKE2b hashes (8 bytes per entry; the Majestic Million costs ~8 MB
instead of ~100 MB as a Python set). Lookups check the host and every parent with at least two labels,
because CERT Polska recommends blocking subdomains of listed domains; parents are never inferred to be
listed from a listed child.
"""

from __future__ import annotations

import bisect
import hashlib
import time
from array import array
from dataclasses import dataclass

from . import feedfiles, logs

BLOCKLISTS = ("certpl",)
REQUIRED = ("psl", "certpl", "majestic", "disposable")
UNKNOWN_AGE = 2_147_483_647


def _h(domain: str) -> int:
    return int.from_bytes(hashlib.blake2b(domain.encode("ascii", "ignore"), digest_size=8).digest(), "big")


class HashSet:
    def __init__(self, values=()):
        hashes = array("Q", sorted({_h(v) for v in values}))
        self._data = hashes

    @classmethod
    def from_file(cls, path: str, limit: int = 3_000_000) -> "HashSet":
        out = cls()
        hashes = set()
        with open(path, "r", encoding="ascii", errors="ignore") as handle:
            for i, line in enumerate(handle):
                if i >= limit:
                    break
                value = line.strip()
                if value and not value.startswith("#"):
                    hashes.add(_h(value.lower()))
        out._data = array("Q", sorted(hashes))
        return out

    def __len__(self) -> int:
        return len(self._data)

    def __contains__(self, domain: str) -> bool:
        h = _h(domain)
        i = bisect.bisect_left(self._data, h)
        return i < len(self._data) and self._data[i] == h


def suffixes(host: str) -> list[str]:
    labels = host.split(".")
    return [".".join(labels[i:]) for i in range(len(labels) - 1)]


@dataclass
class LoadedFeed:
    info: feedfiles.FeedInfo
    data: HashSet | None
    mtime: float | None


class FeedStore:
    def __init__(self, feeds_dir: str | None):
        self.feeds_dir = feeds_dir
        self.feeds: dict[str, LoadedFeed] = {}

    def reload(self) -> set[str]:
        """Loads feeds whose current.json changed; returns the IDs that changed."""
        changed: set[str] = set()
        if not self.feeds_dir:
            return changed
        for feed_id in REQUIRED:
            mtime = feedfiles.current_mtime(self.feeds_dir, feed_id)
            loaded = self.feeds.get(feed_id)
            if mtime is None or (loaded is not None and loaded.mtime == mtime):
                continue
            info = feedfiles.read_current(self.feeds_dir, feed_id)
            if info is None:
                logs.warning("feed_invalid", feed=feed_id)
                continue
            if loaded is not None and loaded.info.version == info.version:
                data = loaded.data  # metadata refresh only (e.g. a not-modified download)
            else:
                try:
                    data = None if feed_id == "psl" else HashSet.from_file(info.data_path)
                except OSError:
                    logs.warning("feed_unreadable", feed=feed_id)
                    continue
            self.feeds[feed_id] = LoadedFeed(info, data, mtime)
            changed.add(feed_id)
            logs.info("feed_loaded", feed=feed_id, count=info.entries)
        return changed

    def lookup(self, host: str, reg: str | None) -> dict:
        listed = []
        candidates = suffixes(host) or [host]
        for feed_id in BLOCKLISTS:
            feed = self.feeds.get(feed_id)
            if feed and feed.data is not None and any(c in feed.data for c in candidates):
                listed.append(feed_id)
        disposable = self.feeds.get("disposable")
        majestic = self.feeds.get("majestic")
        return {
            "listed": listed,
            "disposable": bool(disposable and disposable.data is not None
                               and any(c in disposable.data for c in candidates)),
            "popular": bool(majestic and majestic.data is not None
                            and ((reg and reg in majestic.data) or host in majestic.data)),
        }

    def url_hash_listed(self, url_sha256: str) -> list[str]:
        return []  # no URL-hash feed is enabled by default (bring-your-own-key feeds only)

    def states(self, now: int | None = None) -> list[dict]:
        now = int(time.time()) if now is None else now
        out = []
        for feed_id in REQUIRED:
            feed = self.feeds.get(feed_id)
            if feed is None:
                out.append({"id": feed_id, "age_s": UNKNOWN_AGE, "stale": True})
                continue
            age = max(0, now - feed.info.fetched_at)
            out.append({"id": feed_id, "age_s": age, "stale": age > 3 * feed.info.refresh_s})
        return out

    def completeness(self, now: int | None = None) -> str:
        states = {s["id"]: s for s in self.states(now)}
        if all(states[b]["age_s"] == UNKNOWN_AGE for b in BLOCKLISTS):
            return "failed"
        return "partial" if any(s["stale"] for s in states.values()) else "ok"
