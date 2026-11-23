"""Feed mirrors held by the supervisor (never by workers): blocklists, popularity and disposable domains.

Domains are stored as sorted 64-bit BLAKE2b hashes (8 bytes per entry; the Majestic Million costs ~8 MB
instead of ~100 MB as a Python set). Lookups check the host and every parent with at least two labels,
because CERT Polska recommends blocking subdomains of listed domains; parents are never inferred to be
listed from a listed child.

Never-list guard (security review PY-11): a host that is, or lies below, an official brand domain or a freemail
domain of the analyzer's packs is never reported as listed or disposable, whatever a feed contains. This is the
same rule the updater applies when it publishes a guarded feed, checked again here so that the guarantee does not
rest on the updater alone. (Filtering at load time and at lookup time give the same result: an entry below a
never-list name can only match hosts below that name.)

Loading is done in steps (`reload_async`) so that hashing and parsing a large feed never blocks the supervisor's
event loop for long (PY-22).
"""

from __future__ import annotations

import asyncio
import bisect
import hashlib
import heapq
import time
from array import array
from dataclasses import dataclass
from itertools import islice

from . import feedfiles, logs

BLOCKLISTS = ("certpl",)
REQUIRED = ("psl", "certpl", "majestic", "disposable")
UNKNOWN_AGE = 2_147_483_647


def _h(domain: str) -> int:
    return int.from_bytes(hashlib.blake2b(domain.encode("ascii", "ignore"), digest_size=8).digest(), "big")


STEP_LINES = 50_000
SORT_CHUNK = 100_000


class HashSet:
    def __init__(self, values=()):
        hashes = array("Q", sorted({_h(v) for v in values}))
        self._data = hashes

    @classmethod
    def from_file(cls, path: str, limit: int = 3_000_000) -> "HashSet":
        out = None
        for out in cls.load_steps(path, limit):
            pass
        return out

    @classmethod
    def load_steps(cls, path: str, limit: int = 3_000_000):
        """Reads, hashes and sorts in steps; yields None between steps and the finished HashSet last."""
        hashes: set[int] = set()
        with open(path, "r", encoding="ascii", errors="ignore") as handle:
            for i, line in enumerate(handle):
                if i >= limit:
                    break
                value = line.strip()
                if value and not value.startswith("#"):
                    hashes.add(_h(value.lower()))
                if i % STEP_LINES == STEP_LINES - 1:
                    yield None
        values = list(hashes)
        del hashes
        runs = []
        for start in range(0, len(values), SORT_CHUNK):
            runs.append(sorted(values[start:start + SORT_CHUNK]))
            yield None
        del values
        merged = heapq.merge(*runs)
        data = array("Q")
        while True:
            block = list(islice(merged, SORT_CHUNK))
            if not block:
                break
            data.extend(block)
            yield None
        out = cls()
        out._data = data
        yield out

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


def default_never() -> frozenset[str]:
    """Official brand domains and freemail domains of the bundled packs."""
    from .packs import default_packs

    packs = default_packs()
    return frozenset(packs.all_official) | packs.freemail


class FeedStore:
    def __init__(self, feeds_dir: str | None, never: frozenset[str] | None = None):
        self.feeds_dir = feeds_dir
        self.feeds: dict[str, LoadedFeed] = {}
        self._never = never

    @property
    def never(self) -> frozenset[str]:
        if self._never is None:
            self._never = default_never()
        return self._never

    def never_listed(self, host: str) -> bool:
        """True when `host` equals or lies below a never-list name."""
        labels = host.split(".")
        return any(".".join(labels[i:]) in self.never for i in range(len(labels) - 1))

    def reload(self) -> set[str]:
        """Loads feeds whose current.json changed; returns the IDs that changed."""
        changed: set[str] = set()
        for _ in self._reload_steps(changed):
            pass
        return changed

    async def reload_async(self) -> set[str]:
        changed: set[str] = set()
        for _ in self._reload_steps(changed):
            await asyncio.sleep(0)
        return changed

    def _reload_steps(self, changed: set[str]):
        if not self.feeds_dir:
            return
        for feed_id in REQUIRED:
            mtime = feedfiles.current_mtime(self.feeds_dir, feed_id)
            loaded = self.feeds.get(feed_id)
            if mtime is None or (loaded is not None and loaded.mtime == mtime):
                continue
            info = feedfiles.read_current(self.feeds_dir, feed_id, verify_hash=False)
            digest = None
            if info is not None:
                try:
                    for digest in feedfiles.sha256_file_steps(info.data_path):
                        yield
                except OSError:
                    digest = None
            if info is None or digest != info.sha256:
                logs.warning("feed_invalid", feed=feed_id)
                continue
            if loaded is not None and loaded.info.version == info.version:
                data = loaded.data  # metadata refresh only (e.g. a not-modified download)
            elif feed_id == "psl":
                data = None
            else:
                data = None
                try:
                    for data in HashSet.load_steps(info.data_path):
                        if data is None:
                            yield
                except OSError:
                    logs.warning("feed_unreadable", feed=feed_id)
                    continue
            self.feeds[feed_id] = LoadedFeed(info, data, mtime)
            changed.add(feed_id)
            logs.info("feed_loaded", feed=feed_id, count=info.entries)
            yield

    def lookup(self, host: str, reg: str | None) -> dict:
        listed = []
        candidates = suffixes(host) or [host]
        guarded = self.never_listed(host)
        for feed_id in BLOCKLISTS:
            feed = self.feeds.get(feed_id)
            if not guarded and feed and feed.data is not None and any(c in feed.data for c in candidates):
                listed.append(feed_id)
        disposable = self.feeds.get("disposable")
        majestic = self.feeds.get("majestic")
        return {
            "listed": listed,
            "disposable": bool(not guarded and disposable and disposable.data is not None
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
