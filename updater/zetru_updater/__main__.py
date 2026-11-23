"""Updater service: `python -m zetru_updater` runs the schedule loop; `--once` processes every due feed once.

Environment: ZETRU_FEEDS_DIR (/feeds), ZETRU_STAGING_DIR (download area; default <feeds dir>/.staging on the feeds
volume, so a 100 MB Majestic download is not charged to the container's memory limit as tmpfs would be, PY-14),
ZETRU_ALLOW_NONCOMMERCIAL (1 enables feeds whose manifest says commercial=false).

The attempt time is saved before a download starts, so a run that is killed (out of memory) still counts as an
attempt and Majestic is not fetched again before 24 h (PY-14). Feeds without the never-list guard (psl, majestic,
…) are processed before guarded ones in every pass, so the first certpl release on a fresh volume is already
filtered with the Majestic top 1,000 when Majestic is reachable (PY-25).
"""

from __future__ import annotations

import json
import os
import random
import sys
import time

from . import core, fetch

STATE_FILE = ".updater-state.json"
MIN_SLEEP_S = 10
MAX_SLEEP_S = 300


def log(event: str, **fields) -> None:
    record = {"ts": int(time.time()), "svc": "updater", "event": event}
    record.update(fields)
    sys.stderr.write(json.dumps(record) + "\n")
    sys.stderr.flush()


def load_state(feeds_dir: str, feed_id: str) -> dict:
    try:
        with open(os.path.join(feeds_dir, feed_id, STATE_FILE), "r", encoding="utf-8") as handle:
            doc = json.load(handle)
        return doc if isinstance(doc, dict) else {}
    except (OSError, ValueError):
        return {}


def save_state(feeds_dir: str, feed_id: str, state: dict) -> None:
    feed_dir = os.path.join(feeds_dir, feed_id)
    os.makedirs(feed_dir, mode=0o755, exist_ok=True)
    tmp = os.path.join(feed_dir, STATE_FILE + ".tmp")
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(state, handle)
    os.chmod(tmp, 0o644)
    os.replace(tmp, os.path.join(feed_dir, STATE_FILE))


def next_due(feed: core.Feed, state: dict, now: float) -> float:
    last_attempt = state.get("last_attempt", 0)
    if state.get("failures"):
        due = last_attempt + min(feed.refresh_s, 60 * 2 ** min(int(state["failures"]), 8))
    else:
        due = state.get("last_success", 0) + feed.refresh_s
    # Providers with a download limit (Majestic: at most once per 24 h) count every attempt.
    return max(due, last_attempt + feed.min_interval_s) if feed.min_interval_s else due


def run_feed(feed: core.Feed, feeds_dir: str, staging: str, hosts: set[str], opener=None, now=None) -> str:
    state = load_state(feeds_dir, feed.id)
    now = time.time() if now is None else now
    state["last_attempt"] = int(now)
    status = "error"
    try:
        save_state(feeds_dir, feed.id, state)   # before the download: a killed run still counts as an attempt
    except OSError:
        pass
    try:
        has_current = core.read_current(feeds_dir, feed.id) is not None
        result = fetch.fetch(feed.url, staging, hosts, feed.max_bytes,
                             etag=state.get("etag") if has_current else None,
                             last_modified=state.get("last_modified") if has_current else None, opener=opener)
        if result.status == "not_modified":
            core.touch_current(feeds_dir, feed, int(now))
            status = "not_modified"
        else:
            try:
                status, current = core.process_download(feeds_dir, feed, result.path, int(now))
            finally:
                if result.path and os.path.exists(result.path):
                    os.unlink(result.path)
            state["etag"], state["last_modified"] = result.etag, result.last_modified
        state["last_success"] = int(now)
        state["failures"] = 0
    except core.ValidationError as exc:
        status = f"rejected:{exc}"
        state["failures"] = int(state.get("failures", 0)) + 1
    except fetch.FetchError as exc:
        status = f"fetch_failed:{exc}"
        state["failures"] = int(state.get("failures", 0)) + 1
    except Exception as exc:  # noqa: BLE001 - one broken feed must never stop the loop
        status = f"error:{type(exc).__name__}"
        state["failures"] = int(state.get("failures", 0)) + 1
    save_state(feeds_dir, feed.id, state)
    log("feed", feed=feed.id, status=status)
    return status


def processing_order(feeds: list[core.Feed]) -> list[core.Feed]:
    """Unguarded feeds (psl, majestic, …) first: the never-list guard of certpl/disposable uses them."""
    return sorted(feeds, key=lambda f: f.never_list_guard)


def clean_staging(staging: str) -> None:
    """Removes downloads left behind by a killed run."""
    try:
        names = os.listdir(staging)
    except OSError:
        return
    for name in names:
        if name.startswith("download-"):
            try:
                os.unlink(os.path.join(staging, name))
            except OSError:
                pass


def main(argv: list[str]) -> int:
    os.umask(0o022)  # published files 0644, directories 0755: readable by analyzer and inference
    feeds_dir = os.environ.get("ZETRU_FEEDS_DIR", "/feeds")
    staging = os.environ.get("ZETRU_STAGING_DIR") or os.path.join(feeds_dir, ".staging")
    clean_staging(staging)
    feeds = core.load_manifest()
    enabled = []
    for feed in processing_order(feeds):
        if core.allowed(feed):
            enabled.append(feed)
        else:
            log("feed_refused", feed=feed.id, reason="non_commercial_licence")
    hosts = fetch.allowed_hosts([f.url for f in enabled])
    once = "--once" in argv
    while True:
        now = time.time()
        for feed in enabled:
            if next_due(feed, load_state(feeds_dir, feed.id), now) <= now:
                run_feed(feed, feeds_dir, staging, hosts)
        if once:
            return 0
        now = time.time()
        wake = min(next_due(f, load_state(feeds_dir, f.id), now) for f in enabled) if enabled else now + MAX_SLEEP_S
        time.sleep(max(MIN_SLEEP_S, min(MAX_SLEEP_S, wake - now)) * random.uniform(0.95, 1.05))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
