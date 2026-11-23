"""Regression tests for the security review of the updater (findings PY-11, PY-14, PY-18, PY-21, PY-25)."""

import dataclasses
import json
import os
import sys
import tracemalloc
from array import array

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from zetru_updater import __main__ as service  # noqa: E402
from zetru_updater import core  # noqa: E402

FEEDS = {f.id: f for f in core.load_manifest()}


def small(feed_id, **over):
    defaults = {"min_bytes": 1, "min_entries": 1}
    defaults.update(over)
    return dataclasses.replace(FEEDS[feed_id], **defaults)


def domains(n, prefix="d"):
    return [f"{prefix}{i}.example" for i in range(n)]


def write(tmp_path, name, lines):
    path = tmp_path / name
    path.write_text("\n".join(lines) + "\n")
    return str(path)


# PY-11: subdomains of never-list names ---------------------------------------------------------------------------

def test_subdomains_of_static_never_list_names_are_removed():
    static = {"google.com", "paypal.com", "gmail.com"}
    entries = ["accounts.google.com", "login.paypal.com", "smtp.gmail.com", "x.y.google.com", "evil.example",
               "google.com.evil.example", "notgoogle.com"] + domains(2000)
    kept, removed = core.apply_never_list(entries, static, set())
    assert removed == 4
    assert {"evil.example", "google.com.evil.example", "notgoogle.com"} <= set(kept)


def test_majestic_top_names_protect_only_themselves():
    # Hosting platforms are in the Majestic top 1,000; phishing subdomains on them must stay listable.
    kept, removed = core.apply_never_list(["weebly.com", "www.weebly.com", "phish.weebly.com"] + domains(2000),
                                          set(), set(), exact={"weebly.com"})
    assert removed == 2 and "phish.weebly.com" in kept


def test_wildcard_public_suffix_rules_count_as_suffixes():
    suffixes = core.Suffixes(rules=frozenset({"com"}), wildcards=frozenset({"ck"}), exceptions=frozenset({"www.ck"}))
    kept, removed = core.apply_never_list(["foo.ck", "www.ck", "com", "a.foo.ck"] + domains(2000), set(), suffixes)
    assert removed == 2 and {"www.ck", "a.foo.ck"} <= set(kept)


def test_too_many_never_list_subdomains_reject_the_release():
    with pytest.raises(core.ValidationError, match="never_list_flood"):
        core.apply_never_list([f"h{i}.google.com" for i in range(50)] + domains(100), {"google.com"}, set())


def test_guarded_publication_uses_subdomain_rule(tmp_path):
    feeds_dir = str(tmp_path / "feeds")
    status, current = core.process_download(feeds_dir, small("certpl"),
                                            write(tmp_path, "c", domains(500) + ["accounts.google.com"]), now=1)
    assert status == "published_filtered" and current["entries"] == 500


# PY-14: memory and the attempt time ---------------------------------------------------------------------------------

def test_attempt_time_is_saved_before_the_download(tmp_path):
    feeds_dir, staging = str(tmp_path / "feeds"), str(tmp_path / "staging")

    class Killed:
        def open(self, request, timeout=None):
            raise KeyboardInterrupt   # stands in for the OOM killer: nothing after this line runs

    with pytest.raises(KeyboardInterrupt):
        service.run_feed(FEEDS["majestic"], feeds_dir, staging, {"downloads.majestic.com"}, opener=Killed(), now=5000)
    state = service.load_state(feeds_dir, "majestic")
    assert state["last_attempt"] == 5000
    assert service.next_due(FEEDS["majestic"], state, 5001) >= 5000 + 86400


def test_change_ratio_uses_sorted_hash_arrays():
    old = core.sorted_keys(domains(1000))
    assert isinstance(old, array) and old.itemsize == 8 and list(old) == sorted(old)
    core.check_change_ratio(old, core.sorted_keys(domains(600)))
    with pytest.raises(core.ValidationError, match="removed"):
        core.check_change_ratio(old, core.sorted_keys(domains(400)))
    assert core._diff_counts(core.sorted_keys(["a", "b"]), core.sorted_keys(["b", "c", "d"])) == (1, 2)


def test_previous_version_is_streamed_as_keys(tmp_path):
    feeds_dir = str(tmp_path / "feeds")
    feed = small("certpl")
    core.process_download(feeds_dir, feed, write(tmp_path, "a", domains(50_000)), now=1)
    keys = core.previous_keys(feeds_dir, feed)
    assert isinstance(keys, array) and len(keys) == 50_000


def test_process_download_memory_stays_bounded(tmp_path):
    feeds_dir = str(tmp_path / "feeds")
    feed = small("certpl")
    core.process_download(feeds_dir, feed, write(tmp_path, "a", domains(200_000)), now=1)
    path = write(tmp_path, "b", domains(200_000) + domains(1000, "n"))
    tracemalloc.start()
    core.process_download(feeds_dir, feed, path, now=2)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    # 200,000 entries: strings and one set during parsing; the previous version only as an 8-byte-per-entry array.
    assert peak < 60 * 1024 * 1024


def test_default_staging_is_on_the_feeds_volume_and_leftovers_are_removed(tmp_path):
    staging = tmp_path / "feeds" / ".staging"
    staging.mkdir(parents=True)
    (staging / "download-0123456789abcdef").write_bytes(b"x")
    service.clean_staging(str(staging))
    assert not any(staging.iterdir())


# PY-18: draining in small steps ----------------------------------------------------------------------------------------

def test_reference_version_stops_a_drain_in_small_steps(tmp_path):
    feeds_dir = str(tmp_path / "feeds")
    feed = small("certpl")
    entries = domains(2000)
    core.process_download(feeds_dir, feed, write(tmp_path, "v0", entries), now=1000)
    entries = entries[: int(len(entries) * 0.6)]           # 40 % removed: passes both checks
    core.process_download(feeds_dir, feed, write(tmp_path, "v1", entries), now=1300)
    entries = entries[: int(len(entries) * 0.6)]           # 40 % of the previous, 64 % of the reference
    with pytest.raises(core.ValidationError, match="vs_reference"):
        core.process_download(feeds_dir, feed, write(tmp_path, "v2", entries), now=1600)
    assert core.read_current(feeds_dir, "certpl")["entries"] == 1200


def test_reference_moves_after_a_day_and_survives_pruning(tmp_path):
    feeds_dir = str(tmp_path / "feeds")
    feed = small("certpl")
    core.process_download(feeds_dir, feed, write(tmp_path, "v0", domains(1000)), now=1000)
    first = core.read_reference(feeds_dir, "certpl")
    for step in range(1, 6):
        core.process_download(feeds_dir, feed, write(tmp_path, f"v{step}", domains(1000 + step)), now=1000 + step)
    assert core.read_reference(feeds_dir, "certpl")["version"] == first["version"]
    assert os.path.isdir(os.path.join(feeds_dir, "certpl", first["version"]))   # kept although older than 3 versions
    core.process_download(feeds_dir, feed, write(tmp_path, "late", domains(1010)), now=1000 + 86400)
    assert core.read_reference(feeds_dir, "certpl")["version"] != first["version"]


# PY-21, PY-25 -------------------------------------------------------------------------------------------------------------

def test_label_and_feed_id_validation_reject_a_trailing_newline():
    assert core.normalize_domain("example.com") == "example.com"
    assert core._LABEL.fullmatch("abc\n") is None and core._FEED_ID.fullmatch("certpl\n") is None


def test_unguarded_feeds_are_processed_before_guarded_ones():
    order = [f.id for f in service.processing_order(core.load_manifest())]
    assert order.index("majestic") < order.index("certpl") and order.index("psl") < order.index("disposable")
    assert all(not f.never_list_guard for f in service.processing_order(core.load_manifest())[:4])


def test_manifest_still_loads_with_fullmatch_validation(tmp_path):
    doc = json.load(open(core.MANIFEST_PATH, encoding="utf-8"))
    doc["feeds"][0]["id"] = "psl\n"
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(doc))
    with pytest.raises(ValueError):
        core.load_manifest(str(path))
