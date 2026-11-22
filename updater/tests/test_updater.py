import dataclasses
import email.message
import hashlib
import io
import json
import os
import stat
import sys
import urllib.error

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from zetru_updater import __main__ as service  # noqa: E402
from zetru_updater import core, fetch  # noqa: E402

FEEDS = {f.id: f for f in core.load_manifest()}


def small(feed_id, **over):
    defaults = {"min_bytes": 1, "min_entries": 1}
    defaults.update(over)
    return dataclasses.replace(FEEDS[feed_id], **defaults)


def write(tmp_path, name, text):
    path = tmp_path / name
    path.write_bytes(text.encode() if isinstance(text, str) else text)
    return str(path)


def domains(n, prefix="d"):
    return [f"{prefix}{i}.example" for i in range(n)]


class FakeResponse(io.BytesIO):
    def __init__(self, data, headers=None):
        super().__init__(data)
        self.headers = email.message.Message()
        for k, v in (headers or {}).items():
            self.headers[k] = v


class FakeOpener:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def open(self, request, timeout=None):
        self.requests.append(request)
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


# Manifest --------------------------------------------------------------------------------------------------

def test_manifest_has_default_feeds_with_licences():
    assert set(FEEDS) == {"psl", "iana-tlds", "rdap-bootstrap", "certpl", "majestic", "disposable"}
    for feed in FEEDS.values():
        assert feed.url.startswith("https://") and feed.licence and feed.commercial
    assert FEEDS["certpl"].refresh_s == 300 and FEEDS["majestic"].min_interval_s == 86400
    assert FEEDS["majestic"].attribution and "CC BY 3.0" in FEEDS["majestic"].attribution
    assert FEEDS["certpl"].never_list_guard and FEEDS["disposable"].never_list_guard


def test_noncommercial_feeds_are_refused_unless_enabled():
    feed = dataclasses.replace(FEEDS["certpl"], commercial=False)
    assert not core.allowed(feed, {})
    assert core.allowed(feed, {"ZETRU_ALLOW_NONCOMMERCIAL": "1"})


def test_never_list_contains_every_official_brand_and_freemail_domain():
    pack_dir = os.path.join(HERE, "..", "..", "analyzer", "zetru_analyzer", "packs")
    with open(os.path.join(pack_dir, "brands-de-en.json"), encoding="utf-8") as handle:
        brands = json.load(handle)["brands"]
    with open(os.path.join(pack_dir, "freemail.json"), encoding="utf-8") as handle:
        freemail = json.load(handle)["domains"]
    never = core.load_never_list("/nonexistent")
    expected = set(freemail) | {d for b in brands for d in b["sending_domains"] + b["link_domains"]}
    assert expected - never == set()


# Parsers ---------------------------------------------------------------------------------------------------

def test_parse_domains_normalises_and_rejects_garbage(tmp_path):
    data, entries = core.parse_domains(write(tmp_path, "d", "# c\nA.Example.\nb.example # x\nb.example\nmüller.de\n"))
    assert entries == ["a.example", "b.example", "xn--mller-kva.de"]
    with pytest.raises(core.ValidationError):
        core.parse_domains(write(tmp_path, "bad", "\n".join(["not a domain"] * 10 + ["ok.example"])))


def test_parse_majestic_keeps_rank_order(tmp_path):
    csv = "GlobalRank,TldRank,Domain,TLD\n1,1,google.com,com\n2,2,facebook.com,com\n3,1,example.de,de\n"
    data, entries = core.parse_majestic(write(tmp_path, "m.csv", csv))
    assert entries == ["google.com", "facebook.com", "example.de"] and data.startswith(b"google.com\n")
    with pytest.raises(core.ValidationError):
        core.parse_majestic(write(tmp_path, "m2.csv", "Rank,Site\n1,x.com\n"))


def test_parse_psl_iana_rdap(tmp_path):
    psl = "// ===BEGIN ICANN DOMAINS===\ncom\n*.ck\n!www.ck\n// ===END ICANN DOMAINS===\n"
    assert core.parse_psl(write(tmp_path, "p", psl))[1] == ["com", "*.ck", "!www.ck"]
    with pytest.raises(core.ValidationError):
        core.parse_psl(write(tmp_path, "p2", "com\n"))
    assert core.parse_iana_tlds(write(tmp_path, "t", "# Version 1\nCOM\nXN--P1AI\n"))[1] == ["com", "xn--p1ai"]
    with pytest.raises(core.ValidationError):
        core.parse_iana_tlds(write(tmp_path, "t2", "# v\ncom!\n"))
    rdap = json.dumps({"services": [[["de", "com"], ["https://rdap.example/"]]], "publication": "x"})
    assert core.parse_rdap_bootstrap(write(tmp_path, "r", rdap))[1] == ["de", "com"]
    with pytest.raises(core.ValidationError):
        core.parse_rdap_bootstrap(write(tmp_path, "r2", json.dumps({"services": [[["de"], ["ftp://x"]]]})))


# Validation ------------------------------------------------------------------------------------------------

def test_change_ratio():
    core.check_change_ratio(None, domains(10))
    core.check_change_ratio(domains(100), domains(60))                # 40 % removed
    with pytest.raises(core.ValidationError, match="removed"):
        core.check_change_ratio(domains(100), domains(40))            # 60 % removed
    with pytest.raises(core.ValidationError, match="added"):
        core.check_change_ratio(domains(10), domains(10) + domains(31, "n"))   # 310 % added
    core.check_change_ratio(domains(10), domains(10) + domains(30, "n"))


def test_never_list_guard():
    never = {"paypal.com", "gmail.com"}
    kept, removed = core.apply_never_list(["evil.example", "paypal.com", "www.gmail.com", "co.uk"] + domains(2000),
                                          never, {"co.uk"})
    assert removed == 3 and "evil.example" in kept and "paypal.com" not in kept
    with pytest.raises(core.ValidationError, match="never_list_flood"):
        core.apply_never_list(sorted(never) * 20 + domains(100), never, set())


def test_size_and_entry_bounds():
    with pytest.raises(core.ValidationError, match="entry_bounds"):
        core.validate(FEEDS["certpl"], 50_000, domains(10))
    with pytest.raises(core.ValidationError, match="size_bounds"):
        core.validate(FEEDS["certpl"], 10, domains(5000))


# Publication -----------------------------------------------------------------------------------------------

def test_publish_is_atomic_world_readable_and_pruned(tmp_path):
    feeds_dir = str(tmp_path / "feeds")
    feed = small("certpl")
    versions = []
    for i in range(5):
        data = ("\n".join(domains(10 + i)) + "\n").encode()
        current = core.publish(feeds_dir, feed, data, 10 + i, now=1_800_000_000 + i)
        versions.append(current["version"])
        doc = json.load(open(os.path.join(feeds_dir, "certpl", "current.json")))
        assert doc == current
        assert set(doc) == {"version", "fetched_at", "entries", "sha256", "licence", "commercial", "attribution",
                            "refresh_s", "path"}
        published = os.path.join(feeds_dir, "certpl", doc["path"])
        assert hashlib.sha256(open(published, "rb").read()).hexdigest() == doc["sha256"]
        assert stat.S_IMODE(os.stat(published).st_mode) == 0o644
        assert stat.S_IMODE(os.stat(os.path.dirname(published)).st_mode) == 0o755
    remaining = sorted(d for d in os.listdir(os.path.join(feeds_dir, "certpl")) if not d.startswith((".", "current")))
    assert remaining == versions[-3:]


def test_process_download_rejects_and_keeps_previous(tmp_path):
    feeds_dir = str(tmp_path / "feeds")
    feed = small("certpl")
    status, current = core.process_download(feeds_dir, feed, write(tmp_path, "a", "\n".join(domains(100))), now=1)
    assert status == "published" and current["entries"] == 100
    with pytest.raises(core.ValidationError):
        core.process_download(feeds_dir, feed, write(tmp_path, "b", "\n".join(domains(10))), now=2)
    assert core.read_current(feeds_dir, "certpl")["version"] == current["version"]
    status, again = core.process_download(feeds_dir, feed, write(tmp_path, "c", "\n".join(domains(100))), now=3)
    assert status == "unchanged" and again["fetched_at"] == 3 and again["version"] == current["version"]


def test_guarded_feed_filters_never_list_entries(tmp_path):
    feeds_dir = str(tmp_path / "feeds")
    status, current = core.process_download(feeds_dir, small("disposable"),
                                            write(tmp_path, "d", "\n".join(domains(200) + ["gmail.com"])), now=1)
    assert status == "published_filtered" and current["entries"] == 200


# Fetching --------------------------------------------------------------------------------------------------

def test_fetch_only_allowed_hosts_and_https(tmp_path):
    with pytest.raises(fetch.FetchError, match="host_not_allowed"):
        fetch.fetch("https://evil.example/x", str(tmp_path), {"hole.cert.pl"}, 100, opener=FakeOpener([]))
    with pytest.raises(fetch.FetchError, match="host_not_allowed"):
        fetch.fetch("http://hole.cert.pl/x", str(tmp_path), {"hole.cert.pl"}, 100, opener=FakeOpener([]))


def test_truncated_download_is_rejected(tmp_path):
    opener = FakeOpener([FakeResponse(b"a.example\nb.exa", {"Content-Length": "100"})])
    with pytest.raises(fetch.FetchError, match="truncated"):
        fetch.fetch("https://hole.cert.pl/d", str(tmp_path), {"hole.cert.pl"}, 1000, opener=opener)


def test_redirects_are_refused():
    handler = fetch._NoRedirect()
    with pytest.raises(fetch.FetchError, match="redirect_refused"):
        handler.redirect_request(None, None, 302, "Found", {}, "https://elsewhere.example/")


def test_fetch_size_cap_and_conditional_request(tmp_path):
    opener = FakeOpener([FakeResponse(b"x" * 200)])
    with pytest.raises(fetch.FetchError, match="too_large"):
        fetch.fetch("https://hole.cert.pl/d", str(tmp_path), {"hole.cert.pl"}, 100, opener=opener)
    assert not [p for p in os.listdir(tmp_path) if p.startswith("download-")]
    not_modified = urllib.error.HTTPError("https://hole.cert.pl/d", 304, "Not Modified", {}, None)
    opener = FakeOpener([not_modified])
    result = fetch.fetch("https://hole.cert.pl/d", str(tmp_path), {"hole.cert.pl"}, 100, etag='"abc"', opener=opener)
    assert result.status == "not_modified" and opener.requests[0].get_header("If-none-match") == '"abc"'


def test_run_feed_end_to_end_with_backoff(tmp_path, monkeypatch):
    feeds_dir, staging = str(tmp_path / "feeds"), str(tmp_path / "staging")
    feed = small("certpl")
    hosts = {"hole.cert.pl"}
    body = ("\n".join(domains(150)) + "\n").encode()
    opener = FakeOpener([FakeResponse(body, {"ETag": '"v1"'})])
    assert service.run_feed(feed, feeds_dir, staging, hosts, opener=opener, now=1000) == "published"
    state = service.load_state(feeds_dir, "certpl")
    assert state["etag"] == '"v1"' and state["failures"] == 0
    assert service.next_due(feed, state, 1000) == 1000 + feed.refresh_s
    opener = FakeOpener([urllib.error.HTTPError("u", 304, "nm", {}, None)])
    assert service.run_feed(feed, feeds_dir, staging, hosts, opener=opener, now=2000) == "not_modified"
    assert core.read_current(feeds_dir, "certpl")["fetched_at"] == 2000
    opener = FakeOpener([urllib.error.URLError("down")])
    assert service.run_feed(feed, feeds_dir, staging, hosts, opener=opener, now=3000).startswith("fetch_failed")
    state = service.load_state(feeds_dir, "certpl")
    assert state["failures"] == 1 and service.next_due(feed, state, 3000) == 3000 + 120
    assert not [p for p in os.listdir(staging) if p.startswith("download-")]


def test_majestic_respects_minimum_interval():
    feed = FEEDS["majestic"]
    assert service.next_due(feed, {"last_success": 0, "failures": 3, "last_attempt": 100}, 200) == 86500
    assert service.next_due(feed, {"last_success": 50, "failures": 0, "last_attempt": 50}, 200) == 86450
