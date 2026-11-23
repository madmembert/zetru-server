import base64
import hashlib
import json
import os
import socket
import struct
import time

import pytest

from zetru_analyzer import feedfiles, framing, ipc, logs
from zetru_analyzer.feeds import UNKNOWN_AGE, FeedStore, HashSet

RAW = b"From: a@example.com\r\n\r\nhello"


def body(meta: dict, raw: bytes = RAW) -> bytes:
    blob = json.dumps(meta).encode()
    return struct.pack(">I", len(blob)) + blob + raw


def meta(**over):
    m = {"schema": 1, "mail_sha256": hashlib.sha256(RAW).hexdigest(), "account_ref": "a" * 32, "mode": "auto",
         "locale": "en", "catalog_version": 1}
    m.update(over)
    return m


def test_parse_analyze_ok():
    parsed, raw = framing.parse_analyze(body(meta(qr_payloads=["https://x.example"], ocr_text="t", received_at=1)), 1000)
    assert raw == RAW and parsed["qr_payloads"] == ["https://x.example"]


@pytest.mark.parametrize("bad", [
    b"", b"\x00\x00\x00\x00{}x", b"\x00\x01\x00\x01{}", struct.pack(">I", 3) + b"{x}" + RAW,
])
def test_parse_analyze_framing_errors(bad):
    with pytest.raises(framing.BadRequest):
        framing.parse_analyze(bad, 1000)


@pytest.mark.parametrize("override", [
    {"schema": 2}, {"mail_sha256": "0" * 64}, {"mail_sha256": "X" * 64}, {"account_ref": "short"}, {"mode": "x"},
    {"locale": "fr"}, {"catalog_version": True}, {"qr_payloads": ["x"] * 6}, {"qr_payloads": ["x" * 2049]},
    {"ocr_text": "x" * 4001}, {"received_at": "now"},
])
def test_meta_validation(override):
    with pytest.raises(framing.BadRequest):
        framing.parse_analyze(body(meta(**override)), 1000)


def test_mail_size_limit():
    with pytest.raises(framing.BadRequest):
        framing.parse_analyze(body(meta()), 5)


def test_policy_header():
    encoded = base64.urlsafe_b64encode(json.dumps({"backends": ["rules", "encoder"], "max_mail_bytes": 1000}).encode())
    assert framing.parse_policy(encoded.decode().rstrip("=")) == {"backends": ["rules", "encoder"], "max_mail_bytes": 1000}
    assert framing.parse_policy(None)["backends"] == ["rules"]
    for bad in ("%%%", base64.urlsafe_b64encode(b'{"backends": ["evil"]}').decode(),
                base64.urlsafe_b64encode(b'{"max_mail_bytes": 0}').decode()):
        with pytest.raises(framing.BadRequest):
            framing.parse_policy(bad)


def test_url_check_validation():
    ok = framing.parse_url_check(json.dumps({"items": [{"host": "a.example", "url_sha256": "0" * 64}]}).encode())
    assert ok[0]["host"] == "a.example"
    for bad in ({"items": []}, {"items": [{"host": "a", "url_sha256": "x"}]},
                {"items": [{"host": "a.example", "url_sha256": "0" * 64}] * 11}):
        with pytest.raises(framing.BadRequest):
            framing.parse_url_check(json.dumps(bad).encode())


def test_ipc_roundtrip_and_limits():
    a, b = socket.socketpair()
    ipc.send_frame(a, {"t": "job", "x": 1}, b"blob\x00data")
    msg, blob = ipc.recv_frame(b, 1024)
    assert msg == {"t": "job", "x": 1} and blob == b"blob\x00data"
    ipc.send_frame(a, {"t": "big"}, b"x" * 2000)
    with pytest.raises(ipc.ProtocolError):
        ipc.recv_frame(b, 1024)
    a.close()
    b.close()
    with pytest.raises(ipc.ProtocolError):
        ipc.decode(struct.pack(">I", 100) + b"{}")
    with pytest.raises(ipc.ProtocolError):
        ipc.decode(struct.pack(">I", 2) + b"[]")


# Feeds ------------------------------------------------------------------------------------------------------

def publish(root, feed_id, lines, refresh=300, fetched_at=None, corrupt=False):
    version = "v1"
    os.makedirs(os.path.join(root, feed_id, version), exist_ok=True)
    data = ("\n".join(lines) + "\n").encode()
    path = os.path.join(root, feed_id, version, "domains.txt")
    with open(path, "wb") as handle:
        handle.write(data)
    digest = hashlib.sha256(data).hexdigest()
    if corrupt:
        digest = "0" * 64
    current = {"version": version, "fetched_at": fetched_at or int(time.time()), "entries": len(lines),
               "sha256": digest, "licence": "test", "commercial": True, "attribution": None, "refresh_s": refresh,
               "path": f"{version}/domains.txt"}
    with open(os.path.join(root, feed_id, "current.json"), "w") as handle:
        json.dump(current, handle)


def test_feed_store_lookup_semantics(tmp_path):
    root = str(tmp_path)
    publish(root, "certpl", ["evil.example", "bad.pages.dev"])
    publish(root, "majestic", ["google.com", "example.org"], refresh=86400)
    publish(root, "disposable", ["mailinator.com"], refresh=86400)
    store = FeedStore(root)
    assert store.reload() == {"certpl", "majestic", "disposable"}
    assert store.lookup("login.evil.example", "evil.example")["listed"] == ["certpl"]   # subdomain of a listed entry
    assert store.lookup("pages.dev", None)["listed"] == []                             # parent of a listed entry
    assert store.lookup("bad.pages.dev", "bad.pages.dev")["listed"] == ["certpl"]
    assert store.lookup("www.example.org", "example.org")["popular"]
    assert store.lookup("x.mailinator.com", "mailinator.com")["disposable"]
    states = {s["id"]: s for s in store.states()}
    assert states["psl"]["age_s"] == UNKNOWN_AGE and states["psl"]["stale"]
    assert store.completeness() == "partial"


def test_feed_store_rejects_tampered_data_and_reports_stale(tmp_path):
    root = str(tmp_path)
    publish(root, "certpl", ["evil.example"], corrupt=True)
    store = FeedStore(root)
    store.reload()
    assert "certpl" not in store.feeds and store.completeness() == "failed"
    publish(root, "certpl", ["evil.example"], refresh=300, fetched_at=int(time.time()) - 3600)
    os.utime(os.path.join(root, "certpl", "current.json"), (time.time() + 5, time.time() + 5))
    store.reload()
    state = next(s for s in store.states() if s["id"] == "certpl")
    assert state["stale"] and 3500 < state["age_s"] < 3700


def test_feedfiles_path_traversal(tmp_path):
    root = str(tmp_path)
    os.makedirs(os.path.join(root, "certpl"))
    with open(os.path.join(root, "certpl", "current.json"), "w") as handle:
        json.dump({"version": "v", "fetched_at": 1, "entries": 1, "sha256": "0" * 64, "licence": "x",
                   "commercial": True, "attribution": None, "refresh_s": 300, "path": "../../etc/passwd"}, handle)
    assert feedfiles.read_current(root, "certpl") is None
    assert feedfiles.read_current(root, "../x") is None


def test_hashset():
    hs = HashSet(["a.example", "b.example"])
    assert "a.example" in hs and "c.example" not in hs and len(hs) == 2


# Logging contract -------------------------------------------------------------------------------------------

def test_logs_drop_unknown_fields_and_redact(capsys):
    logs.info("request", endpoint="analyze", subject="Secret subject", domain="evil.example",
              reason="contains spaces and @", tenant="not-a-uuid")
    line = json.loads(capsys.readouterr().err.strip())
    assert "subject" not in line and "domain" not in line
    assert line["reason"] == "redacted" and line["tenant"] == "invalid"
