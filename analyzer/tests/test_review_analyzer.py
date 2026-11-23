"""Regression tests for the security review of the analyzer (findings PY-01 … PY-23). Timing tests use
pathological inputs of about 200 KB and must finish well under a second each."""

import asyncio
import base64
import dataclasses
import gzip
import hashlib
import io
import json
import os
import socket
import struct
import sys
import tarfile
import time
import zipfile
import zlib

import pytest
from helpers import NOW, LocalBroker, ids, make_meta, run_pipeline

from zetru_analyzer import (attachments, domains, feedfiles, framing, htmltext, httpclient, ipc, logs, lookalike,
                            mimeparse, packs, pdfcrypt, pipeline, sandbox, signals, state, supervisor, textpatterns)
from zetru_analyzer.config import Config
from zetru_analyzer.feeds import FeedStore
from zetru_analyzer.httpserver import Server
from zetru_analyzer.supervisor import Budget, Supervisor, Zygote

PACKS = packs.default_packs()
PERSONAL = ("Hallo Bob, wollen wir am Samstag zusammen frühstücken gehen? Ich hätte gegen zehn Uhr Zeit und würde "
            "das Café am Markt vorschlagen. Liebe Grüße, Anna")
PHISH = ("Dear customer, your PayPal account has been limited for security reasons. Please confirm your login "
         "details here to restore access. Thank you for your cooperation, your PayPal team.")
FAKE_PE = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x40) + b"PE\x00\x00" + b"\x00" * 64


def mail(body: str, sender='"Anna" <anna@sender.example>', subject="Hallo", headers="", ctype="text/plain",
         charset="utf-8") -> bytes:
    return (f"From: {sender}\r\nTo: bob@example.org\r\nSubject: {subject}\r\n{headers}"
            f"Content-Type: {ctype}; charset={charset}\r\n\r\n{body}\r\n").encode("utf-8")


def with_attachment(name: str, data: bytes, ctype: str = "application/octet-stream") -> bytes:
    b64 = base64.encodebytes(data).decode()
    return ("From: anna@sender.example\r\nTo: bob@example.org\r\nSubject: Dokument\r\n"
            'Content-Type: multipart/mixed; boundary="b"\r\n\r\n'
            f"--b\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{PERSONAL}\r\n"
            f'--b\r\nContent-Type: {ctype}; name="{name}"\r\nContent-Disposition: attachment; filename="{name}"\r\n'
            f"Content-Transfer-Encoding: base64\r\n\r\n{b64}\r\n--b--\r\n").encode()


def fast(fn, limit=1.0):
    started = time.monotonic()
    result = fn()
    elapsed = time.monotonic() - started
    assert elapsed < limit, f"took {elapsed:.2f} s"
    return result


# PY-01: content-triggered exceptions ---------------------------------------------------------------------------

def test_hostile_port_and_surrogate_links_do_not_break_the_analysis():
    body = (f'<p>{PHISH}</p><a href="http://example.com:²/"></a><a href="http://example.com:{"9" * 5000}/">x</a>'
            '<a href="https://paypa1-login.example/x">PayPal</a>')
    result = run_pipeline(mail(body, ctype="text/html"),
                          meta_extra={"qr_payloads": ["https://example.com/\ud800"]})
    assert result["completeness"]["urls"] == "ok" and "LINK_LOOKALIKE" in ids(result)


@pytest.mark.parametrize("charset,body", [
    ("unicode_escape", PERSONAL + " https://example.com/\\ud800 "),
    ("utf-7", PERSONAL + " https://example.com/+2AA- "),
    ("punycode", PERSONAL),
])
def test_dangerous_charsets_are_decoded_as_utf8(charset, body):
    result = run_pipeline(mail(body, charset=charset))
    assert result["completeness"]["parse"] in ("ok", "partial")
    assert mimeparse._charset_ok(charset) == "utf_8"


def test_crashing_stage_marks_only_that_stage_and_adds_a_caution(monkeypatch):
    def boom(*args, **kwargs):
        raise KeyError("bug")

    monkeypatch.setattr(lookalike, "brand_lookalike", boom)
    result = run_pipeline(mail(PERSONAL + " https://shop.example/a"))
    assert result["completeness"]["urls"] == "failed"
    assert {"MIME_MALFORMED", "MIME_LIMITS"} <= ids(result)
    assert result["completeness"]["classifier"] == "ok" and result["campaign_bands"] is not None


# PY-02: link limits ---------------------------------------------------------------------------------------------

def test_many_links_to_one_host_do_not_push_real_links_out():
    filler = "".join(f'<a href="https://example.org/p/{i}"></a>' for i in range(300))
    real = ('<a href="https://evil-feed.example/login">Konto</a>'
            '<a href="https://paypal-sicherheit.example/x">PayPal</a>'
            '<a href="https://fresh-shop.example/a">Shop</a>')
    broker = LocalBroker(listed={"evil-feed.example": ["certpl"]}, ages={"fresh-shop.example": 3})
    result = run_pipeline(mail("<p>" + PERSONAL + "</p>" + filler + real, ctype="text/html"), broker)
    assert {"LINK_FEED_HIT", "LINK_LOOKALIKE", "LINK_DOMAIN_NEW"} <= ids(result)
    assert result["completeness"]["urls"] == "ok"


def test_more_link_candidates_than_the_limit_is_partial_with_mime_limits():
    links = "".join(f'<a href="https://h{i}.example/x">x</a>' for i in range(pipeline.MAX_LINK_CANDIDATES + 5))
    result = fast(lambda: run_pipeline(mail("<p>" + PERSONAL + "</p>" + links, ctype="text/html")), 10.0)
    assert result["completeness"]["urls"] == "partial" and "MIME_LIMITS" in ids(result)


def test_more_age_candidates_than_the_budget_is_partial():
    links = " ".join(f"https://small-site{i}.example/a" for i in range(8))
    broker = LocalBroker(ages={f"small-site{i}.example": 900 for i in range(8)})
    result = run_pipeline(mail(PERSONAL + " " + links), broker)
    assert result["completeness"]["urls"] == "partial" and result["completeness"]["domain_age"] == "partial"
    assert len(broker.calls[-1]["ages"]) == pipeline.AGE_BUDGET


def test_hidden_links_do_not_take_the_age_budget_of_visible_ones():
    hidden = "".join(f'<a style="display:none" href="https://hidden{i}.example/a">x</a>' for i in range(6))
    visible = '<a href="https://fresh-shop.example/a">Jetzt ansehen</a>'
    broker = LocalBroker(ages={"fresh-shop.example": 2})
    result = run_pipeline(mail("<p>" + PERSONAL + "</p>" + hidden + visible, ctype="text/html"), broker)
    assert "LINK_DOMAIN_NEW" in ids(result)


# PY-03: oversized canonical state --------------------------------------------------------------------------------

def test_long_tokens_cannot_switch_the_classifier_off():
    padding = " ".join("x" * 900 for _ in range(80))
    raw = mail(PHISH + " https://paypa1-secure.example/login " + padding, sender='"PayPal" <service@pp-mail.example>')
    broker = LocalBroker()
    result = run_pipeline(raw, broker)
    assert len(broker.calls[-1]["decide"]["state"]) < supervisor.MAX_STATE   # the supervisor accepts it unchanged
    assert result["completeness"]["classifier"] == "ok"
    assert {"CLS_ASKS_CREDENTIALS", "CLS_CAT_PHISHING"} <= ids(result)


def test_rendered_state_stays_far_below_the_limit():
    word = "ä" * 5000
    rendered = state.render(word, "x.example", ["bulk"], "none", " ".join([word] * 40), [word] * 400,
                            [(word, "x.example", True)] * 10, ["pdf"] * 6, " ".join([word] * 70))
    assert len(rendered) < 40_000 and len(rendered.encode("utf-8")) < 120_000
    assert "\ud800" not in state.render("a\ud800b", None, [], "none", "s\x01t", [], [], [], None)


def test_supervisor_cuts_an_oversized_state_instead_of_failing(tmp_path):
    seen = []

    async def inference(doc):
        seen.append(doc)
        return {"answers": []}

    async def run():
        sup = Supervisor(Config.from_env({"ZETRU_FEEDS_DIR": str(tmp_path)}), inference=inference)
        return await sup.broker({"t": "req", "decide": {"state": "x" * 100_000}}, Budget(), {"backends": ["rules"]})

    reply = asyncio.run(run())
    assert reply["decide"]["status"] == "ok" and len(seen[0]["state"]) == supervisor.MAX_STATE


# PY-05: super-linear parsing paths -------------------------------------------------------------------------------

@pytest.mark.parametrize("css", ["a" * 200_000, "/* " * 70_000, "@;" * 100_000, "a{" * 100_000, "}" * 200_000])
def test_style_blocks_are_linear(css):
    fast(lambda: htmltext.extract("<style>" + css + "</style><p>x</p>"))


def test_link_marker_collapse_is_linear():
    fast(lambda: state.body_tokens(" " * 200_000 + "[LINK]" + " \n" * 50_000 + "[LINK] [LINK]"))


def test_password_input_scan_is_linear():
    assert fast(lambda: attachments.html_active(b"<input " * 30_000)) is False
    assert attachments.password_input(b'<html><input name="p" type="password"></html>')
    assert not attachments.password_input(b'<input type="text"> type=password')


def test_pdf_encrypt_object_search_is_bounded():
    pdf = b"%PDF-1.4\n/Encrypt 1 0 R\n" + b"1 0 obj<< >>\n" * 15_000 + b"/Encrypt 1 0 R\n" * 2000
    assert fast(lambda: pdfcrypt.opens_without_password(pdf)) is None


def test_pdf_name_scan_of_a_flate_bomb_is_fast():
    stream = zlib.compress(b"/A" * (8 * 1024 * 1024), 9)
    pdf = b"%PDF-1.5\n1 0 obj << /Filter /FlateDecode >>\nstream\n" + stream + b"\nendstream\nendobj\n"
    assert len(pdf) < 200_000
    result = fast(lambda: attachments.pdf_scan(pdf))
    assert result["active"] is False


def test_pdf_hex_escaped_names_are_still_found():
    assert attachments.pdf_scan(b"%PDF-1.4 << /S /J#61vaScr#69pt >>")["active"]
    assert not attachments.pdf_scan(b"%PDF-1.4 << /S /JavaScriptX /JSON >>")["active"]


def test_many_overlapping_pdf_streams_hit_the_work_budget():
    body = b"<< /Filter /FlateDecode >>\nstream\n" * 3000 + b"x" * 100_000 + b"\nendstream\n"
    result = fast(lambda: attachments.pdf_scan(b"%PDF-1.5\n" + body))
    assert result["partial"]


def test_tar_reader_is_linear_and_counts_pax_headers():
    pax = tarfile.TarInfo("x")
    pax.type = tarfile.XHDTYPE
    header = pax.tobuf(tarfile.USTAR_FORMAT)[:512]
    with pytest.raises(attachments.ArchiveError):
        fast(lambda: attachments.tar_names(header * 8000))
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for i in range(500):
            info = tarfile.TarInfo(f"dir/f{i}.txt")
            info.pax_headers = {"comment": "x"}
            tf.addfile(info, io.BytesIO(b""))
    assert len(fast(lambda: attachments.tar_names(buf.getvalue()))) == 500


def test_phone_scan_with_many_ibans_and_dates_is_fast():
    text = " ".join(f"DE89 3704 0044 0532 0130 0{i % 10} 01.02.2026" for i in range(5000))
    fast(lambda: textpatterns.find_phones(text))


def test_punycode_body_is_not_decoded_with_punycode():
    raw = mail("a" * 200_000, charset="punycode")
    parsed = fast(lambda: mimeparse.parse(raw))
    assert parsed.plain_texts[0].startswith("aaa")


def test_many_rfc2231_parameters_are_cut_and_flagged():
    params = "".join(f"; a*{i}*=b" for i in range(10_000))
    raw = f"From: a@sender.example\r\nTo: b@example.org\r\nContent-Type: text/plain{params}\r\n\r\nx\r\n".encode()
    result = fast(lambda: run_pipeline(raw))
    assert "MIME_LIMITS" in ids(result) and result["completeness"]["parse"] == "partial"


def test_header_budget_bounds_many_distinct_parts():
    parts = "".join(f"--b\r\nContent-Type: text/plain; name=\"f{i}\"{''.join(f'; p{i}x{j}=v' for j in range(150))}\r\n"
                    f"Content-Disposition: attachment\r\n\r\nx\r\n" for i in range(300))
    raw = ('From: a@sender.example\r\nTo: b@example.org\r\nContent-Type: multipart/mixed; boundary="b"\r\n\r\n'
           + parts + "--b--\r\n").encode()
    parsed = fast(lambda: mimeparse.parse(raw), 3.0)
    assert parsed.headers_truncated


def test_nested_comments_in_from_do_not_crash():
    raw = ("From: a@sender.example (x" + "(" * 50_000 + "\r\nTo: b@example.org\r\n\r\n" + PERSONAL).encode()
    result = fast(lambda: run_pipeline(raw))
    assert "MIME_MALFORMED" in ids(result)


def test_attachment_cpu_budget_stops_inspection(monkeypatch):
    monkeypatch.setattr(pipeline, "ATTACHMENT_CPU_BUDGET_S", -1.0)
    result = run_pipeline(with_attachment("Rechnung.pdf", FAKE_PE))
    assert result["completeness"]["attachments"] == "partial" and "MIME_LIMITS" in ids(result)
    assert "ATT_EXECUTABLE" not in ids(result)


def test_ole2_stream_reads_are_bounded():
    from test_attachments import cfb

    data = cfb([("Workbook", 2, b"\x09\x08" + b"\0" * 600) for _ in range(30)])
    fast(lambda: attachments.ole2_info(data))


# PY-06: DNS answers ------------------------------------------------------------------------------------------------

def test_txt_records_are_cleaned_and_bounded():
    records = [bytes(range(256)) * 300] * 20
    cleaned = supervisor.clean_txt(records)
    assert len(cleaned) == supervisor.MAX_TXT_RECORDS
    assert all(len(r) <= supervisor.MAX_TXT_CHARS and all(" " <= c <= "~" for c in r) for r in cleaned)


def test_broker_reply_fits_the_worker_frame_limit(tmp_path):
    async def resolver(name):
        return "ok", ["\xff" * 65_000] * 10

    async def run():
        sup = Supervisor(Config.from_env({"ZETRU_FEEDS_DIR": str(tmp_path)}), resolver=resolver)
        names = [f"s{i}._domainkey.attacker.example" for i in range(3)] + ["_dmarc.attacker.example", "attacker.example"]
        names += [f"_dmarc.x{i}.attacker.example" for i in range(20)]
        return await sup.broker({"t": "req", "dns": names}, Budget(), {"backends": []})

    reply = asyncio.run(run())
    assert len(ipc.encode(reply)) <= ipc.MAX_RESP
    assert supervisor.fit_reply({"t": "resp", "dns": {f"n{i}": {"status": "ok", "txt": ["a" * 2048] * 8}
                                                       for i in range(60)}})


# PY-07, PY-08: sandbox ------------------------------------------------------------------------------------------------

DENIED_NOW = ("kill", "tkill", "tgkill", "rt_sigqueueinfo", "pidfd_send_signal", "pidfd_open", "prctl", "mkdirat",
              "symlinkat", "linkat", "unlinkat", "renameat2", "mknodat", "ftruncate", "fchmodat", "setxattr",
              "memfd_create", "shmget", "msgget", "semget", "mq_open", "keyctl", "clone", "clone3", "unshare", "setns",
              "bpf", "userfaultfd", "perf_event_open")


@pytest.mark.parametrize("arch", ["x86_64", "aarch64"])
def test_signals_and_file_system_changes_are_denied(arch):
    prog = sandbox.build_filter(arch)
    audit = sandbox.AUDIT_ARCH[arch]
    eperm = sandbox.SECCOMP_RET_ERRNO | __import__("errno").EPERM
    for name in DENIED_NOW:
        assert sandbox.run_filter(prog, sandbox.SYSCALLS[arch][name], audit) == eperm, name
    assert len(prog) < 255 and all(jt <= 255 and jf <= 255 for _, jt, jf, _ in prog)


def test_not_dumpable_is_a_noop_outside_linux_and_imports_everywhere():
    import zetru_analyzer.__main__ as main_module  # noqa: F401 - syntax and import check of the Linux-only paths
    import zetru_analyzer.zygote as zygote_module  # noqa: F401

    if not sys.platform.startswith("linux"):
        assert sandbox.set_not_dumpable() is False


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="prctl exists only on Linux")
def test_not_dumpable_on_linux():
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r)
        ok = sandbox.set_not_dumpable()
        state_now = sandbox._libc().prctl(3, 0, 0, 0, 0)   # PR_GET_DUMPABLE
        os.write(w, f"{ok},{state_now}".encode())
        os._exit(0)
    os.close(w)
    data = os.read(r, 100).decode()
    os.waitpid(pid, 0)
    assert data == "True,0"


def test_hung_zygote_counts_as_dead():
    class Proc:
        def poll(self):
            return None

    zygote = Zygote(Config.from_env({}))
    zygote.proc = Proc()
    assert zygote.alive()
    zygote.spawn_timeouts = supervisor.SPAWN_TIMEOUTS_DEAD
    assert not zygote.alive()


def test_healthz_is_503_when_degraded():
    from test_httpserver import FakeSupervisor, exchange, request, responses

    class Degraded(FakeSupervisor):
        async def health(self):
            return {"status": "degraded", "feeds": [], "backends": []}

    data, _ = exchange(request("GET", "/internal/healthz"), Degraded())
    assert responses(data)[0][0] == 503


# PY-09: attachment exceptions keep findings -----------------------------------------------------------------------

def test_oversized_integer_in_encrypt_dict_keeps_pdf_findings():
    pdf = (b"%PDF-1.4\n1 0 obj << /OpenAction 2 0 R >> endobj\n2 0 obj << /S /JavaScript /JS (app.alert(1)) >> endobj\n"
           b"trailer << /Encrypt << /Filter /Standard /R " + b"9" * 5000 + b" /U (x) >> >>\n%%EOF")
    report = attachments.inspect("2", "a.pdf", "application/pdf", pdf, PACKS)
    assert "ATT_PDF_ACTIVE" in report.signals and not report.failed


def test_unexpected_error_in_one_step_keeps_the_others(monkeypatch):
    def boom(data):
        raise RuntimeError("bug")

    monkeypatch.setattr(attachments, "pdf_scan", boom)
    report = attachments.inspect("2", "Rechnung.pdf.exe", "application/pdf", b"%PDF-1.4 x", PACKS)
    assert report.failed and "ATT_TYPE_MISMATCH" in report.signals
    result = run_pipeline(with_attachment("Rechnung.pdf.exe", b"%PDF-1.4 x", "application/pdf"))
    assert result["completeness"]["attachments"] == "partial"
    assert any(s["id"] == "MIME_LIMITS" and s.get("evidence", {}).get("part") == "2" for s in result["signals"])
    assert "ATT_TYPE_MISMATCH" in ids(result)


# PY-10: ZIP listing ------------------------------------------------------------------------------------------------

def zip_of(files: dict, method=zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", method) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_fake_end_record_in_the_comment_does_not_empty_the_listing():
    real = zip_of({"invoice.pdf.exe": FAKE_PE})
    fake_eocd = b"PK\x05\x06" + b"\x00" * 18
    data = real[:-2] + struct.pack("<H", len(fake_eocd)) + fake_eocd
    report = attachments.inspect("2", "docs.zip", "application/zip", data, PACKS)
    assert "ATT_ARCHIVE_RISKY" in report.signals


def test_fake_outer_end_record_with_an_empty_listing_is_opaque():
    real = zip_of({"invoice.pdf.exe": FAKE_PE})
    eocd = real.rfind(b"PK\x05\x06")
    tail = real[eocd:]                                  # real end record, becomes the fake one's comment
    fake = b"PK\x05\x06" + b"\x00" * 16 + struct.pack("<H", len(tail))
    data = real[:eocd] + fake + tail
    assert attachments.zip_entries(data) == []          # the outermost exact record lists nothing …
    report = attachments.inspect("2", "docs.zip", "application/zip", data, PACKS)
    assert "ATT_ARCHIVE_OPAQUE" in report.signals       # … but the unlisted local header gives it away


def test_prefixed_zip_with_archive_extension_is_scanned():
    data = b"\x00" + zip_of({"invoice.pdf.exe": FAKE_PE})
    report = attachments.inspect("2", "x.zip", "application/zip", data, PACKS)
    assert report.real_type == "zip" and "ATT_ARCHIVE_RISKY" in report.signals


def test_archive_extension_with_unknown_content_is_opaque():
    report = attachments.inspect("2", "x.zip", "application/zip", os.urandom(64) + b"\x00", PACKS)
    assert "ATT_ARCHIVE_OPAQUE" in report.signals


def test_member_hidden_from_the_central_directory_is_opaque():
    visible = zip_of({"a.txt": b"hello"})
    hidden = zip_of({"setup.exe": FAKE_PE})
    eocd = visible.rfind(b"PK\x05\x06")
    cd_size, cd_offset = struct.unpack_from("<II", visible, eocd + 12)
    shift = len(hidden[:hidden.find(b"PK\x01\x02")])
    local_part = hidden[:shift]
    data = bytearray(local_part + visible)
    struct.pack_into("<I", data, shift + eocd + 16, cd_offset + shift)
    pos = data.find(b"PK\x01\x02")
    struct.pack_into("<I", data, pos + 42, struct.unpack_from("<I", data, pos + 42)[0] + shift)
    entries = attachments.zip_entries(bytes(data))
    assert [e.name for e in entries] == ["a.txt"]
    assert attachments.unlisted_local_headers(bytes(data), entries)
    assert "ATT_ARCHIVE_OPAQUE" in attachments.inspect("2", "a.zip", "application/zip", bytes(data), PACKS).signals


def test_stored_nested_zip_is_not_opaque():
    inner = zip_of({"a.txt": b"x"})
    outer = zip_of({"inner.zip": inner}, zipfile.ZIP_STORED)
    assert not attachments.unlisted_local_headers(outer, attachments.zip_entries(outer))
    assert attachments.inspect("2", "a.zip", "application/zip", outer, PACKS).signals == {}


# PY-11: never-list guard in the analyzer --------------------------------------------------------------------------

def test_feed_store_never_lists_brand_and_freemail_subdomains(tmp_path):
    from test_framing_ipc_feeds import publish

    root = str(tmp_path)
    publish(root, "certpl", ["accounts.google.com", "login.paypal.com", "evil.example"])
    publish(root, "disposable", ["gmail.com", "mailinator.com"], refresh=86400)
    store = FeedStore(root)
    store.reload()
    for host in ("accounts.google.com", "x.login.paypal.com", "login.paypal.com"):
        assert store.lookup(host, None)["listed"] == [], host
    assert store.lookup("evil.example", None)["listed"] == ["certpl"]
    assert not store.lookup("gmail.com", "gmail.com")["disposable"]
    assert store.lookup("mailinator.com", "mailinator.com")["disposable"]


# PY-13: unsigned From/Subject placed above a signed message -------------------------------------------------------

def test_prepended_unsigned_headers_are_not_authenticated():
    from test_dkim_dmarc import MAIL, RSA_TXT, sign

    signed = sign(MAIL)
    dns = {"s1._domainkey.sender.example": {"status": "ok", "txt": [RSA_TXT]},
           "_dmarc.sender.example": {"status": "ok", "txt": ["v=DMARC1; p=reject"]}}
    control = run_pipeline(signed, LocalBroker(dns=dns))
    assert control["auth"]["dmarc"]["result"] == "pass" and control["auth"]["dkim"][0]["aligned"]
    forged = (b"From: Security Team <ceo@sender.example>\r\nSubject: URGENT: wire transfer needed today\r\n"
              b"Reply-To: attacker@evil.example\r\n" + signed)
    result = run_pipeline(forged, LocalBroker(dns=dns))
    assert result["auth"]["dmarc"]["result"] == "fail"
    assert not any(d["aligned"] and d["result"] == "pass" for d in result["auth"]["dkim"])
    assert "MIME_MALFORMED" in ids(result)
    subject_only = b"Subject: URGENT: wire transfer needed today\r\n" + signed
    result = run_pipeline(subject_only, LocalBroker(dns=dns))
    assert result["auth"]["dkim"][0]["result"] == "unverifiable"
    assert result["auth"]["dmarc"]["result"] != "pass"


# PY-15: OOXML macros -----------------------------------------------------------------------------------------------

def test_macro_part_with_another_name_is_detected_by_content_type():
    types = (b'<Types><Override PartName="/word/foo.bin" '
             b'ContentType="application/vnd.ms-office.vbaProject"/></Types>')
    docm = zip_of({"[Content_Types].xml": types, "word/document.xml": b"<d/>", "word/foo.bin": b"vba"})
    report = attachments.inspect("2", "a.docx", "application/octet-stream", docm, PACKS)
    assert "ATT_MACRO" in report.signals


def test_macro_enabled_extension_is_flagged_for_ooxml():
    xlsm = zip_of({"[Content_Types].xml": b"<Types/>", "xl/workbook.xml": b"<w/>"})
    assert "ATT_MACRO" in attachments.inspect("2", "a.xlsm", "application/octet-stream", xlsm, PACKS).signals
    assert "ATT_MACRO" not in attachments.inspect("2", "a.xlsx", "application/octet-stream", xlsm, PACKS).signals


# PY-17: frame limits ----------------------------------------------------------------------------------------------

def test_largest_accepted_mail_fits_the_worker_frame():
    meta = make_meta(b"x", ocr_text="\x01" * 4000, qr_payloads=["\U0001f600" * 1000] * 5)
    head = ipc.encode_head({"t": "job", "meta": meta, "policy": {"backends": list(framing.KNOWN_BACKENDS),
                                                                  "max_mail_bytes": framing.HARD_MAX_MAIL},
                            "now": NOW}, framing.HARD_MAX_MAIL)
    total = struct.unpack(">I", head[:4])[0]
    assert total <= ipc.MAX_TO_WORKER
    too_big = base64.urlsafe_b64encode(json.dumps({"max_mail_bytes": framing.HARD_MAX_MAIL + 1}).encode()).decode()
    with pytest.raises(framing.BadRequest):
        framing.parse_policy(too_big)


# PY-19, PY-20: HTTP layer -------------------------------------------------------------------------------------------

def test_busy_is_decided_before_the_body_is_read():
    from test_httpserver import TENANT, FakeSupervisor, analyze_body, exchange, request, responses

    class Full(FakeSupervisor):
        capacity = 1

        def has_capacity(self, reserved=0):
            return False

    data, sup = exchange(request("POST", "/internal/v1/analyze", analyze_body(b"x" * 60_000), TENANT), Full())
    status, head, body = responses(data)[0]
    assert status == 503 and body["error"]["code"] == "busy" and b"Connection: close" in head and not sup.calls


def test_connections_beyond_the_cap_are_refused():
    from test_httpserver import FakeSupervisor, Writer, request

    server = Server(FakeSupervisor())
    server.connections = server.max_connections

    async def run():
        reader = asyncio.StreamReader()
        reader.feed_data(request("GET", "/internal/healthz"))
        reader.feed_eof()
        writer = Writer()
        await server.handle(reader, writer)
        return writer.data

    assert asyncio.run(run()).startswith(b"HTTP/1.1 503")


@pytest.mark.parametrize("size", [b"-5", b"+5", b"0x5", b"1_0", b"123456789"])
def test_malformed_chunk_sizes_are_rejected(size):
    from test_httpserver import exchange, responses

    raw = (b"POST /internal/v1/url/check HTTP/1.1\r\nTransfer-Encoding: chunked\r\n"
           b"X-Zetru-Tenant: 5b0c5c1e-6f0b-4a53-9d0e-2a6f1f1f7c11\r\n\r\n" + size + b"\r\nabcde\r\n0\r\n\r\n")
    assert responses(exchange(raw)[0])[0][0] == 400


@pytest.mark.parametrize("tenant", [None, "nope", "5B0C5C1E-6F0B-4A53-9D0E-2A6F1F1F7C11",
                                    "5b0c5c1e-6f0b-4a53-9d0e-2a6f1f1f7c11\n"])
def test_analyze_requires_a_valid_tenant(tenant):
    from test_httpserver import analyze_body, exchange, request, responses

    headers = {} if tenant is None else {"X-Zetru-Tenant": tenant.strip("\n")}
    data, sup = exchange(request("POST", "/internal/v1/analyze", analyze_body(), headers))
    if tenant and tenant.endswith("\n"):
        assert not framing.valid_tenant(tenant)
        return
    assert responses(data)[0][0] == 400 and not sup.calls


# PY-21: anchored validators ----------------------------------------------------------------------------------------

def test_validators_reject_a_trailing_newline():
    assert signals.validate_evidence({"url_sha256": "a" * 64 + "\n"}) is None
    assert signals.validate_evidence({"domain": "x.example\n"}) is None
    assert signals.validate_signal({"id": "LINK_FEED_HIT\n"}) is None
    assert supervisor.allowed_dns_names(["_dmarc.example.com\n"]) == []
    assert supervisor.validate_answer({"id": "category\n", "type": "choice", "backend": "rules",
                                       "model_version": "x"}) is None
    assert not framing.valid_tenant("5b0c5c1e-6f0b-4a53-9d0e-2a6f1f1f7c11\n")
    assert logs._clean("reason", "ok\n") == "redacted"
    assert feedfiles.read_current("/nonexistent", "certpl\n") is None
    assert domains.normalize_domain("a\n.example") is None


# PY-22: blocking work in the supervisor ---------------------------------------------------------------------------

def test_failed_name_resolution_is_cached(monkeypatch):
    calls = []

    def failing(*args, **kwargs):
        calls.append(args)
        raise OSError("dns down")

    monkeypatch.setattr(socket, "getaddrinfo", failing)
    monkeypatch.setattr(httpclient, "_CACHE", {})
    monkeypatch.setattr(httpclient, "_FAILED", {})
    for _ in range(5):
        with pytest.raises(httpclient.HttpError):
            httpclient.resolve("inference", 8082)
    assert len(calls) == 1


def test_feed_reload_yields_to_the_event_loop(tmp_path):
    from test_framing_ipc_feeds import publish

    publish(str(tmp_path), "majestic", [f"d{i}.example" for i in range(200_000)], refresh=86400)
    store = FeedStore(str(tmp_path))
    ticks = []

    async def ticker():
        while True:
            ticks.append(time.monotonic())
            await asyncio.sleep(0)

    async def run():
        task = asyncio.get_running_loop().create_task(ticker())
        await asyncio.sleep(0)
        changed = await store.reload_async()
        task.cancel()
        return changed

    assert asyncio.run(run()) == {"majestic"}
    assert len(ticks) > 5 and "d123.example" in store.feeds["majestic"].data


# PY-23: broker round trips ------------------------------------------------------------------------------------------

def test_worker_gets_at_most_four_broker_round_trips(tmp_path):
    from test_supervisor import _read_job, run_with

    replies = []

    async def behaviour(reader, writer):
        await _read_job(reader)
        for _ in range(6):
            writer.write(ipc.encode({"t": "req", "feeds": [{"host": "a.example"}]}))
            await writer.drain()
            try:
                reply, _ = await ipc.read_frame(reader, ipc.MAX_RESP)
            except (asyncio.IncompleteReadError, ConnectionError):
                break
            replies.append(reply)

    status, resp = run_with(tmp_path, behaviour)
    assert status == 200 and len(replies) == supervisor.MAX_REQ_FRAMES
    assert resp["completeness"]["parse"] == "failed"


def test_worker_that_vanishes_while_the_supervisor_writes_still_gets_an_answer(tmp_path):
    from test_supervisor import _read_job, run_with

    async def behaviour(reader, writer):
        await _read_job(reader)
        writer.write(ipc.encode({"t": "req", "dns": [f"_dmarc.x{i}.example" for i in range(20)]}))
        await writer.drain()
        writer.transport.abort()

    status, resp = run_with(tmp_path, behaviour)
    assert status == 200 and resp["completeness"]["parse"] == "failed"


def test_resolver_address_is_looked_up_again_after_timeouts(tmp_path):
    import dns.exception

    class Unreachable:
        async def resolve(self, *args, **kwargs):
            raise dns.exception.Timeout()

    async def run():
        sup = Supervisor(Config.from_env({"ZETRU_FEEDS_DIR": str(tmp_path)}))
        sup._dns = Unreachable()
        results = [await sup._txt("_dmarc.example.com") for _ in range(supervisor.DNS_ERRORS_RERESOLVE)]
        return sup, results

    sup, results = asyncio.run(run())
    assert all(r["status"] == "error" for r in results) and sup._dns is None
