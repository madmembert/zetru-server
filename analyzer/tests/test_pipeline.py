"""Targeted pipeline behaviour beyond the corpus."""

import pytest
from helpers import LocalBroker, ids, run_pipeline

from zetru_analyzer import mimeparse, pipeline, simhash


def mail(body: str, sender='"Anna" <anna@sender.example>', subject="Hallo", headers="", ctype="text/plain") -> bytes:
    return (f"From: {sender}\r\nTo: bob@example.org\r\nSubject: {subject}\r\n{headers}"
            f"Content-Type: {ctype}; charset=utf-8\r\n\r\n{body}\r\n").encode("utf-8")


PERSONAL = ("Hallo Bob, wollen wir am Samstag zusammen frühstücken gehen? Ich hätte gegen zehn Uhr Zeit und würde "
            "das Café am Markt vorschlagen. Liebe Grüße, Anna")


def test_clean_personal_mail_has_no_findings_and_full_completeness():
    result = run_pipeline(mail(PERSONAL))
    assert ids(result) == set()
    comp = result["completeness"]
    assert {k: comp[k] for k in ("parse", "auth", "urls", "attachments", "domain_age", "classifier")} == \
        {"parse": "ok", "auth": "ok", "urls": "ok", "attachments": "ok", "domain_age": "ok", "classifier": "ok"}
    assert result["auth"]["dmarc"] == {"domain": "sender.example", "policy": "absent", "testing": False, "result": "none"}
    assert len(result["campaign_bands"]) == 4


def test_parse_failure_result(monkeypatch):
    def boom(raw):
        raise mimeparse.ParseError("X")

    monkeypatch.setattr(mimeparse, "parse", boom)
    result = run_pipeline(b"garbage")
    assert result["completeness"]["parse"] == "failed" and ids(result) == {"MIME_MALFORMED"}


def test_depth_and_part_limits():
    nested = "".join(f'--b{i}\r\nContent-Type: multipart/mixed; boundary="b{i + 1}"\r\n\r\n' for i in range(30))
    raw = (b'From: a@sender.example\r\nTo: b@example.org\r\nContent-Type: multipart/mixed; boundary="b0"\r\n\r\n'
           + nested.encode() + b"--b30\r\nContent-Type: text/plain\r\n\r\nhi\r\n")
    result = run_pipeline(raw)
    assert "MIME_LIMITS" in ids(result) and result["completeness"]["parse"] == "partial"
    many = "".join("--b\r\nContent-Type: text/plain\r\n\r\nx\r\n" for _ in range(1100)) + "--b--\r\n"
    raw = (b'From: a@sender.example\r\nTo: b@example.org\r\nContent-Type: multipart/mixed; boundary="b"\r\n\r\n'
           + many.encode())
    assert "MIME_LIMITS" in ids(run_pipeline(raw))


def test_hidden_text_rules():
    visible = "<p>" + PERSONAL + "</p>"
    preheader = '<div style="display:none">Kurzer Vorschautext für die Liste</div>'
    assert "MIME_HIDDEN_TEXT" not in ids(run_pipeline(mail(preheader + visible, ctype="text/html")))
    middle = visible + '<span style="font-size:0">' + "verborgen " * 30 + "</span>"
    assert "MIME_HIDDEN_TEXT" in ids(run_pipeline(mail(middle, ctype="text/html")))


def test_parts_differ():
    raw = ("From: a@sender.example\r\nTo: b@example.org\r\nSubject: x\r\n"
           'Content-Type: multipart/alternative; boundary="b"\r\n\r\n'
           "--b\r\nContent-Type: text/plain\r\n\r\n" + PERSONAL + " https://real-shop.example/a\r\n"
           "--b\r\nContent-Type: text/html\r\n\r\n<p>" + PERSONAL + '<a href="https://other-site.example/a">x</a></p>\r\n'
           "--b--\r\n").encode()
    assert "MIME_PARTS_DIFFER" in ids(run_pipeline(raw))
    same = raw.replace(b"other-site.example", b"real-shop.example")
    assert "MIME_PARTS_DIFFER" not in ids(run_pipeline(same))


def test_word_obfuscation():
    text = PERSONAL + " Bitte prüfen Sie Ihr PаyPal Konto und Ihr Pass​wort."
    result = run_pipeline(mail(text))
    sig = next(s for s in result["signals"] if s["id"] == "ACCT_WORD_OBFUSCATION")
    assert sig["evidence"]["count"] == 2 and sig["evidence"]["brand"] == "paypal"
    assert "ACCT_WORD_OBFUSCATION" not in ids(run_pipeline(mail(PERSONAL + " Wir sehen uns bei O2 und N26.")))


def test_disposable_sender_and_ugc_link():
    broker = LocalBroker(disposable=["wegwerf.example"])
    result = run_pipeline(mail(PERSONAL + " https://mein-dokument.pages.dev/view", sender="x@wegwerf.example"), broker)
    assert {"ID_DOMAIN_DISPOSABLE", "LINK_UGC_HOSTING"} <= ids(result)


def test_domain_age_signals_and_completeness():
    broker = LocalBroker(ages={"sender.example": 3, "fresh-shop.example": 10, "old-shop.example": 900})
    text = PERSONAL + " https://fresh-shop.example/a https://old-shop.example/b"
    result = run_pipeline(mail(text), broker)
    by_id = {s["id"]: s["evidence"] for s in result["signals"]}
    assert by_id["ID_DOMAIN_NEW"] == {"domain": "sender.example", "age_days": 3}
    assert by_id["LINK_DOMAIN_NEW"]["domain"] == "fresh-shop.example"
    assert result["completeness"]["domain_age"] == "ok"
    broker = LocalBroker(ages={"sender.example": None})
    assert run_pipeline(mail(PERSONAL), broker)["completeness"]["domain_age"] == "partial"
    broker = LocalBroker(ages={"sender.example": "error"})
    assert run_pipeline(mail(PERSONAL), broker)["completeness"]["domain_age"] == "failed"


def test_popular_and_official_domains_skip_age_lookups():
    broker = LocalBroker(popular=["sender.example"])
    run_pipeline(mail(PERSONAL + " https://www.paypal.com/x https://bit.ly/abc"), broker)
    assert broker.calls[-1]["ages"] == []


def test_feed_budget_marks_urls_partial():
    links = " ".join(f"https://host{i}.example/x" for i in range(45))
    result = run_pipeline(mail(PERSONAL + " " + links))
    assert result["completeness"]["urls"] == "partial"


def test_classifier_states():
    assert run_pipeline(mail(PERSONAL), backends=())["completeness"]["classifier"] == "skipped"
    assert run_pipeline(mail(PERSONAL), LocalBroker(decide=False))["completeness"]["classifier"] == "failed"
    french = ("Bonjour Paul, nous vous informons que la réunion de demain est annulée. Nous vous proposons une "
              "nouvelle date la semaine prochaine, merci de confirmer votre disponibilité.")
    result = run_pipeline(mail(french))
    assert result["completeness"]["classifier"] == "abstained" and "CLS_ABSTAIN" in ids(result)


def test_callback_lure_needs_unofficial_or_weak_sender():
    text = ("Ihr Abonnement wurde für 399,99 € verlängert. Falls Sie diese Verlängerung nicht veranlasst haben, "
            "rufen Sie uns sofort unter 0800 123 4567 an, um sie zu stornieren.")
    assert "PHONE_CALLBACK_LURE" in ids(run_pipeline(mail(text, sender="abo-service@gmail.com")))
    # A phone number offered for questions in an ordinary service mail is not a lure.
    service = PERSONAL + " Bei Fragen erreichen Sie uns telefonisch unter 030 123456."
    assert "PHONE_CALLBACK_LURE" not in ids(run_pipeline(mail(service)))


def test_brand_from_official_domain_is_not_flagged():
    result = run_pipeline(mail(PERSONAL, sender='"PayPal" <service@paypal.de>'))
    assert "ID_BRAND_NOT_OFFICIAL" not in ids(result) and "ID_LOOKALIKE_BRAND" not in ids(result)
    result = run_pipeline(mail(PERSONAL, sender='"PayPal Service" <service@pp-hilfe.example>'))
    assert "ID_BRAND_NOT_OFFICIAL" in ids(result)


def test_campaign_bands_are_stable_and_similar():
    a = simhash.bands(PERSONAL * 3, ["x.example"])
    assert a == simhash.bands(PERSONAL * 3, ["x.example"])
    # A long campaign text personalised with a different name stays within a small Hamming distance.
    words = [f"wort{i % 97}" for i in range(400)]
    base = " ".join(words)
    personalised = base.replace("wort5 ", "Anna ", 1)
    h1 = simhash.simhash64(simhash.features(base, ["x.example"]))
    h2 = simhash.simhash64(simhash.features(personalised, ["x.example"]))
    assert bin(h1 ^ h2).count("1") <= 6
    b1, b2 = simhash.bands(base, ["x.example"]), simhash.bands(personalised, ["x.example"])
    assert any(x == y for x, y in zip(b1, b2))
    assert simhash.bands("hi", []) is None
    assert all(len(band) == 4 and int(band, 16) >= 0 for band in a)


def test_signal_limits():
    links = " ".join(f"https://paypal-{i}.example/x" for i in range(30))
    result = run_pipeline(mail(PERSONAL + " " + links))
    assert sum(1 for s in result["signals"] if s["id"] == "LINK_LOOKALIKE") == 8
    assert len(result["signals"]) <= 64


def test_failure_result_shape():
    result = pipeline.failure_result("resources")
    assert ids(result) == {"MIME_MALFORMED", "MIME_LIMITS"}
    assert result["completeness"]["parse"] == "failed" and result["campaign_bands"] is None
