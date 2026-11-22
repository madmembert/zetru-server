"""DKIM re-verification cross-checked against dkimpy (test-only dependency) and DMARC per RFC 9989."""

import base64

import dkim
import pytest
from helpers import NOW, LocalBroker, ids, run_pipeline
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from zetru_analyzer import dkimverify, dmarc, domains, mimeparse

PSL = domains.bundled_psl()
MAIL = (b"From: Anna <anna@sender.example>\r\nTo: bob@example.org\r\nSubject: Hello there\r\n"
        b"Date: Fri, 20 Nov 2026 09:30:00 +0000\r\nMessage-ID: <1@sender.example>\r\n\r\n"
        b"Hi Bob,\r\n\r\nthis   is a  test.\r\n\r\n\r\n")


def rsa_key(bits=2048):
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                            serialization.NoEncryption())
    pub = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return pem, "v=DKIM1; k=rsa; p=" + base64.b64encode(pub).decode()


RSA_PEM, RSA_TXT = rsa_key()
ED_SEED = bytes(range(32))


def ed_key():
    from nacl.signing import SigningKey

    key = SigningKey(ED_SEED)
    return base64.b64encode(ED_SEED), "v=DKIM1; k=ed25519; p=" + base64.b64encode(bytes(key.verify_key)).decode()


def sign(mail=MAIL, canon=(b"relaxed", b"relaxed"), algo=b"rsa-sha256", length=False, selector=b"s1",
         domain=b"sender.example", key=RSA_PEM, headers=None):
    return dkim.sign(mail, selector, domain, key, canonicalize=canon, signature_algorithm=algo, length=length,
                     include_headers=headers or [b"from", b"to", b"subject", b"date", b"message-id"]) + mail


def verify(raw, txt, status="ok"):
    mail = mimeparse.parse(raw)
    sig = dkimverify.parse_signatures(mail.headers)[0]
    return dkimverify.verify(sig, mail.headers, mail.body_raw, [txt] if txt else [], status, now=NOW)


def dkimpy_verify(raw, txt):
    return dkim.verify(raw, dnsfunc=lambda name, timeout=5: txt.encode())


@pytest.mark.parametrize("canon", [(b"relaxed", b"relaxed"), (b"simple", b"simple"), (b"relaxed", b"simple"),
                                   (b"simple", b"relaxed")])
def test_rsa_pass_all_canonicalisations(canon):
    raw = sign(canon=canon)
    assert dkimpy_verify(raw, RSA_TXT)
    res = verify(raw, RSA_TXT)
    assert res.result == "pass" and res.body_hash_ok and not res.l_partial


def test_ed25519_pass():
    key, txt = ed_key()
    raw = sign(algo=b"ed25519-sha256", key=key)
    assert dkimpy_verify(raw, txt)
    assert verify(raw, txt).result == "pass"


def test_relaxed_tolerates_whitespace_changes_simple_does_not():
    raw = sign(canon=(b"relaxed", b"relaxed"))
    changed = raw.replace(b"this   is a  test.", b"this is a test.")
    assert verify(changed, RSA_TXT).result == "pass"
    raw = sign(canon=(b"simple", b"simple"))
    changed = raw.replace(b"this   is a  test.", b"this is a test.")
    res = verify(changed, RSA_TXT)
    assert res.result == "fail" and res.reason == "body_hash"
    assert not dkimpy_verify(changed, RSA_TXT)


def test_tampered_header_fails_signature():
    raw = sign().replace(b"Subject: Hello there", b"Subject: Hello Bob")
    res = verify(raw, RSA_TXT)
    assert res.result == "fail" and res.reason == "signature" and res.body_hash_ok


def test_added_header_instance_breaks_signature_when_signed_bottom_up():
    raw = sign()
    raw = raw.replace(b"\r\n\r\nHi Bob", b"\r\nSubject: injected\r\n\r\nHi Bob")
    assert verify(raw, RSA_TXT).result == "fail"
    assert not dkimpy_verify(raw, RSA_TXT)


def test_length_tag_partial_coverage():
    raw = sign(length=True) + b"Appended unsigned text.\r\n"
    res = verify(raw, RSA_TXT)
    assert res.result == "pass" and res.l_partial
    assert dkimpy_verify(raw, RSA_TXT)


@pytest.mark.parametrize("status,txt,reason", [
    ("nxdomain", None, "no_key"), ("error", None, "dns"), ("ok", "v=DKIM1; k=rsa; p=", "no_key"),
    ("ok", "v=DKIM1; h=sha1; k=rsa; p=AAAA", "key_hash"),
])
def test_unverifiable_key_states(status, txt, reason):
    res = verify(sign(), txt, status)
    assert res.result == "unverifiable" and res.reason == reason


def test_rsa_sha1_and_weak_keys_are_unverifiable():
    raw = sign(algo=b"rsa-sha1")
    assert verify(raw, RSA_TXT).reason == "algorithm"
    # A 512-bit public key in DNS (the size check happens before any signature maths).
    weak = rsa.RSAPublicNumbers(65537, (1 << 511) | 0x1235).public_key()
    der = weak.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert verify(sign(), "v=DKIM1; k=rsa; p=" + base64.b64encode(der).decode()).reason == "weak_key"


def test_expired_signature_is_unverifiable():
    raw = sign()
    raw = raw.replace(b"DKIM-Signature: v=1;", b"DKIM-Signature: v=1; x=1000;", 1)
    assert verify(raw, RSA_TXT).reason == "expired"


def test_pkcs1_rsa_key_record_is_accepted():
    key = serialization.load_pem_private_key(RSA_PEM, None)
    pkcs1 = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1)
    assert verify(sign(), "v=DKIM1; k=rsa; p=" + base64.b64encode(pkcs1).decode()).result == "pass"


def test_body_canonicalisation_rules():
    assert dkimverify.canonical_body(b"", "simple") == b"\r\n"
    assert dkimverify.canonical_body(b"", "relaxed") == b""
    assert dkimverify.canonical_body(b"a  b \r\n\r\n\r\n", "relaxed") == b"a b\r\n"
    assert dkimverify.canonical_body(b"a  b \r\n\r\n", "simple") == b"a  b \r\n"
    assert dkimverify.canonical_header(b"SUBJect :  a \t b\r\n c \r\n", "relaxed") == b"subject:a b c\r\n"


# DMARC ------------------------------------------------------------------------------------------------------

def test_tree_walk_limits():
    assert dmarc.tree_walk("a.b.example.com") == ["a.b.example.com", "b.example.com", "example.com", "com"]
    long = ".".join(f"l{i}" for i in range(10)) + ".example.com"
    walk = dmarc.tree_walk(long)
    assert len(walk) == 8 and walk[0] == long and len(walk[1].split(".")) == 7 and walk[-1] == "com"


def lookups(records):
    return {name: ("ok", [records[name]]) if name in records else ("nxdomain", []) for name in records} | {}


def discover(domain, records, exists=True):
    names = dmarc.tree_walk(domain)
    table = {n: (("ok", [records[n]]) if n in records else ("nxdomain", [])) for n in names}
    return dmarc.discover(domain, table, exists)


def test_policy_discovery_and_subdomain_policies():
    records = {"example.com": "v=DMARC1; p=reject; sp=quarantine; np=reject"}
    assert discover("example.com", records).published == "reject"
    assert discover("news.example.com", records).published == "quarantine"
    assert discover("ghost.example.com", records, exists=False).published == "reject"
    assert discover("news.example.com", {"example.com": "v=DMARC1; p=none"}).published == "none"
    assert discover("example.org", {}).status == "absent"


def test_testing_flag_softens_one_step():
    policy = discover("example.com", {"example.com": "v=DMARC1; p=reject; t=y"})
    assert policy.testing and policy.effective == "quarantine"
    policy = discover("example.com", {"example.com": "v=DMARC1; p=quarantine; t=y"})
    assert policy.effective == "none"


def test_psd_and_org_domain():
    records = {"com": "v=DMARC1; p=none; psd=y", "example.com": "v=DMARC1; p=reject"}
    policy = discover("a.example.com", records)
    assert policy.org_domain == "example.com" and policy.record_domain == "example.com"
    policy = discover("mail.dept.example.com", {"dept.example.com": "v=DMARC1; p=reject; psd=n"})
    assert policy.org_domain == "dept.example.com"


def test_multiple_records_are_ignored_and_dns_errors_are_temporary():
    table = {n: ("ok", ["v=DMARC1; p=reject", "v=DMARC1; p=none"]) if n == "example.com" else ("nxdomain", [])
             for n in dmarc.tree_walk("example.com")}
    assert dmarc.discover("example.com", table, True).status == "absent"
    table = {n: ("error", []) for n in dmarc.tree_walk("example.com")}
    assert dmarc.discover("example.com", table, True).status == "temperror"


@pytest.mark.parametrize("dkim_results,return_path,result,signal", [
    ([("example.com", "pass")], "b@other.example", "pass", None),
    ([("mail.example.com", "pass")], "b@other.example", "pass", None),          # relaxed alignment
    ([("other.example", "pass")], "b@other.example", "fail", "AUTH_DMARC_FAIL_ENFORCED"),
    ([], "b@bounce.example.com", "none", None),                                # SPF might align: undeterminable
    ([], "", "none", None),                                                    # null sender: HELO identity
    ([], None, "none", None),
    ([("example.com", "unverifiable")], "b@other.example", "none", None),
    ([("example.com", "fail")], "b@other.example", "fail", "AUTH_DMARC_FAIL_ENFORCED"),
])
def test_evaluate(dkim_results, return_path, result, signal):
    policy = discover("example.com", {"example.com": "v=DMARC1; p=reject"})
    outcome = dmarc.evaluate("example.com", policy, PSL, dkim_results, return_path, set())
    assert outcome.result == result and outcome.signal == signal


def test_modified_in_store_is_not_a_dmarc_failure():
    policy = discover("example.com", {"example.com": "v=DMARC1; p=reject"})
    outcome = dmarc.evaluate("example.com", policy, PSL, [("example.com", "fail")], "b@other.example", {"example.com"})
    assert outcome.result == "none" and outcome.signal is None


def test_policy_none_gives_caution_signal():
    policy = discover("example.com", {"example.com": "v=DMARC1; p=none"})
    outcome = dmarc.evaluate("example.com", policy, PSL, [], "b@other.example", set())
    assert outcome.signal == "AUTH_DMARC_FAIL_NONE"


# Through the pipeline -----------------------------------------------------------------------------------------

def test_pipeline_partial_l_and_body_modified():
    raw = sign(length=True) + b"Unsigned appendix.\r\n"
    broker = LocalBroker(dns={"s1._domainkey.sender.example": {"status": "ok", "txt": [RSA_TXT]}})
    result = run_pipeline(raw, broker)
    assert "AUTH_DKIM_PARTIAL_L" in ids(result)
    assert result["auth"]["dkim"][0] == {"d": "sender.example", "s": "s1", "result": "pass", "aligned": True,
                                         "l_partial": True}
    # Body changed in the store after the provider reported a pass.
    modified = (b"Authentication-Results: mx.provider.example; dkim=pass header.d=sender.example\r\n"
                + sign().replace(b"this   is", b"THIS   is"))
    result = run_pipeline(modified, broker)
    assert "AUTH_DKIM_BODY_MODIFIED" in ids(result)
    assert "AUTH_DMARC_FAIL_ENFORCED" not in ids(result)


def test_pipeline_replay_suspect():
    raw = (b"Delivered-To: victim@example.org\r\n" + sign().replace(b"To: bob@example.org", b"To: bob@example.org"))
    broker = LocalBroker(dns={"s1._domainkey.sender.example": {"status": "ok", "txt": [RSA_TXT]}})
    # dkimpy stamps t= with the signing time; deliver it three days later.
    import time as _time

    result = run_pipeline(raw, broker, meta_extra={"received_at": int(_time.time()) + 3 * 86400})
    assert "AUTH_REPLAY_SUSPECT" in ids(result)
    addressed = raw.replace(b"Delivered-To: victim@example.org", b"Delivered-To: bob@example.org")
    result = run_pipeline(addressed, broker, meta_extra={"received_at": int(_time.time()) + 3 * 86400})
    assert "AUTH_REPLAY_SUSPECT" not in ids(result)


def test_pipeline_dns_failure_marks_auth_partial():
    broker = LocalBroker(dns={"s1._domainkey.sender.example": {"status": "error", "txt": []}})
    result = run_pipeline(sign(), broker)
    assert result["completeness"]["auth"] == "partial"
    assert result["auth"]["dkim"][0]["result"] == "unverifiable"
