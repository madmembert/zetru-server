import hashlib

import pytest

from zetru_analyzer import domains, urls
from zetru_analyzer.domains import PublicSuffixList, normalize_domain
from zetru_analyzer.packs import default_packs

PSL = domains.bundled_psl()


@pytest.mark.parametrize("host,expected", [
    ("www.example.com", "example.com"),
    ("a.b.example.co.uk", "example.co.uk"),
    ("foo.pages.dev", "foo.pages.dev"),            # private section
    ("x.y.foo.github.io", "foo.github.io"),
    ("com", None),
    ("co.uk", None),
    ("paypal.de", "paypal.de"),
    ("xn--mller-kva.de", "xn--mller-kva.de"),
])
def test_registrable_domain(host, expected):
    assert PSL.registrable_domain(host) == expected


def test_psl_wildcard_and_exception_rules():
    psl = PublicSuffixList.parse("\n".join(["com", "*.ck", "!www.ck"] + [f"t{i}" for i in range(1000)]))
    assert psl.public_suffix("a.b.ck") == "b.ck"
    assert psl.registrable_domain("a.b.ck") == "a.b.ck"
    assert psl.public_suffix("www.ck") == "ck"
    assert psl.registrable_domain("x.www.ck") == "www.ck"
    assert psl.registrable_domain("unknowntld") is None
    assert psl.registrable_domain("a.unknowntld") == "a.unknowntld"


@pytest.mark.parametrize("raw,expected", [
    ("Example.COM.", "example.com"),
    ("müller.de", "xn--mller-kva.de"),
    ("pаypal.com", "xn--pypal-4ve.com"),   # Cyrillic a
    ("exa mple.com", None),
    ("-bad.com", None),
    ("", None),
    ("a..b", None),
    ("pay​pal.com", "paypal.com"),    # zero-width removed
])
def test_normalize_domain(raw, expected):
    assert normalize_domain(raw) == expected


def test_ip_literals():
    assert domains.is_ip_literal("192.168.0.1")
    assert domains.is_ip_literal("[::1]")
    assert domains.is_ip_literal("0x7f.1")
    assert not domains.is_ip_literal("example.com")


@pytest.mark.parametrize("raw,canonical", [
    ("HTTPS://Example.COM:443/Path?q=1#frag", "https://example.com/Path?q=1"),
    ("http://example.com:80", "http://example.com/"),
    ("http://example.com:8080/x", "http://example.com:8080/x"),
    ("https://example.com", "https://example.com/"),
    ("www.example.com/a", "http://www.example.com/a"),
    ("https:\\\\evil.example\\path?x=\\y", "https://evil.example/path?x=\\y"),
    ("https:/evil.example/x", "https://evil.example/x"),
    ("https://paypal.com@evil.example/login", "https://paypal.com@evil.example/login"),
    ("http://3232235777/", "http://192.168.1.1/"),
    ("http://0x7f.1/", "http://127.0.0.1/"),
    ("https://müller.de/x", "https://xn--mller-kva.de/x"),
    ("  https://ex\nample.com/a\tb  ", "https://example.com/ab"),
    ("https://[2001:DB8::1]:443/", "https://[2001:db8::1]/"),
])
def test_canonicalize(raw, canonical):
    assert urls.canonicalize(raw)[0] == canonical


@pytest.mark.parametrize("raw", ["javascript:alert(1)", "mailto:a@b.c", "ftp://x.y", "https://exa mple.com/", "https://host:99999/",
                                 "https://ho_st.-x/"])
def test_canonicalize_rejects(raw):
    assert urls.canonicalize(raw) is None


def test_url_sha256_is_over_canonical_url():
    canonical, host, is_ip = urls.canonicalize("HTTPS://Example.com/a#x")
    assert host == "example.com" and not is_ip
    assert urls.url_sha256(canonical) == hashlib.sha256(b"https://example.com/a").hexdigest()


def test_userinfo_trick_host():
    assert urls.canonicalize("https://www.paypal.com@evil.example/")[1] == "evil.example"


def test_text_extraction_strips_punctuation():
    found = urls.extract_from_text("See https://a.example/x). Or www.b.example, and (https://c.example/y)!")
    assert found == ["https://a.example/x", "www.b.example", "https://c.example/y"]


@pytest.mark.parametrize("wrapped,dest", [
    ("https://www.google.com/url?q=https%3A%2F%2Fevil.example%2Fa&sa=D", "https://evil.example/a"),
    ("https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.example%2Fb&data=x", "https://evil.example/b"),
    ("https://urldefense.proofpoint.com/v2/url?u=https-3A__evil.example_c&d=x", "https://evil.example/c"),
    ("https://urldefense.com/v3/__https://evil.example/d__;!!abc", "https://evil.example/d"),
    ("https://l.facebook.com/l.php?u=https%3A%2F%2Fevil.example%2Fe", "https://evil.example/e"),
])
def test_unwrap_redirectors(wrapped, dest):
    canonical, host, _ = urls.canonicalize(wrapped)
    assert urls.unwrap(canonical, host, default_packs())[0] == dest


def test_shorteners_are_not_unwrapped():
    canonical, host, _ = urls.canonicalize("https://bit.ly/abc")
    assert urls.unwrap(canonical, host, default_packs()) is None
    assert default_packs().is_shortener("bit.ly")


def test_domain_in_link_text():
    assert urls.domain_in_text("paypal.com/konto") == "paypal.com"
    assert urls.domain_in_text("https://www.example.org/x") == "www.example.org"
    assert urls.domain_in_text("Jetzt ansehen") is None
