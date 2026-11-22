import pytest

from zetru_analyzer import domains, htmltext, lookalike, state
from zetru_analyzer.packs import default_packs

PSL = domains.bundled_psl()
PACKS = default_packs()
TEXT = "Dies ist versteckter Text der nicht angezeigt wird"


@pytest.mark.parametrize("html", [
    f'<div style="display:none">{TEXT}</div>',
    f'<span style="visibility: hidden">{TEXT}</span>',
    f'<p style="opacity:0">{TEXT}</p>',
    f'<p style="font-size:0px">{TEXT}</p>',
    f'<p style="font-size:1px">{TEXT}</p>',
    f'<p style="font-size:0.5pt">{TEXT}</p>',
    f'<div style="max-height:0;overflow:hidden">{TEXT}</div>',
    f'<div style="mso-hide:all">{TEXT}</div>',
    f'<p style="color:#fff;background-color:#ffffff">{TEXT}</p>',
    f'<table bgcolor="#000000"><tr><td><font color="black">{TEXT}</font></td></tr></table>',
    f'<style>.pre {{ display: none !important; }}</style><div class="pre">{TEXT}</div>',
    f'<style>#x {{visibility:hidden}}</style><div id="x">{TEXT}</div>',
    f'<div hidden>{TEXT}</div>',
    f'<div style="position:absolute;left:-9999px">{TEXT}</div>',
    f'<div style="display:none"><p>{TEXT}</p></div>',
])
def test_hidden_variants(html):
    result = htmltext.extract("<p>Sichtbar</p>" + html)
    assert "versteckter" not in result.visible
    assert result.hidden_chars >= len(TEXT.replace(" ", ""))


@pytest.mark.parametrize("html", [
    f'<p style="color:#333333">{TEXT}</p>',
    f'<p style="font-size:14px">{TEXT}</p>',
    f'<style>@media (max-width:600px) {{ .m {{ display:none }} }}</style><p class="m">{TEXT}</p>',
    f'<p style="color:white">{TEXT}</p>',   # no explicit background: not judged as hidden
    f'<div style="height:0">{TEXT}</div>',  # without overflow hidden the text is still shown
])
def test_visible_variants(html):
    result = htmltext.extract(html)
    assert "versteckter" in result.visible
    assert result.hidden_chars == 0


def test_preheader_counted_separately():
    result = htmltext.extract('<div style="display:none">Kurzer Vorschautext</div><p>Hallo Welt</p>'
                              '<span style="display:none">mehr</span>')
    assert result.preheader_hidden_chars == len("KurzerVorschautext")
    assert result.hidden_chars == result.preheader_hidden_chars + 4


def test_scripts_styles_and_head_are_not_text():
    result = htmltext.extract("<head><title>T</title></head><style>p{}</style><script>var x='geheim';</script><p>Ja</p>")
    assert "geheim" not in result.visible and result.hidden_chars == 0 and "Ja" in result.visible


def test_anchors_and_state_markers():
    result = htmltext.extract('<p>Bitte <a href="https://x.example/a">hier klicken</a>.</p>'
                              '<blockquote>Alte Nachricht <a href="https://q.example">q</a></blockquote>'
                              '<form action="https://f.example/post"></form>')
    assert [a.href for a in result.anchors] == ["https://x.example/a", "https://q.example"]
    assert result.anchors[0].text == "hier klicken"
    assert "[LINK]" in result.state_text and "Alte Nachricht" not in result.state_text
    assert "Alte Nachricht" in result.visible
    assert result.other_urls == ["https://f.example/post"]


def test_state_render_and_quote_stripping():
    body = state.body_tokens("Hallo Anna,\nwie geht es dir? https://x.example/a\n\n> zitiert\n-- \nSignatur Text")
    assert "zitiert" not in body and "Signatur" not in body and "[LINK]" in body
    rendered = state.render("PayPal", "paypa1.example", ["freemail"], "none", "Betreff", body,
                            [("paypal.com", "evil.example", True)], ["pdf"], None)
    lines = rendered.splitlines()
    assert lines[0] == "[FROM] PayPal | paypa1.example | flags: freemail"
    assert "[LINKS] paypal.com → evil.example [MISMATCH]" in lines
    assert [l.split(" ")[0] for l in lines] == ["[FROM]", "[AUTH]", "[SUBJECT]", "[BODY-HEAD]", "[LINKS]", "[ATTACH]",
                                                "[OCR]", "[BODY-TAIL]"]


def test_state_head_and_tail_limits():
    words = [f"w{i}" for i in range(400)]
    rendered = state.render("", None, [], "none", "s", words, [], [], None)
    head = rendered.splitlines()[3].split()[1:]
    tail = rendered.splitlines()[7].split()[1:]
    assert len(head) == state.HEAD_TOKENS and len(tail) == state.TAIL_TOKENS and tail[-1] == "w399"


@pytest.mark.parametrize("host,brand,rule", [
    ("xn--pypal-4ve.com", "paypal", 1),          # Cyrillic a
    ("paypa1.de", "paypal", 1),
    ("paypal.co", "paypal", 3),
    ("login.paypal.github.io", "paypal", 3),
    ("paypa1-sicherheit.com", "paypal", 4),
    ("paypal.konto-check.net", "paypal", 4),
    ("micros0ft-security.com", "microsoft", 4),
    ("amazom.de", "amazon", 2),
    ("deutsche-bank-sicherheit.com", "deutschebank", 4),
    ("sparkasse-login.com", "sparkasse", 4),
    ("dhl-paket-zustellung.com", "dhl", 4),
])
def test_brand_lookalikes(host, brand, rule):
    hit = lookalike.brand_lookalike(host, PSL, PACKS)
    assert hit is not None and hit.brand == brand and hit.rule == rule


@pytest.mark.parametrize("host", [
    "paypal.com", "www.paypal.de", "e.mail.paypal.de", "google.at", "sparkasse-koelnbonn.de",
    "volksbank-mittelhessen.de", "example.com", "otto-mueller.de", "ups-shop.example", "booking-system.de",
    "zoll-auktion.de",
])
def test_no_lookalike(host):
    assert lookalike.brand_lookalike(host, PSL, PACKS) is None


def test_damerau_levenshtein():
    assert lookalike.damerau_levenshtein("paypal", "papyal") == 1   # transposition
    assert lookalike.damerau_levenshtein("amazon", "amazom") == 1
    assert lookalike.damerau_levenshtein("abc", "xyzuvw", limit=2) == 3


def test_brand_tokens_in_display_names():
    assert [b.key for b in PACKS.brands_mentioned("PayPal Kundenservice")] == ["paypal"]
    assert [b.key for b in PACKS.brands_mentioned("Micr0soft Support")] == ["microsoft"]
    assert PACKS.brands_mentioned("Otto Müller", "otto.mueller") == []
    assert PACKS.brands_mentioned("Ups, kleiner Fehler") == []
    assert [b.key for b in PACKS.brands_mentioned("UPS Germany")] == ["ups"]
    assert [b.key for b in PACKS.brands_mentioned("Service", "paypal-service")] == ["paypal"]
    assert [b.key for b in PACKS.brands_mentioned("", "paypalkundendienst")] == ["paypal"]


def test_official_sender_rules():
    paypal = PACKS.brand("paypal")
    assert paypal.is_official_sender("mail.paypal.de", "paypal.de")
    assert not paypal.is_official_sender("paypal.example", "paypal.example")
    polizei = PACKS.brand("polizei")
    assert polizei.is_official_sender("polizei.bayern.de", "bayern.de")      # authority suffix
    sparkasse = PACKS.brand("sparkasse")
    assert sparkasse.is_official_sender("sparkasse-hannover.de", "sparkasse-hannover.de")  # regional member
    microsoft = PACKS.brand("microsoft")
    assert not microsoft.is_official_sender("outlook.com", "outlook.com")   # freemail is never an official sender
