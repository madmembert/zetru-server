"""HTML → visible text with CSS-hidden content removed (concept §6.5).

Hidden: display:none, visibility:hidden, opacity ~0, font-size ≤ 1px, text colour equal to an explicit
background colour, zero-size or clipped boxes with overflow hidden, off-screen positioning, mso-hide:all,
the `hidden` attribute. Rules come from inline styles, `bgcolor`/`color` attributes and simple selectors
(`.class`, `#id`, `tag`, `tag.class`) in <style> blocks outside @-rules. Nothing is rendered or fetched.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser

_VOID = frozenset("area base br col embed hr img input link meta param source track wbr keygen".split())
_SKIP = frozenset("script style head title template noscript object iframe svg math".split())
_BLOCK = frozenset("p div br tr li h1 h2 h3 h4 h5 h6 table section article header footer ul ol blockquote "
                   "pre hr address center dl dt dd form fieldset nav aside main figure figcaption".split())
_CELL = frozenset(("td", "th"))
_QUOTE_CLASSES = ("gmail_quote", "moz-cite-prefix", "yahoo_quoted", "divrplyfwdmsg", "outlookmessageheader")
_BRACE = re.compile(r"([{}])")
_SIMPLE_SELECTOR = re.compile(r"(?:[a-z][a-z0-9]*)?(?:\.[\w-]+)?|#[\w-]+")
_NAMED_COLOURS = {
    "white": "ffffff", "black": "000000", "red": "ff0000", "green": "008000", "blue": "0000ff",
    "yellow": "ffff00", "gray": "808080", "grey": "808080", "silver": "c0c0c0", "transparent": None,
    "whitesmoke": "f5f5f5", "snow": "fffafa", "ivory": "fffff0", "ghostwhite": "f8f8ff",
}
MAX_STYLE_RULES = 2000


@dataclass
class Anchor:
    href: str
    text: str
    hidden: bool


@dataclass
class HtmlResult:
    visible: str = ""
    state_text: str = ""            # visible, outside quotes, with " [LINK]" after link text
    raw_visible: str = ""           # visible text before zero-width stripping (obfuscation check)
    visible_chars: int = 0
    hidden_chars: int = 0
    preheader_hidden_chars: int = 0
    anchors: list[Anchor] = field(default_factory=list)
    other_urls: list[str] = field(default_factory=list)   # form actions, area links, meta refresh
    images: int = 0


def parse_declarations(style: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for decl in style.split(";"):
        if ":" not in decl:
            continue
        prop, value = decl.split(":", 1)
        prop = prop.strip().lower()
        value = value.strip().lower().replace("!important", "").strip()
        if prop and len(prop) < 64:
            out[prop] = value[:200]
    return out


def strip_css_comments(css: str) -> str:
    """Removes /* … */ comments; same result as re.sub(r"/\\*.*?\\*/", "", css, flags=re.S) in linear time (the
    lazy regex rescans the rest of the text from every unclosed "/*", PY-05)."""
    out, pos = [], 0
    while True:
        start = css.find("/*", pos)
        if start < 0:
            break
        end = css.find("*/", start + 2)
        if end < 0:
            break
        out.append(css[pos:start])
        pos = end + 2
    out.append(css[pos:])
    return "".join(out)


def css_rules(css: str):
    """(selector text, declaration text) pairs; same matches as re.finditer(r"([^{}]+)\\{([^{}]*)\\}", css) in
    linear time (that regex is quadratic on long brace-free text, PY-05)."""
    parts = _BRACE.split(css)   # text, brace, text, brace, …: texts at even, braces at odd indices
    i = 1
    while i < len(parts):
        if parts[i] == "{" and i + 2 < len(parts) and parts[i + 2] == "}" and parts[i - 1]:
            yield parts[i - 1], parts[i + 1]
            i += 4
        else:
            i += 2


def _strip_at_rules(css: str) -> str:
    """Removes @media/@supports/... blocks (conditional rules would make hiding decisions unreliable)."""
    out = []
    i, n = 0, len(css)
    while i < n:
        if css[i] == "@":
            semi = css.find(";", i)
            brace = css.find("{", i, semi if semi >= 0 else n)   # bounded search keeps "@;@;…" linear
            if brace < 0:
                i = n if semi < 0 else semi + 1
                continue
            depth, j = 0, brace
            while j < n:
                if css[j] == "{":
                    depth += 1
                elif css[j] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            i = j + 1
            continue
        out.append(css[i])
        i += 1
    return "".join(out)


def _style_blocks(html: str, limit: int = 200):
    """<style> contents found with a linear scan (a regex with a lazy body is quadratic on unclosed tags)."""
    lower = html.lower()
    pos = 0
    for _ in range(limit):
        start = lower.find("<style", pos)
        if start < 0:
            return
        open_end = lower.find(">", start)
        if open_end < 0:
            return
        close = lower.find("</style", open_end)
        if close < 0:
            return
        yield html[open_end + 1:close]
        pos = close + 7


def parse_stylesheets(html: str) -> dict[str, dict[str, str]]:
    """Maps simple selectors ('.c', '#i', 'tag', 'tag.c') to merged declarations."""
    rules: dict[str, dict[str, str]] = {}
    count = 0
    for block in _style_blocks(html[:2_000_000]):
        css = _strip_at_rules(strip_css_comments(block))
        for selectors, declarations in css_rules(css):
            decls = parse_declarations(declarations)
            for selector in selectors.split(","):
                sel = selector.strip().lower()
                if sel and _SIMPLE_SELECTOR.fullmatch(sel):
                    rules.setdefault(sel, {}).update(decls)
                    count += 1
                    if count > MAX_STYLE_RULES:
                        return rules
    return rules


def parse_colour(value: str | None) -> str | None:
    if not value:
        return None
    v = value.strip().lower()
    if v in _NAMED_COLOURS:
        return _NAMED_COLOURS[v]
    m = re.fullmatch(r"#?([0-9a-f]{3}|[0-9a-f]{6})", v)
    if m:
        h = m.group(1)
        return "".join(c * 2 for c in h) if len(h) == 3 else h
    m = re.fullmatch(r"rgba?\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})(?:\s*,\s*([\d.]+))?\s*\)", v)
    if m:
        if m.group(4) is not None:
            try:
                if float(m.group(4)) < 0.05:
                    return None  # transparent
            except ValueError:
                return None
        return "".join(f"{min(255, int(x)):02x}" for x in m.groups()[:3])
    return None


def _length_px(value: str) -> float | None:
    m = re.match(r"^(-?[\d.]+)\s*(px|pt|em|rem|%|)?", value.strip())
    if not m:
        return None
    try:
        number = float(m.group(1))
    except ValueError:
        return None
    unit = m.group(2) or ""
    if unit == "pt":
        return number * 4 / 3
    if unit in ("em", "rem", "%"):
        return 0.0 if number == 0 else None
    if unit == "" and number != 0:
        return None
    return number


def _background(decls: dict[str, str]) -> str | None:
    if "background-color" in decls:
        return parse_colour(decls["background-color"])
    if "background" in decls:
        for token in decls["background"].split():
            colour = parse_colour(token)
            if colour:
                return colour
    return None


def hides(decls: dict[str, str]) -> bool:
    if decls.get("display", "").startswith("none"):
        return True
    if decls.get("visibility", "") in ("hidden", "collapse"):
        return True
    if "opacity" in decls:
        try:
            if float(decls["opacity"].split()[0]) <= 0.01:
                return True
        except (ValueError, IndexError):
            pass
    if "font-size" in decls:
        size = _length_px(decls["font-size"])
        if size is not None and size <= 1.0:
            return True
    if decls.get("mso-hide", "") == "all":
        return True
    overflow_hidden = "hidden" in decls.get("overflow", "") or "hidden" in decls.get("overflow-y", "")
    if overflow_hidden:
        for prop in ("max-height", "height", "max-width", "width"):
            if prop in decls:
                size = _length_px(decls[prop])
                if size is not None and size <= 1.0:
                    return True
    if decls.get("position", "") in ("absolute", "fixed"):
        clip = decls.get("clip", "").replace(" ", "")
        if clip.startswith("rect(0") or clip.startswith("rect(1px,1px,1px,1px"):
            return True
        for prop in ("left", "top"):
            if prop in decls:
                size = _length_px(decls[prop])
                if size is not None and size <= -999:
                    return True
    if "text-indent" in decls:
        size = _length_px(decls["text-indent"])
        if size is not None and size <= -999:
            return True
    if decls.get("clip-path", "").replace(" ", "") in ("inset(50%)", "inset(100%)", "circle(0)", "circle(0px)"):
        return True
    return False


@dataclass
class _Frame:
    tag: str
    hidden: bool
    skip: bool
    quoted: bool
    colour: str | None
    background: str | None


class _Extractor(HTMLParser):
    def __init__(self, rules: dict[str, dict[str, str]]):
        super().__init__(convert_charrefs=True)
        self.rules = rules
        self.stack: list[_Frame] = []
        self.visible: list[str] = []
        self.state: list[str] = []
        self.result = HtmlResult()
        self.anchor: dict | None = None
        self.seen_visible = False

    # Current context ------------------------------------------------------------------------------
    def _top(self) -> _Frame:
        return self.stack[-1] if self.stack else _Frame("", False, False, False, None, None)

    def _decls_for(self, tag: str, attrs: dict[str, str]) -> dict[str, str]:
        decls: dict[str, str] = {}
        if tag in self.rules:
            decls.update(self.rules[tag])
        classes = attrs.get("class", "").lower().split()
        for c in classes[:20]:
            for key in ("." + c, tag + "." + c):
                if key in self.rules:
                    decls.update(self.rules[key])
        ident = attrs.get("id", "").lower().strip()
        if ident and "#" + ident in self.rules:
            decls.update(self.rules["#" + ident])
        if "style" in attrs:
            decls.update(parse_declarations(attrs["style"]))
        return decls

    def handle_starttag(self, tag: str, attrs_list) -> None:
        attrs = {k.lower(): (v or "") for k, v in attrs_list[:64]}
        parent = self._top()
        if tag == "img":
            self.result.images += 1
        if tag in ("form",) and attrs.get("action"):
            self.result.other_urls.append(attrs["action"])
        if tag == "area" and attrs.get("href"):
            self.result.other_urls.append(attrs["href"])
        if tag == "meta" and attrs.get("http-equiv", "").lower() == "refresh":
            m = re.search(r"url\s*=\s*['\"]?([^'\";]+)", attrs.get("content", ""), re.I)
            if m:
                self.result.other_urls.append(m.group(1).strip())
        if tag in _BLOCK:
            self._emit_break()
        elif tag in _CELL:
            self._emit_text(" ", structural=True)
        if tag in _VOID:
            return
        decls = self._decls_for(tag, attrs)
        colour = parse_colour(decls.get("color"))
        if colour is None and tag == "font":
            colour = parse_colour(attrs.get("color"))
        background = _background(decls) or parse_colour(attrs.get("bgcolor"))
        eff_colour = colour or parent.colour
        eff_background = background or parent.background
        hidden = parent.hidden or hides(decls) or "hidden" in attrs
        if not hidden and eff_colour and eff_background and eff_colour == eff_background and (colour or background):
            hidden = True
        classes = attrs.get("class", "").lower()
        quoted = parent.quoted or tag == "blockquote" or any(q in classes for q in _QUOTE_CLASSES) \
            or attrs.get("id", "").lower() in ("divrplyfwdmsg", "appendonsend")
        frame = _Frame(tag, hidden, parent.skip or tag in _SKIP, quoted, eff_colour, eff_background)
        if len(self.stack) < 512:
            self.stack.append(frame)
        if tag == "a" and attrs.get("href"):
            self._close_anchor()
            self.anchor = {"href": attrs["href"], "text": [], "hidden": hidden}

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in _VOID:
            self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        if tag == "a":
            self._close_anchor()
        if tag in _BLOCK:
            self._emit_break()
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i].tag == tag:
                del self.stack[i:]
                break

    def handle_data(self, data: str) -> None:
        frame = self._top()
        if frame.skip:
            return
        if frame.hidden:
            n = sum(1 for ch in data if not ch.isspace())
            self.result.hidden_chars += n
            if not self.seen_visible:
                self.result.preheader_hidden_chars += n
            return
        self._emit_text(data, quoted=frame.quoted)
        if self.anchor is not None:
            self.anchor["text"].append(data)

    # Output -----------------------------------------------------------------------------------------
    def _emit_text(self, data: str, structural: bool = False, quoted: bool = False) -> None:
        self.visible.append(data)
        if not quoted:
            self.state.append(data)
        if not structural:
            n = sum(1 for ch in data if not ch.isspace())
            if n:
                self.seen_visible = True
                self.result.visible_chars += n

    def _emit_break(self) -> None:
        self.visible.append("\n")
        self.state.append("\n")

    def _close_anchor(self) -> None:
        if self.anchor is None:
            return
        text = " ".join("".join(self.anchor["text"]).split())
        self.result.anchors.append(Anchor(self.anchor["href"], text[:300], self.anchor["hidden"]))
        if not self.anchor["hidden"]:
            self.state.append(" [LINK] ")
        self.anchor = None


def extract(html: str) -> HtmlResult:
    rules = parse_stylesheets(html)
    parser = _Extractor(rules)
    try:
        parser.feed(html)
        parser.close()
    except Exception:  # HTMLParser is lenient; treat anything else as end of input
        pass
    parser._close_anchor()
    result = parser.result
    result.raw_visible = "".join(parser.visible)
    result.visible = result.raw_visible
    result.state_text = "".join(parser.state)
    return result
