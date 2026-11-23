"""Feed parsing, validation and atomic publication (concept §6.7, server-internal-api.md "Shared volumes").

Publication: the normalised data is written into /feeds/<id>/.tmp-<version>/ (same file system), renamed to
/feeds/<id>/<version>/, then current.json is replaced atomically (write temp + fsync + rename). Directories are
0755 and files 0644 so the analyzer (uid 10002) and inference (uid 10003) can read them. The two previous
versions are kept so readers that loaded an older current.json can finish.

Security review fixes (DECISIONS.md):
- never-list guard (PY-11): an entry is removed when it equals or lies below a name of the static never-list
  (brands, freemail), equals a Majestic top-1,000 name (exactly: subdomains of hosting platforms in the top 1,000
  are user content and are rightly listed), or is a public suffix — wildcard PSL rules included;
- change ratio (PY-18): each release is compared with the previous one and with a reference version that moves
  at most once per 24 h, so a list cannot be drained in many small steps;
- memory (PY-14): entries are compared as sorted arrays of 64-bit hashes; the previous version is streamed.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import shutil
import time
from array import array
from dataclasses import dataclass

HERE = os.path.dirname(os.path.abspath(__file__))
MANIFEST_PATH = os.path.join(HERE, "manifest.json")
NEVER_LIST_PATH = os.path.join(HERE, "never_list.txt")
KEEP_VERSIONS = 3
MAX_REMOVED_RATIO = 0.50
MAX_ADDED_RATIO = 3.00
MAX_INVALID_RATIO = 0.05
MAJESTIC_TOP_NEVER = 1000
REFERENCE_FILE = "reference.json"
REFERENCE_AGE_S = 86400
_LABEL = re.compile(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?")
_FEED_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,47}")


class ValidationError(Exception):
    pass


@dataclass(frozen=True)
class Feed:
    id: str
    url: str
    format: str
    file: str
    licence: str
    commercial: bool
    attribution: str | None
    refresh_s: int
    min_interval_s: int
    min_bytes: int
    max_bytes: int
    min_entries: int
    max_entries: int
    never_list_guard: bool


def load_manifest(path: str = MANIFEST_PATH) -> list[Feed]:
    with open(path, "r", encoding="utf-8") as handle:
        doc = json.load(handle)
    feeds = []
    for entry in doc["feeds"]:
        if not _FEED_ID.fullmatch(entry["id"]) or not entry["url"].startswith("https://"):
            raise ValueError(f"invalid manifest entry {entry.get('id')}")
        feeds.append(Feed(
            id=entry["id"], url=entry["url"], format=entry["format"], file=entry["file"], licence=entry["licence"],
            commercial=bool(entry["commercial"]), attribution=entry.get("attribution"),
            refresh_s=int(entry["refresh_s"]), min_interval_s=int(entry.get("min_interval_s", 0)),
            min_bytes=int(entry["min_bytes"]), max_bytes=int(entry["max_bytes"]), min_entries=int(entry["min_entries"]),
            max_entries=int(entry["max_entries"]), never_list_guard=bool(entry.get("never_list_guard", False)),
        ))
    return feeds


def allowed(feed: Feed, env=os.environ) -> bool:
    return feed.commercial or env.get("ZETRU_ALLOW_NONCOMMERCIAL") == "1"


def normalize_domain(value: str) -> str | None:
    host = value.strip().rstrip(".").lower()
    if not host or len(host) > 253:
        return None
    labels = []
    for label in host.split("."):
        if not label.isascii():
            try:
                label = label.encode("idna").decode("ascii")
            except (UnicodeError, ValueError):
                return None
        if not _LABEL.fullmatch(label):
            return None
        labels.append(label)
    return ".".join(labels) if len(labels) >= 2 else None


# Parsers: raw file → (normalised bytes, entry keys) -------------------------------------------------------

def _lines(path: str):
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            yield line.rstrip("\r\n")


def parse_psl(path: str) -> tuple[bytes, list[str]]:
    with open(path, "rb") as handle:
        raw = handle.read()
    text = raw.decode("utf-8")
    if "===BEGIN ICANN DOMAINS===" not in text or "===END ICANN DOMAINS===" not in text:
        raise ValidationError("psl_markers")
    rules = [l.strip().split()[0] for l in text.splitlines() if l.strip() and not l.strip().startswith("//")]
    for rule in rules:
        if not re.fullmatch(r"[!*]?[^\s!*]+(?:\.[^\s]+)*", rule):
            raise ValidationError("psl_syntax")
    return raw, rules


def parse_iana_tlds(path: str) -> tuple[bytes, list[str]]:
    tlds = []
    for i, line in enumerate(_lines(path)):
        if not line or line.startswith("#"):
            continue
        if not re.fullmatch(r"[A-Z0-9-]{2,63}", line):
            raise ValidationError("tld_syntax")
        tlds.append(line.lower())
    return ("\n".join(tlds) + "\n").encode("ascii"), tlds


def parse_rdap_bootstrap(path: str) -> tuple[bytes, list[str]]:
    with open(path, "rb") as handle:
        try:
            doc = json.load(handle)
        except ValueError:
            raise ValidationError("json") from None
    services = doc.get("services") if isinstance(doc, dict) else None
    if not isinstance(services, list):
        raise ValidationError("rdap_structure")
    tlds = []
    for service in services:
        if not (isinstance(service, list) and len(service) == 2 and all(isinstance(x, list) for x in service)):
            raise ValidationError("rdap_structure")
        names, urls = service
        if not urls or not all(isinstance(u, str) and re.match(r"^https?://[^\s/]+/", u) for u in urls):
            raise ValidationError("rdap_url")
        for name in names:
            if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9-]{2,63}", name):
                raise ValidationError("rdap_tld")
            tlds.append(name)
    canonical = json.dumps({"description": doc.get("description", ""), "publication": doc.get("publication", ""),
                            "version": doc.get("version", ""), "services": services}, sort_keys=True)
    return canonical.encode("utf-8"), tlds


def parse_domains(path: str) -> tuple[bytes, list[str]]:
    seen, invalid, total = set(), 0, 0
    for line in _lines(path):
        value = line.split("#", 1)[0].strip()
        if not value:
            continue
        total += 1
        domain = normalize_domain(value)
        if domain is None:
            invalid += 1
            continue
        seen.add(domain)
    if total and invalid / total > MAX_INVALID_RATIO:
        raise ValidationError("domain_syntax")
    entries = sorted(seen)
    return ("\n".join(entries) + "\n").encode("ascii"), entries


def parse_majestic(path: str) -> tuple[bytes, list[str]]:
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as handle:
        reader = csv.reader(handle)
        try:
            header = next(reader)
        except StopIteration:
            raise ValidationError("empty") from None
        if "Domain" not in header:
            raise ValidationError("majestic_header")
        col = header.index("Domain")
        entries, seen, invalid, total = [], set(), 0, 0
        for row in reader:
            if len(row) <= col:
                invalid += 1
                continue
            total += 1
            domain = normalize_domain(row[col])
            if domain is None:
                invalid += 1
                continue
            if domain not in seen:
                seen.add(domain)
                entries.append(domain)
    if total and invalid / total > MAX_INVALID_RATIO:
        raise ValidationError("domain_syntax")
    return ("\n".join(entries) + "\n").encode("ascii"), entries


PARSERS = {"psl": parse_psl, "iana-tlds": parse_iana_tlds, "rdap-bootstrap": parse_rdap_bootstrap,
           "domains": parse_domains, "majestic": parse_majestic}


# Validation ----------------------------------------------------------------------------------------------

def _key(entry: str) -> int:
    return int.from_bytes(hashlib.blake2b(entry.encode(), digest_size=8).digest(), "big")


def sorted_keys(entries) -> array:
    """Sorted, de-duplicated 64-bit keys (8 bytes each instead of a Python set of ints)."""
    if isinstance(entries, array):
        return entries
    return array("Q", sorted({_key(e) for e in entries}))


def _diff_counts(old: array, new: array) -> tuple[int, int]:
    """(entries of `old` missing from `new`, entries of `new` missing from `old`), by merging."""
    i = j = removed = added = 0
    while i < len(old) and j < len(new):
        a, b = old[i], new[j]
        if a == b:
            i += 1
            j += 1
        elif a < b:
            removed += 1
            i += 1
        else:
            added += 1
            j += 1
    return removed + (len(old) - i), added + (len(new) - j)


def check_change_ratio(previous, current) -> None:
    """Rejects a release that removes more than 50 % or adds more than 300 % of the previous entries. Both
    arguments are entry lists or sorted key arrays."""
    if previous is None or not len(previous):
        return
    old, new = sorted_keys(previous), sorted_keys(current)
    removed, added = _diff_counts(old, new)
    if removed / len(old) > MAX_REMOVED_RATIO:
        raise ValidationError("change_ratio_removed")
    if added / len(old) > MAX_ADDED_RATIO:
        raise ValidationError("change_ratio_added")


def _read_never_file(path: str) -> set[str]:
    never = set()
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            value = line.strip()
            if value and not value.startswith("#"):
                never.add(value.lower())
    return never


def load_never_lists(feeds_dir: str, path: str = NEVER_LIST_PATH) -> tuple[set[str], set[str]]:
    """(static never-list: names whose subdomains are protected too, Majestic top 1,000: exact names)."""
    static = _read_never_file(path)
    top: set[str] = set()
    current = read_current(feeds_dir, "majestic")
    if current:
        try:
            with open(os.path.join(feeds_dir, "majestic", current["path"]), "r", encoding="ascii") as handle:
                for i, line in enumerate(handle):
                    if i >= MAJESTIC_TOP_NEVER:
                        break
                    top.add(line.strip())
        except (OSError, UnicodeError):
            pass
    return static, top


def load_never_list(feeds_dir: str, path: str = NEVER_LIST_PATH) -> set[str]:
    """Static never-list plus the Majestic top 1,000 from the currently published Majestic feed."""
    static, top = load_never_lists(feeds_dir, path)
    return static | top


@dataclass(frozen=True)
class Suffixes:
    rules: frozenset
    wildcards: frozenset      # "ck" for the rule "*.ck"
    exceptions: frozenset     # "www.ck" for the rule "!www.ck"

    def is_suffix(self, name: str) -> bool:
        if name in self.rules:
            return True
        parent = name.partition(".")[2]
        return bool(parent) and parent in self.wildcards and name not in self.exceptions


def load_public_suffixes(feeds_dir: str) -> Suffixes:
    current = read_current(feeds_dir, "psl")
    empty = Suffixes(frozenset(), frozenset(), frozenset())
    if not current:
        return empty
    try:
        _, rules = parse_psl(os.path.join(feeds_dir, "psl", current["path"]))
    except (OSError, ValidationError, UnicodeError):
        return empty
    plain, wildcards, exceptions = set(), set(), set()
    for rule in rules:
        if rule.startswith("!"):
            exceptions.add(rule[1:].lower())
        elif rule.startswith("*."):
            wildcards.add(rule[2:].lower())
        else:
            plain.add(rule.lower())
    return Suffixes(frozenset(plain), frozenset(wildcards), frozenset(exceptions))


def never_listed(entry: str, never: set[str], exact: set[str] = frozenset()) -> bool:
    """`entry` equals or lies below a name in `never`, or equals (with or without "www.") a name in `exact`."""
    labels = entry.split(".")
    if any(".".join(labels[i:]) in never for i in range(len(labels) - 1)):
        return True
    base = entry[4:] if entry.startswith("www.") else entry
    return entry in exact or base in exact


def apply_never_list(entries: list[str], never: set[str], suffixes, exact: set[str] = frozenset()
                     ) -> tuple[list[str], int]:
    """Removes never-list names, their subdomains (`never`), exact names (`exact`) and public suffixes.
    `suffixes` is a Suffixes object or a plain set of suffix names. A release with more than max(10, 1 %) hits
    is rejected as poisoned."""
    is_suffix = suffixes.is_suffix if isinstance(suffixes, Suffixes) else suffixes.__contains__
    kept, removed = [], 0
    for entry in entries:
        if never_listed(entry, never, exact) or is_suffix(entry):
            removed += 1
            continue
        kept.append(entry)
    if removed > max(10, len(entries) // 100):
        raise ValidationError("never_list_flood")
    return kept, removed


def validate(feed: Feed, raw_size: int, entries: list[str]) -> None:
    if not feed.min_bytes <= raw_size <= feed.max_bytes:
        raise ValidationError("size_bounds")
    if not feed.min_entries <= len(entries) <= feed.max_entries:
        raise ValidationError("entry_bounds")


# Publication ----------------------------------------------------------------------------------------------

def read_current(feeds_dir: str, feed_id: str) -> dict | None:
    try:
        with open(os.path.join(feeds_dir, feed_id, "current.json"), "r", encoding="utf-8") as handle:
            doc = json.load(handle)
        if not isinstance(doc, dict) or not isinstance(doc.get("path"), str) or ".." in doc["path"]:
            return None
        return doc
    except (OSError, ValueError):
        return None


def _version_keys(feeds_dir: str, feed: Feed, rel_path: str) -> array | None:
    """Sorted keys of a published version, streamed from its file (no list of a million strings)."""
    path = os.path.join(feeds_dir, feed.id, rel_path)
    try:
        if feed.format == "psl":
            return sorted_keys(parse_psl(path)[1])
        if feed.format == "rdap-bootstrap":
            return sorted_keys(parse_rdap_bootstrap(path)[1])
        keys = set()
        with open(path, "r", encoding="ascii", errors="replace") as handle:
            for line in handle:
                value = line.strip()
                if value:
                    keys.add(_key(value))
        return array("Q", sorted(keys))
    except (OSError, ValidationError, UnicodeError):
        return None


def previous_keys(feeds_dir: str, feed: Feed) -> array | None:
    current = read_current(feeds_dir, feed.id)
    return _version_keys(feeds_dir, feed, current["path"]) if current else None


def previous_entries(feeds_dir: str, feed: Feed) -> list[str] | None:
    current = read_current(feeds_dir, feed.id)
    if not current:
        return None
    path = os.path.join(feeds_dir, feed.id, current["path"])
    try:
        if feed.format == "psl":
            return parse_psl(path)[1]
        if feed.format == "rdap-bootstrap":
            return parse_rdap_bootstrap(path)[1]
        with open(path, "r", encoding="ascii", errors="replace") as handle:
            return [line.strip() for line in handle if line.strip()]
    except (OSError, ValidationError, UnicodeError):
        return None


def read_reference(feeds_dir: str, feed_id: str) -> dict | None:
    try:
        with open(os.path.join(feeds_dir, feed_id, REFERENCE_FILE), "r", encoding="utf-8") as handle:
            doc = json.load(handle)
        if not isinstance(doc, dict) or not isinstance(doc.get("path"), str) or ".." in doc["path"] \
                or not isinstance(doc.get("version"), str) or not isinstance(doc.get("published_at"), int):
            return None
        if not os.path.isfile(os.path.join(feeds_dir, feed_id, doc["path"])):
            return None
        return doc
    except (OSError, ValueError):
        return None


def update_reference(feeds_dir: str, feed: Feed, current: dict, now: int) -> None:
    """The reference moves to the version just published when it is missing or at least 24 h old."""
    reference = read_reference(feeds_dir, feed.id)
    if reference is None or now - reference["published_at"] >= REFERENCE_AGE_S:
        _write_json_atomic(os.path.join(feeds_dir, feed.id, REFERENCE_FILE),
                           {"version": current["version"], "path": current["path"], "published_at": now})


def _fsync_dir(path: str) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _write_json_atomic(path: str, doc: dict) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(doc, handle, sort_keys=True)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)
    _fsync_dir(os.path.dirname(path))


def publish(feeds_dir: str, feed: Feed, data: bytes, entries: int, now: int | None = None) -> dict:
    now = int(time.time()) if now is None else now
    digest = hashlib.sha256(data).hexdigest()
    version = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(now)) + "-" + digest[:8]
    feed_dir = os.path.join(feeds_dir, feed.id)
    os.makedirs(feed_dir, mode=0o755, exist_ok=True)
    os.chmod(feed_dir, 0o755)
    final_dir = os.path.join(feed_dir, version)
    if not os.path.isdir(final_dir):
        tmp_dir = os.path.join(feed_dir, f".tmp-{version}")
        shutil.rmtree(tmp_dir, ignore_errors=True)
        os.makedirs(tmp_dir, mode=0o755)
        os.chmod(tmp_dir, 0o755)
        file_path = os.path.join(tmp_dir, feed.file)
        with open(file_path, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(file_path, 0o644)
        os.rename(tmp_dir, final_dir)
        _fsync_dir(feed_dir)
    current = {"version": version, "fetched_at": now, "entries": entries, "sha256": digest, "licence": feed.licence,
               "commercial": feed.commercial, "attribution": feed.attribution, "refresh_s": feed.refresh_s,
               "path": f"{version}/{feed.file}"}
    _write_json_atomic(os.path.join(feed_dir, "current.json"), current)
    reference = read_reference(feeds_dir, feed.id)
    prune(feed_dir, version, keep=(reference["version"],) if reference else ())
    return current


def touch_current(feeds_dir: str, feed: Feed, now: int | None = None) -> dict | None:
    """Records a successful check without new content (HTTP 304 or identical data)."""
    current = read_current(feeds_dir, feed.id)
    if not current:
        return None
    current["fetched_at"] = int(time.time()) if now is None else now
    _write_json_atomic(os.path.join(feeds_dir, feed.id, "current.json"), current)
    return current


def prune(feed_dir: str, keep_version: str, keep: tuple = ()) -> None:
    versions = sorted(d for d in os.listdir(feed_dir)
                      if os.path.isdir(os.path.join(feed_dir, d)) and not d.startswith("."))
    for old in versions[:-KEEP_VERSIONS]:
        if old != keep_version and old not in keep:   # the 24 h reference version stays (PY-18)
            shutil.rmtree(os.path.join(feed_dir, old), ignore_errors=True)
    for name in os.listdir(feed_dir):
        if name.startswith(".tmp-") and not name.endswith(keep_version):
            shutil.rmtree(os.path.join(feed_dir, name), ignore_errors=True)


def process_download(feeds_dir: str, feed: Feed, raw_path: str, now: int | None = None) -> tuple[str, dict | None]:
    """Parses, validates and publishes a downloaded file. Returns (status, current.json document)."""
    now = int(time.time()) if now is None else now
    raw_size = os.path.getsize(raw_path)
    data, entries = PARSERS[feed.format](raw_path)
    removed = 0
    if feed.never_list_guard:
        static, top = load_never_lists(feeds_dir)
        entries, removed = apply_never_list(entries, static, load_public_suffixes(feeds_dir), top)
        data = ("\n".join(entries) + "\n").encode("ascii")
    validate(feed, raw_size, entries)
    count = len(entries)
    keys = sorted_keys(entries)
    del entries                                   # the strings are no longer needed (PY-14)
    check_change_ratio(previous_keys(feeds_dir, feed), keys)
    current = read_current(feeds_dir, feed.id)
    reference = read_reference(feeds_dir, feed.id)
    if reference is not None and (current is None or reference["version"] != current["version"]):
        try:
            check_change_ratio(_version_keys(feeds_dir, feed, reference["path"]), keys)
        except ValidationError as exc:
            raise ValidationError(f"{exc}_vs_reference") from None
    if current and current.get("sha256") == hashlib.sha256(data).hexdigest():
        return "unchanged", touch_current(feeds_dir, feed, now)
    published = publish(feeds_dir, feed, data, count, now)
    update_reference(feeds_dir, feed, published, now)
    return ("published" if not removed else "published_filtered"), published
