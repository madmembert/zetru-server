"""Attachment inspection without rendering, execution or extraction to disk (concept §6.5).

- magic-byte detection and type/extension mismatch
- ZIP central-directory listing (limits: 1,000 entries, 2 nesting levels, 200 MB declared size); nested
  archives are decompressed in memory only when small, bounded by their declared size
- TAR and GZIP(+TAR) listing, other archive formats are opaque
- OOXML macro detection (vbaProject.bin), OLE2 directory (macro storages, encryption, MSI)
- PDF token scan (/JavaScript, /JS, /Launch, /EmbeddedFile, /OpenAction, /Encrypt) incl. Flate streams
- HTML/SVG active content (script, forms, event handlers, external URLs, encoded blobs > 10 KB)
"""

from __future__ import annotations

import re
import struct
import unicodedata
import zlib
from dataclasses import dataclass, field

from . import pdfcrypt
from .packs import Packs

MAX_ZIP_ENTRIES = 1000
MAX_NESTING = 2
MAX_DECLARED = 200 * 1024 * 1024
MAX_NESTED_INFLATE = 20 * 1024 * 1024
MAX_TAR_STREAM = 64 * 1024 * 1024
MAX_PDF_STREAMS = 300
MAX_PDF_INFLATE = 16 * 1024 * 1024
MAX_SCAN_BYTES = 8 * 1024 * 1024
BLOB_MIN_BASE64 = 13654   # characters of base64 that decode to more than 10 KB
BLOB_MIN_HEX = 20480
_BASE64_RUN = re.compile(rb"[A-Za-z0-9+/]+")   # each run is matched once: linear time on hostile input
_HEX_RUN = re.compile(rb"[0-9a-fA-F]+")
_BIDI_ZW = re.compile("[​-‏‪-‮⁠-⁩﻿؜]")
OLE2_MAGIC = bytes.fromhex("D0CF11E0A1B11AE1")
MSI_CLSID = bytes.fromhex("84100C0000000000C000000000000046")
ONENOTE_GUID = bytes.fromhex("E4525C7B8CD8A74DAEB15378D02996D3")
LNK_MAGIC = bytes.fromhex("4C0000000114020000000000C000000000000046")

EXEC_TYPES = frozenset({"pe", "elf", "macho", "lnk", "msi", "iso", "vhd", "onenote"})
ARCHIVE_TYPES = frozenset({"zip", "rar", "7z", "gzip", "bzip2", "xz", "cab", "tar"})
IMAGE_TYPES = frozenset({"png", "jpeg", "gif", "webp", "tiff", "heic", "bmp"})

# Extension → content types it may legitimately have.
_ALLOWED = {
    "pdf": {"pdf"},
    **{e: {"ole2", "rtf", "html"} for e in ("doc", "dot", "xls", "xlt")},
    **{e: {"ole2"} for e in ("ppt", "pps", "pot", "msg")},
    **{e: {"ooxml", "ole2"} for e in ("docx", "docm", "dotx", "dotm", "xlsx", "xlsm", "xltx", "xltm", "xlsb",
                                      "pptx", "pptm", "potx", "potm", "ppsx", "ppsm", "sldx", "sldm")},
    **{e: {"zip", "ooxml"} for e in ("odt", "ods", "odp", "odg", "epub", "zip", "zipx", "jar", "apk", "ipa", "xpi",
                                     "kmz", "aar", "vsix", "nupkg", "whl")},
    "rtf": {"rtf"}, "rar": {"rar"}, "7z": {"7z"}, "gz": {"gzip"}, "tgz": {"gzip"}, "bz2": {"bzip2"},
    "tbz": {"bzip2"}, "xz": {"xz"}, "txz": {"xz"}, "cab": {"cab"}, "tar": {"tar"},
    **{e: IMAGE_TYPES for e in ("jpg", "jpeg", "png", "gif", "bmp", "webp", "tif", "tiff", "heic", "heif")},
    **{e: {"html", "text", "xml"} for e in ("html", "htm", "shtml", "xhtml", "xht", "mht", "mhtml")},
    **{e: {"svg", "xml", "html", "text"} for e in ("svg",)},
    **{e: {"text", "html", "xml", "rtf"} for e in ("txt", "csv", "ics", "vcf", "eml", "json", "xml", "log", "md")},
}
_DECLARED_STRICT = {
    "application/pdf": "pdf", "image/jpeg": "image", "image/png": "image", "image/gif": "image",
    "application/msword": "office", "application/vnd.ms-excel": "office",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "office",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "office",
    "text/plain": "text", "text/calendar": "text",
}


@dataclass
class AttachmentReport:
    path: str
    real_type: str
    label: str                                   # class shown in the canonical state
    signals: dict[str, dict] = field(default_factory=dict)  # signal id → evidence (without part)
    nested_types: list[str] = field(default_factory=list)


# Magic ---------------------------------------------------------------------------------------------------

def _is_pe(data: bytes) -> bool:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return False
    offset = struct.unpack_from("<I", data, 0x3C)[0]
    return 0 < offset < min(len(data) - 4, 1 << 20) and data[offset:offset + 4] == b"PE\x00\x00"


def sniff(data: bytes) -> str:
    head = data[:4096]
    if _is_pe(data):
        return "pe"
    if head.startswith(b"\x7fELF"):
        return "elf"
    if head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
                    b"\xca\xfe\xba\xbe"):
        return "macho"
    if head.startswith(LNK_MAGIC):
        return "lnk"
    if head.startswith(ONENOTE_GUID):
        return "onenote"
    if head.startswith(OLE2_MAGIC):
        return "ole2"
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "zip"
    if b"%PDF-" in head[:1024]:
        return "pdf"
    if head.startswith(b"Rar!\x1a\x07"):
        return "rar"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if head.startswith(b"\x1f\x8b"):
        return "gzip"
    if head.startswith(b"BZh") and len(head) > 3 and head[3:4].isdigit():
        return "bzip2"
    if head.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if head.startswith(b"MSCF"):
        return "cab"
    if head.startswith(b"vhdxfile") or data[-512:-504] == b"conectix":
        return "vhd"
    for off in (0x8001, 0x8801, 0x9001):
        if data[off:off + 5] == b"CD001":
            return "iso"
    if len(data) > 262 and data[257:262] == b"ustar":
        return "tar"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if head.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if head.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "webp"
    if head[:4] in (b"II*\x00", b"MM\x00*"):
        return "tiff"
    if head[4:12] in (b"ftypheic", b"ftypheix", b"ftypmif1", b"ftyphevc"):
        return "heic"
    if head.startswith(b"{\\rtf"):
        return "rtf"
    text = head.lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    if text.startswith((b"<!doctype html", b"<html", b"<head", b"<body", b"<script", b"<iframe", b"<meta")) \
            or b"<html" in text[:1024] or b"<script" in text[:1024]:
        return "html"
    if b"<svg" in text[:4096]:
        return "svg"
    if text.startswith(b"<?xml"):
        return "xml"
    if head and _mostly_text(head):
        return "text"
    return "unknown"


def _mostly_text(head: bytes) -> bool:
    if b"\x00" in head:
        return False
    printable = sum(1 for b in head if b >= 0x20 or b in (9, 10, 13))
    return printable / max(1, len(head)) > 0.95


def extension(name: str | None) -> str:
    if not name:
        return ""
    base = name.strip().rstrip(". ").rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    if "." not in base:
        return ""
    return base.rsplit(".", 1)[1].strip().lower()[:16]


def double_extension(name: str | None, packs: Packs) -> bool:
    if not name:
        return False
    base = name.strip().rstrip(". ").rsplit("/", 1)[-1]
    segments = [s.strip(" _ ").lower() for s in base.split(".")]
    if len(segments) < 3:
        return False
    last, previous = segments[-1], segments[-2]
    return (last in packs.ext_executable or last in packs.ext_html) and previous in packs.ext_document


def has_bidi(name: str | None) -> bool:
    return bool(name) and bool(_BIDI_ZW.search(name))


# ZIP -----------------------------------------------------------------------------------------------------

@dataclass
class ZipEntry:
    name: str
    flags: int
    method: int
    comp_size: int
    size: int
    offset: int


class ArchiveError(Exception):
    pass


def zip_entries(data: bytes) -> list[ZipEntry]:
    """Central-directory listing. Raises ArchiveError when the listing is impossible or exceeds limits."""
    search_from = max(0, len(data) - 65557)
    eocd = data.rfind(b"PK\x05\x06", search_from)
    if eocd < 0 or eocd + 22 > len(data):
        raise ArchiveError("no_eocd")
    (_sig, _disk, _cd_disk, _n_disk, n_total, cd_size, cd_offset, _clen) = struct.unpack_from("<IHHHHIIH", data, eocd)
    if n_total == 0xFFFF or cd_size == 0xFFFFFFFF or cd_offset == 0xFFFFFFFF:
        loc = eocd - 20
        if loc < 0 or data[loc:loc + 4] != b"PK\x06\x07":
            raise ArchiveError("zip64_locator")
        z64 = struct.unpack_from("<Q", data, loc + 8)[0]
        if z64 + 56 > len(data) or data[z64:z64 + 4] != b"PK\x06\x06":
            raise ArchiveError("zip64_eocd")
        n_total, cd_size, cd_offset = struct.unpack_from("<QQQ", data, z64 + 32)
        cd_end_anchor = z64
    else:
        cd_end_anchor = eocd
    if n_total > MAX_ZIP_ENTRIES:
        raise ArchiveError("limits")
    base = cd_end_anchor - cd_size - cd_offset  # bytes prepended (self-extracting stubs)
    if base < 0:
        base = 0
    pos = cd_offset + base
    entries: list[ZipEntry] = []
    total = 0
    for _ in range(n_total):
        if pos + 46 > len(data) or data[pos:pos + 4] != b"PK\x01\x02":
            raise ArchiveError("central_directory")
        (flags, method) = struct.unpack_from("<HH", data, pos + 8)
        comp, size = struct.unpack_from("<II", data, pos + 20)
        nlen, elen, clen = struct.unpack_from("<HHH", data, pos + 28)
        offset = struct.unpack_from("<I", data, pos + 42)[0]
        raw_name = data[pos + 46:pos + 46 + nlen]
        extra = data[pos + 46 + nlen:pos + 46 + nlen + elen]
        if size == 0xFFFFFFFF or comp == 0xFFFFFFFF or offset == 0xFFFFFFFF:
            size, comp, offset = _zip64_extra(extra, size, comp, offset)
        name = raw_name.decode("utf-8" if flags & 0x800 else "cp437", errors="replace")
        entries.append(ZipEntry(name, flags, method, comp, size, offset + base))
        total += size
        if total > MAX_DECLARED:
            raise ArchiveError("limits")
        pos += 46 + nlen + elen + clen
    return entries


def _zip64_extra(extra: bytes, size: int, comp: int, offset: int) -> tuple[int, int, int]:
    i = 0
    while i + 4 <= len(extra):
        tag, length = struct.unpack_from("<HH", extra, i)
        body = extra[i + 4:i + 4 + length]
        if tag == 0x0001:
            j = 0
            if size == 0xFFFFFFFF and j + 8 <= len(body):
                size = struct.unpack_from("<Q", body, j)[0]
                j += 8
            if comp == 0xFFFFFFFF and j + 8 <= len(body):
                comp = struct.unpack_from("<Q", body, j)[0]
                j += 8
            if offset == 0xFFFFFFFF and j + 8 <= len(body):
                offset = struct.unpack_from("<Q", body, j)[0]
            break
        i += 4 + length
    return size, comp, offset


def zip_member(data: bytes, entry: ZipEntry) -> bytes:
    """In-memory decompression of one small member (stored or deflated), bounded by its declared size."""
    if entry.flags & 0x1:
        raise ArchiveError("encrypted")
    if entry.size > MAX_NESTED_INFLATE or entry.comp_size > MAX_NESTED_INFLATE:
        raise ArchiveError("limits")
    pos = entry.offset
    if pos + 30 > len(data) or data[pos:pos + 4] != b"PK\x03\x04":
        raise ArchiveError("local_header")
    nlen, elen = struct.unpack_from("<HH", data, pos + 26)
    start = pos + 30 + nlen + elen
    raw = data[start:start + entry.comp_size]
    if entry.method == 0:
        return raw[: entry.size]
    if entry.method == 8:
        inflater = zlib.decompressobj(-15)
        try:
            out = inflater.decompress(raw, entry.size + 1)
        except zlib.error:
            raise ArchiveError("inflate") from None
        if len(out) > entry.size:
            raise ArchiveError("limits")
        return out
    raise ArchiveError("method")


# TAR / GZIP ------------------------------------------------------------------------------------------------

def _tar_names_from_stream(chunks) -> list[str]:
    names: list[str] = []
    buf = b""
    skip = 0
    pending_long: bytes | None = None
    reading_long = 0
    long_buf = b""
    total = 0
    for chunk in chunks:
        buf += chunk
        while True:
            if skip:
                take = min(skip, len(buf))
                buf = buf[take:]
                skip -= take
                if skip:
                    break
            if reading_long:
                if len(buf) < reading_long:
                    break
                long_buf = buf[:reading_long]
                pending_long = long_buf.split(b"\x00", 1)[0]
                padded = (reading_long + 511) // 512 * 512
                buf = buf[reading_long:]
                skip = padded - reading_long
                reading_long = 0
                continue
            if len(buf) < 512:
                break
            header, buf = buf[:512], buf[512:]
            if header == b"\x00" * 512:
                return names
            try:
                size = int(header[124:136].split(b"\x00", 1)[0].strip() or b"0", 8)
            except ValueError:
                raise ArchiveError("tar_header") from None
            typeflag = header[156:157]
            if typeflag in (b"L",):
                reading_long = size
                continue
            name = header[:100].split(b"\x00", 1)[0]
            prefix = header[345:500].split(b"\x00", 1)[0] if header[257:262] == b"ustar" else b""
            if prefix:
                name = prefix + b"/" + name
            if pending_long is not None:
                name, pending_long = pending_long, None
            if typeflag not in (b"x", b"g"):
                names.append(name.decode("utf-8", errors="replace"))
            total += size
            if len(names) > MAX_ZIP_ENTRIES or total > MAX_DECLARED:
                raise ArchiveError("limits")
            skip = (size + 511) // 512 * 512
    return names


def tar_names(data: bytes) -> list[str]:
    return _tar_names_from_stream([data])


def gzip_inner(data: bytes) -> tuple[str | None, bool]:
    """(original file name from the header, whether it contains a TAR stream)."""
    if len(data) < 10 or data[:2] != b"\x1f\x8b":
        raise ArchiveError("gzip")
    flags = data[3]
    pos = 10
    if flags & 0x04:
        xlen = struct.unpack_from("<H", data, pos)[0]
        pos += 2 + xlen
    name = None
    if flags & 0x08:
        end = data.find(b"\x00", pos)
        if end < 0:
            raise ArchiveError("gzip")
        name = data[pos:end].decode("latin-1")[:256]
    inflater = zlib.decompressobj(16 + 15)
    try:
        head = inflater.decompress(data, 1024)
    except zlib.error:
        raise ArchiveError("inflate") from None
    return name, len(head) > 262 and head[257:262] == b"ustar"


def gzip_tar_names(data: bytes) -> list[str]:
    inflater = zlib.decompressobj(16 + 15)
    produced = 0

    def chunks():
        nonlocal produced
        pending = data
        while True:
            try:
                out = inflater.decompress(pending, 1 << 20)
            except zlib.error:
                raise ArchiveError("inflate") from None
            pending = inflater.unconsumed_tail
            produced += len(out)
            if produced > MAX_TAR_STREAM:
                raise ArchiveError("limits")
            if out:
                yield out
            if not out and not pending:
                return

    return _tar_names_from_stream(chunks())


# OLE2 -------------------------------------------------------------------------------------------------

@dataclass
class OleInfo:
    names: list[str]
    root_clsid: bytes
    encrypted: bool
    macros: bool


def ole2_info(data: bytes) -> OleInfo:
    if len(data) < 512 or not data.startswith(OLE2_MAGIC):
        raise ArchiveError("ole2")
    shift = struct.unpack_from("<H", data, 0x1E)[0]
    mini_shift = struct.unpack_from("<H", data, 0x20)[0]
    if shift not in (9, 12) or mini_shift != 6:
        raise ArchiveError("ole2")
    sector = 1 << shift
    n_fat = struct.unpack_from("<I", data, 0x2C)[0]
    first_dir = struct.unpack_from("<I", data, 0x30)[0]
    mini_cutoff = struct.unpack_from("<I", data, 0x38)[0]
    first_minifat = struct.unpack_from("<I", data, 0x3C)[0]
    first_difat = struct.unpack_from("<I", data, 0x44)[0]
    max_sectors = len(data) // sector + 1

    def sector_data(n: int) -> bytes:
        start = (n + 1) * sector
        if n >= 0xFFFFFFFA or start + sector > len(data) + sector:
            raise ArchiveError("ole2_sector")
        return data[start:start + sector]

    difat = list(struct.unpack_from("<109I", data, 0x4C))
    nxt = first_difat
    seen = 0
    while nxt < 0xFFFFFFFA and seen < max_sectors:
        block = sector_data(nxt)
        values = struct.unpack_from(f"<{sector // 4}I", block)
        difat.extend(values[:-1])
        nxt = values[-1]
        seen += 1
    fat: list[int] = []
    for s in difat[: min(n_fat, max_sectors)]:
        if s >= 0xFFFFFFFA:
            continue
        fat.extend(struct.unpack_from(f"<{sector // 4}I", sector_data(s)))

    def chain(start: int, table: list[int], limit: int) -> list[int]:
        out = []
        cur = start
        while cur < 0xFFFFFFFA:
            if cur >= len(table) or len(out) > limit:
                raise ArchiveError("ole2_chain")
            out.append(cur)
            cur = table[cur]
        return out

    dir_bytes = b"".join(sector_data(s) for s in chain(first_dir, fat, max_sectors))
    entries = []
    for i in range(0, min(len(dir_bytes), 128 * 4096), 128):
        raw = dir_bytes[i:i + 128]
        if len(raw) < 128:
            break
        name_len = struct.unpack_from("<H", raw, 0x40)[0]
        etype = raw[0x42]
        if etype == 0 or name_len < 2 or name_len > 64:
            continue
        name = raw[: name_len - 2].decode("utf-16-le", errors="replace")
        start = struct.unpack_from("<I", raw, 0x74)[0]
        size = struct.unpack_from("<Q", raw, 0x78)[0]
        entries.append((name, etype, raw[0x50:0x60], start, size))
    if not entries:
        raise ArchiveError("ole2_dir")
    root = next((e for e in entries if e[1] == 5), entries[0])
    names = [e[0] for e in entries]
    lower = {n.lower() for n in names}

    minifat: list[int] = []
    if first_minifat < 0xFFFFFFFA:
        for s in chain(first_minifat, fat, max_sectors):
            minifat.extend(struct.unpack_from(f"<{sector // 4}I", sector_data(s)))

    def read_stream(entry, max_bytes: int) -> bytes:
        _, _, _, start, real_size = entry
        size = min(real_size, max_bytes)
        if real_size < mini_cutoff:  # placement depends on the stream's real size, not on how much we read
            mini_stream = b"".join(sector_data(s) for s in chain(root[3], fat, max_sectors))
            out = b"".join(mini_stream[m * 64:(m + 1) * 64] for m in chain(start, minifat, len(minifat)))
        else:
            out = b"".join(sector_data(s) for s in chain(start, fat, max_sectors)[: size // sector + 1])
        return out[:size]

    encrypted = "encryptioninfo" in lower and "encryptedpackage" in lower
    encrypted = encrypted or "encryptedsummary" in lower
    for entry in entries:
        lname = entry[0].lower()
        try:
            if lname == "worddocument" and entry[1] == 2:
                fib = read_stream(entry, 64)
                if len(fib) >= 12 and struct.unpack_from("<H", fib, 0)[0] == 0xA5EC:
                    encrypted = encrypted or bool(struct.unpack_from("<H", fib, 0x0A)[0] & 0x0100)
            elif lname in ("workbook", "book") and entry[1] == 2:
                encrypted = encrypted or _biff_filepass(read_stream(entry, 65536))
        except (ArchiveError, struct.error):
            continue
    macros = bool(lower & {"_vba_project_cur", "_vba_project", "macros", "vba"})
    return OleInfo(names=names, root_clsid=root[2], encrypted=encrypted, macros=macros)


def _biff_filepass(stream: bytes) -> bool:
    pos = 0
    for _ in range(32):
        if pos + 4 > len(stream):
            return False
        rtype, length = struct.unpack_from("<HH", stream, pos)
        if rtype == 0x002F:
            return True
        if rtype == 0x0085:  # BOUNDSHEET: FILEPASS would have come before
            return False
        pos += 4 + length
    return False


# PDF ------------------------------------------------------------------------------------------------------

_PDF_NAME = re.compile(rb"/([^\s/\[\]()<>{}%]{1,127})")
_PDF_STREAM = re.compile(rb"(?<!end)stream\r?\n")


def _pdf_names(data: bytes) -> set[str]:
    names = set()
    for m in _PDF_NAME.finditer(data):
        raw = m.group(1)
        if b"#" in raw:
            raw = re.sub(rb"#([0-9A-Fa-f]{2})", lambda x: bytes([int(x.group(1), 16)]), raw)
        names.add(raw.decode("latin-1"))
    return names


def pdf_scan(data: bytes) -> dict:
    data = data[:MAX_SCAN_BYTES * 4]
    names = _pdf_names(data)
    inflated = 0
    for count, m in enumerate(_PDF_STREAM.finditer(data)):
        if count >= MAX_PDF_STREAMS or inflated >= MAX_PDF_INFLATE:
            break
        dict_start = data.rfind(b"<<", max(0, m.start() - 4096), m.start())
        if dict_start < 0 or b"Flate" not in data[dict_start:m.start()]:
            continue
        start = m.end()
        end = data.find(b"endstream", start)
        if end < 0:
            break
        try:
            out = zlib.decompressobj().decompress(data[start:end], MAX_PDF_INFLATE - inflated)
        except zlib.error:
            continue
        inflated += len(out)
        names |= _pdf_names(out)
    active = bool(names & {"JavaScript", "JS", "Launch", "EmbeddedFile", "EmbeddedFiles", "RichMedia"})
    encrypt = "Encrypt" in names
    return {"active": active, "encrypt": encrypt, "open_action": "OpenAction" in names}


# HTML / SVG ------------------------------------------------------------------------------------------------

_ACTIVE_PATTERNS = [
    re.compile(rb"<\s*(?:[a-z]+:)?script\b", re.I),
    re.compile(rb"<\s*form\b", re.I),
    re.compile(rb"<\s*(?:iframe|object|embed|foreignobject|frame)\b", re.I),
    re.compile(rb"[\s\"'/]on[a-z]{3,30}\s*=", re.I),
    re.compile(rb"javascript\s*:", re.I),
    re.compile(rb"\b(?:href|src|action|formaction|data|poster|background)\s*=\s*[\"']?\s*(?:https?:)?//", re.I),
    re.compile(rb"url\(\s*[\"']?\s*(?:https?:)?//", re.I),
    re.compile(rb"http-equiv\s*=\s*[\"']?refresh", re.I),
    re.compile(rb"<\s*input\b[^>]*type\s*=\s*[\"']?password", re.I),
]


def html_active(data: bytes) -> bool:
    sample = data[:MAX_SCAN_BYTES]
    if any(p.search(sample) for p in _ACTIVE_PATTERNS):
        return True
    return has_blob(sample)


def has_blob(data: bytes) -> bool:
    if any(m.end() - m.start() >= BLOB_MIN_BASE64 for m in _BASE64_RUN.finditer(data)):
        return True
    return any(m.end() - m.start() >= BLOB_MIN_HEX for m in _HEX_RUN.finditer(data))


# Driver -----------------------------------------------------------------------------------------------------

def _archive_type_from_name(name: str) -> str | None:
    ext = extension(name)
    return {"zip": "zip", "jar": "zip", "zipx": "zip", "rar": "rar", "7z": "7z", "gz": "gzip", "tgz": "gzip",
            "tar": "tar", "cab": "cab", "bz2": "bzip2", "xz": "xz", "iso": "iso", "img": "iso"}.get(ext)


class _ArchiveScan:
    def __init__(self, packs: Packs):
        self.packs = packs
        self.risky = 0
        self.opaque = False
        self.encrypted = False
        self.names: list[str] = []

    def check_name(self, name: str) -> None:
        self.names.append(name)
        ext = extension(name)
        if ext in self.packs.ext_executable or has_bidi(name) or double_extension(name, self.packs):
            self.risky += 1

    def scan(self, data: bytes, kind: str, level: int, own_name: str | None = None) -> None:
        if level > MAX_NESTING:
            self.opaque = True
            return
        try:
            if kind == "zip":
                for entry in zip_entries(data):
                    if entry.name.endswith("/"):
                        continue
                    self.check_name(entry.name)
                    if entry.flags & 0x1:
                        self.encrypted = True
                        continue
                    inner = _archive_type_from_name(entry.name)
                    if inner:
                        if inner in ("zip", "gzip", "tar") and level < MAX_NESTING:
                            try:
                                self.scan(zip_member(data, entry), inner, level + 1, entry.name)
                            except ArchiveError as exc:
                                if str(exc) == "encrypted":
                                    self.encrypted = True
                                else:
                                    self.opaque = True
                        else:
                            self.opaque = True
            elif kind == "tar":
                for name in tar_names(data):
                    self.check_name(name)
            elif kind == "gzip":
                inner_name, is_tar = gzip_inner(data)
                if is_tar:
                    for name in gzip_tar_names(data):
                        self.check_name(name)
                else:
                    stem = inner_name or (own_name[:-3] if own_name and own_name.lower().endswith(".gz") else None)
                    if stem:
                        self.check_name(stem)
                    else:
                        self.opaque = True
            else:
                self.opaque = True
        except (ArchiveError, struct.error, IndexError, ValueError):
            self.opaque = True


def inspect(path: str, filename: str | None, declared_type: str, data: bytes, packs: Packs) -> AttachmentReport:
    real = sniff(data)
    ext = extension(filename)
    label = real
    report = AttachmentReport(path=path, real_type=real, label=label)
    sig = report.signals

    if real in EXEC_TYPES:
        sig["ATT_EXECUTABLE"] = {}
        label = "executable"
    if real == "zip":
        try:
            names = [e.name for e in zip_entries(data)]
            lower = [n.lower() for n in names]
            if "[content_types].xml" in lower:
                real = report.real_type = "ooxml"
                label = "office"
                if any(n.endswith("vbaproject.bin") or n.startswith("xl/macrosheets/") for n in lower):
                    sig["ATT_MACRO"] = {}
                    label = "office-macro"
        except (ArchiveError, struct.error):
            pass
    if real == "ole2":
        label = "office"
        try:
            info = ole2_info(data)
            if info.root_clsid == MSI_CLSID:
                real = report.real_type = "msi"
                sig["ATT_EXECUTABLE"] = {}
                label = "executable"
            if info.macros:
                sig["ATT_MACRO"] = {}
                label = "office-macro"
            if info.encrypted:
                sig["ATT_ENCRYPTED"] = {}
                label = "office-encrypted"
        except (ArchiveError, struct.error, IndexError, ValueError):
            pass
    if real in ARCHIVE_TYPES:
        scan = _ArchiveScan(packs)
        scan.scan(data, real, 1, filename)
        label = real
        if scan.risky:
            sig["ATT_ARCHIVE_RISKY"] = {"count": scan.risky}
            label = f"{real}(executable)"
        if scan.encrypted:
            sig["ATT_ENCRYPTED"] = {}
            label = f"{real}(encrypted)"
        if scan.opaque and not scan.risky:
            sig["ATT_ARCHIVE_OPAQUE"] = {}
        report.nested_types = [extension(n) for n in scan.names[:20]]
    if real == "pdf":
        label = "pdf"
        result = pdf_scan(data)
        if result["active"]:
            sig["ATT_PDF_ACTIVE"] = {}
            label = "pdf-active"
        if result["encrypt"]:
            opens = pdfcrypt.opens_without_password(data)
            if opens is False:
                sig["ATT_ENCRYPTED"] = {}
                label = "pdf-encrypted"
    if real in ("html", "svg") or ext in packs.ext_html:
        if real in ("html", "svg", "xml", "text", "unknown"):
            label = "svg" if real == "svg" or ext in ("svg", "svgz") else "html"
            if html_active(data):
                sig["ATT_HTML_SVG_ACTIVE"] = {}
    if real in IMAGE_TYPES:
        label = "image"

    # Type mismatch: confidently detected content that the extension or declared type cannot have.
    mismatch = False
    if ext and ext in _ALLOWED and real not in ("unknown", "text"):
        mismatch = real not in _ALLOWED[ext]
    elif ext and real in EXEC_TYPES and ext not in packs.ext_executable:
        mismatch = True
    declared = _DECLARED_STRICT.get(declared_type)
    if declared and real in EXEC_TYPES | {"html", "svg"} and declared not in ("text",):
        mismatch = True
    if declared == "text" and real in EXEC_TYPES:
        mismatch = True
    if double_extension(filename, packs):
        mismatch = True
    if mismatch:
        sig["ATT_TYPE_MISMATCH"] = {}
    report.label = label
    return report


def filename_is_bidi(name: str | None) -> bool:
    return has_bidi(name) or any(unicodedata.category(c) == "Cf" for c in (name or ""))
