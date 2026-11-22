"""Regenerates the crafted test corpus (.eml + sidecar .json). Run from the server directory with the dev
venv: `.venv/bin/python tests/corpus/generate.py`. Output is deterministic (the newsletter is signed with an
Ed25519 key derived from a fixed seed, which needs the test-only packages dkimpy and PyNaCl).

All attachments are inert stand-ins: the "executable" is only a PE header with no code, archives contain
these stand-ins, the macro project and PDF script are dummy text. Nothing here is real malware.

Sidecar fields: meta (overrides for the request meta), broker (dns: name → {status, txt}, listed: host →
[feed], popular, disposable, ages: domain → age in days), expect (signal IDs that must occur), forbid (IDs
that must not occur), max_severity (highest fallback severity allowed), notes.
"""

from __future__ import annotations

import base64
import io
import json
import os
import struct
import zipfile
from email.message import EmailMessage
from email.utils import format_datetime
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
DATE = format_datetime(datetime(2026, 11, 20, 9, 30, tzinfo=timezone.utc))
FAKE_PE = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x40) + b"PE\x00\x00" + b"\x00" * 200


def write(name: str, msg: EmailMessage | bytes, sidecar: dict) -> None:
    data = msg if isinstance(msg, bytes) else msg.as_bytes(policy=msg.policy.clone(linesep="\r\n"))
    with open(os.path.join(HERE, name + ".eml"), "wb") as handle:
        handle.write(data)
    with open(os.path.join(HERE, name + ".json"), "w", encoding="utf-8") as handle:
        json.dump(sidecar, handle, indent=2, ensure_ascii=False)
        handle.write("\n")


def base(sender: str, to: str, subject: str, mid: str) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = to
    msg["Subject"] = subject
    msg["Date"] = DATE
    msg["Message-ID"] = f"<{mid}>"
    return msg


def zip_bytes(files: dict[str, bytes], encrypt: bool = False) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        for name, data in files.items():
            info = zipfile.ZipInfo(name, date_time=(2026, 11, 20, 9, 30, 0))
            zf.writestr(info, data)
    data = bytearray(buf.getvalue())
    if encrypt:  # set the "encrypted" flag in local and central headers (listing only looks at the flag)
        for sig, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            pos = data.find(sig)
            while pos >= 0:
                flags = struct.unpack_from("<H", data, pos + off)[0] | 1
                struct.pack_into("<H", data, pos + off, flags)
                pos = data.find(sig, pos + 4)
    return bytes(data)


def main() -> None:
    # 1 Brand phishing, German ------------------------------------------------------------------------
    msg = base('"PayPal Kundenservice" <service@paypa1-sicherheit.com>', "anna@example.de",
               "Ihr Konto wurde eingeschränkt", "1@paypa1-sicherheit.com")
    msg["Return-Path"] = "<bounce@paypa1-sicherheit.com>"
    msg.set_content("Sehr geehrter Kunde,\n\naufgrund ungewöhnlicher Aktivitäten wurde Ihr Konto vorübergehend "
                    "eingeschränkt. Bitte bestätigen Sie Ihre Zugangsdaten innerhalb von 24 Stunden, sonst wird Ihr "
                    "Konto dauerhaft gesperrt.\n\nhttps://paypal-konto.example.net/login\n\nIhr PayPal-Team\n")
    msg.add_alternative("""<html><body><p>Sehr geehrter Kunde,</p>
<p>aufgrund ungewöhnlicher Aktivitäten wurde Ihr Konto vorübergehend eingeschränkt. Bitte bestätigen Sie Ihre
Zugangsdaten innerhalb von 24 Stunden, sonst wird Ihr Konto dauerhaft gesperrt.</p>
<p><a href="https://paypal-konto.example.net/login">paypal.com/konto</a></p><p>Ihr PayPal-Team</p></body></html>""",
                        subtype="html")
    write("brand_phishing_de", msg, {
        "notes": "Look-alike sender (digit 1 for l), brand display name, link text shows paypal.com, new domain.",
        "broker": {"ages": {"paypa1-sicherheit.com": 6}},
        "expect": ["ID_LOOKALIKE_BRAND", "ID_BRAND_NOT_OFFICIAL", "LINK_LOOKALIKE", "ID_DOMAIN_NEW",
                   "CLS_ASKS_CREDENTIALS", "CLS_CAT_PHISHING", "CLS_URGENCY", "CLS_IMPERSONATION"],
        "forbid": ["MIME_HIDDEN_TEXT", "CLS_ABSTAIN"],
    })

    # 2 Brand phishing, English (Microsoft 365) ---------------------------------------------------------
    msg = base('"Microsoft 365 Support" <no-reply@micros0ft-security.com>', "jane@example.org",
               "Action required: mailbox storage full", "2@micros0ft-security.com")
    msg.set_content("Dear user,\n\nyour mailbox is almost full and will be deactivated within 24 hours. Sign in "
                    "with your password to keep your account active and avoid losing access to your messages.\n\n"
                    "https://login.micros0ft-security.com/verify\n\nYour Microsoft 365 support team\n")
    write("brand_phishing_en", msg, {
        "notes": "Look-alike with digit zero, plain text link to the same look-alike domain.",
        "expect": ["ID_LOOKALIKE_BRAND", "ID_BRAND_NOT_OFFICIAL", "LINK_LOOKALIKE", "CLS_ASKS_CREDENTIALS",
                   "CLS_CAT_PHISHING", "CLS_URGENCY"],
    })

    # 3 BEC bank change, German -------------------------------------------------------------------------
    msg = base('"Thomas Weber (Geschäftsführung)" <thomas.weber.gf@gmail.com>', "buchhaltung@example.de",
               "Neue Bankverbindung", "3@gmail.com")
    msg.set_content("Hallo Frau Schmidt,\n\nbitte beachten Sie, dass sich unsere Bankverbindung geändert hat. "
                    "Alle künftigen Zahlungen überweisen Sie bitte ab sofort auf unser neues Konto.\n\n"
                    "Neue IBAN: DE89 3704 0044 0532 0130 00\n\nBitte behandeln Sie das vertraulich und antworten "
                    "Sie mir kurz, sobald die Änderung erledigt ist.\n\nViele Grüße\nThomas Weber\n")
    write("bec_bank_change_de", msg, {
        "notes": "Freemail executive persona announcing new bank details (text only).",
        "expect": ["CLS_BANK_CHANGE"],
        "forbid": ["ID_LOOKALIKE_BRAND", "CLS_ABSTAIN"],
    })

    # 4 BEC bank change, English ------------------------------------------------------------------------
    msg = base('"Accounts Receivable" <ar@supplier-invoices.example>', "ap@example.com",
               "Updated banking details for outstanding invoices", "4@supplier-invoices.example")
    msg.set_content("Dear customer,\n\nplease note that our bank details have changed. All future payments and the "
                    "outstanding invoice should be sent to our new account with immediate effect.\n\nNew IBAN: "
                    "GB29 NWBK 6016 1331 9268 19\n\nPlease reply to this email once you have updated your records.\n\n"
                    "Kind regards\nAccounts team\n")
    write("bec_bank_change_en", msg, {
        "expect": ["CLS_BANK_CHANGE"],
        "forbid": ["CLS_ABSTAIN"],
    })

    # 5 Signed newsletter, German (DKIM Ed25519, RFC 8058, DMARC reject) -------------------------------
    write_newsletter()

    # 6 Unsigned newsletter, English ---------------------------------------------------------------------
    msg = base('"Garden Weekly" <news@garden-weekly.example>', "jane@example.org", "Five plants for autumn",
               "6@garden-weekly.example")
    msg["List-Id"] = "<weekly.garden-weekly.example>"
    msg["List-Unsubscribe"] = "<https://garden-weekly.example/unsubscribe?u=42>"
    msg.set_content("Hello gardeners,\n\nthis week we look at five plants that bring colour to your garden in "
                    "autumn, from asters to ornamental grasses. Read the full article on our website: "
                    "https://garden-weekly.example/autumn-plants\n\nHappy gardening!\n")
    write("newsletter_en", msg, {"expect": [], "max_severity": "info", "forbid": ["CLS_CAT_SPAM"]})

    # 7/8 Personal mails ----------------------------------------------------------------------------------
    msg = base('"Lena Fischer" <lena.fischer@posteo.de>', "oma@example.de", "Danke für das Geschenk",
               "7@posteo.de")
    msg.set_content("Liebe Oma,\n\nvielen Dank für das schöne Geburtstagsgeschenk! Ich habe mich riesig über den "
                    "Pullover gefreut und trage ihn schon jeden Tag. Am Sonntag komme ich zum Kaffee vorbei, dann "
                    "erzähle ich dir alles von der Klassenfahrt.\n\nDicke Umarmung\ndeine Lena\n")
    write("personal_de", msg, {"expect": [], "max_severity": "info", "forbid": ["CLS_ABSTAIN"]})
    msg = base('"Tom Baker" <tom.baker@example.net>', "max@example.org", "Brunch on Saturday?", "8@example.net")
    msg.set_content("Hi Max,\n\nshall we go for brunch on Saturday? I would be free around ten and would suggest "
                    "the little cafe by the market, the one with the good pancakes. Let me know what you think.\n\n"
                    "Cheers,\nTom\n")
    write("personal_en", msg, {"expect": [], "max_severity": "info", "forbid": ["CLS_ABSTAIN"]})

    # 9 Executable disguised as PDF -----------------------------------------------------------------------
    msg = base('"Buchhaltung" <rechnung@lieferant-beispiel.example>', "anna@example.de", "Ihre Rechnung",
               "9@lieferant-beispiel.example")
    msg.set_content("Guten Tag,\n\nanbei erhalten Sie die Rechnung für Ihre letzte Bestellung. Bitte prüfen Sie "
                    "den Anhang und melden Sie sich bei Rückfragen gerne bei uns.\n\nMit freundlichen Grüßen\n")
    msg.add_attachment(FAKE_PE, maintype="application", subtype="pdf", filename="Rechnung_2026-118.pdf")
    write("attachment_exe_as_pdf", msg, {"expect": ["ATT_EXECUTABLE", "ATT_TYPE_MISMATCH"]})

    # 10 ZIP with executable ------------------------------------------------------------------------------
    msg = base('"Versand" <versand@shop-beispiel.example>', "jane@example.org", "Your shipping documents",
               "10@shop-beispiel.example")
    msg.set_content("Hello,\n\nplease find the shipping documents for your order attached. Open the archive and "
                    "print the label before the courier arrives tomorrow morning.\n\nBest regards\n")
    msg.add_attachment(zip_bytes({"Shipping_Label.pdf.exe": FAKE_PE, "readme.txt": b"label"}), maintype="application",
                       subtype="zip", filename="documents.zip")
    write("zip_with_exe", msg, {"expect": ["ATT_ARCHIVE_RISKY"], "forbid": ["ATT_ARCHIVE_OPAQUE"]})

    # 11 Macro-enabled Office document -------------------------------------------------------------------
    docm = zip_bytes({"[Content_Types].xml": b"<Types/>", "word/document.xml": b"<w:document/>",
                      "word/vbaProject.bin": b"dummy macro project (inert test data)"})
    msg = base('"HR" <hr@personal-beispiel.example>', "anna@example.de", "Gehaltsabrechnung November",
               "11@personal-beispiel.example")
    msg.set_content("Hallo,\n\nanbei die Gehaltsabrechnung für November. Bitte aktivieren Sie die Bearbeitung, "
                    "damit alle Inhalte richtig angezeigt werden.\n\nViele Grüße aus der Personalabteilung\n")
    msg.add_attachment(docm, maintype="application", subtype="vnd.ms-word.document.macroEnabled.12",
                       filename="Abrechnung_November.docm")
    write("macro_docm", msg, {"expect": ["ATT_MACRO"]})

    # 12 HTML smuggling ----------------------------------------------------------------------------------
    blob = base64.b64encode(b"\x00inert-test-payload" * 900).decode()
    smuggle = (f"<html><body><p>Loading document...</p><script>var d=atob('{blob}');"
               "var b=new Blob([d]);navigator.msSaveOrOpenBlob(b,'invoice.iso');</script></body></html>").encode()
    msg = base('"Accounts" <accounts@invoice-portal.example>', "jane@example.org", "Invoice #88213",
               "12@invoice-portal.example")
    msg.set_content("Hello,\n\nyour invoice is attached as a secure web document. Open the attachment in your "
                    "browser to view and download the invoice.\n\nThank you for your business.\n")
    msg.add_attachment(smuggle, maintype="text", subtype="html", filename="Invoice_88213.html")
    write("html_smuggling", msg, {"expect": ["ATT_HTML_SVG_ACTIVE"]})

    # 13 SVG with script ----------------------------------------------------------------------------------
    svg = (b'<svg xmlns="http://www.w3.org/2000/svg" onload="location.href=\'https://evil.example/x\'">'
           b'<script>document.title="x"</script><text x="10" y="20">Voice message</text></svg>')
    msg = base('"Voicemail" <voicemail@phone-notify.example>', "jane@example.org", "New voice message (0:42)",
               "13@phone-notify.example")
    msg.set_content("You have received a new voice message. The recording is attached to this email, open it "
                    "to listen to the message from your caller.\n")
    msg.add_attachment(svg, maintype="image", subtype="svg+xml", filename="voicemail.svg")
    write("svg_active_en", msg, {"expect": ["ATT_HTML_SVG_ACTIVE"]})

    # 14 Hidden text -------------------------------------------------------------------------------------
    salad = " ".join(["Wetter Garten Blumen Kaffee Urlaub Fahrrad Bücher Musik"] * 12)
    html = f"""<html><head><style>.x {{ display:none }}</style></head><body>
<p>Hallo, Ihre Bestellung wurde versandt. Den Status finden Sie in Ihrem Kundenkonto.</p>
<div class="x">{salad}</div><span style="font-size:0px">{salad}</span>
<p style="color:#ffffff;background-color:#ffffff">{salad}</p></body></html>"""
    msg = base('"Shop" <info@shop-versand.example>', "anna@example.de", "Ihre Bestellung", "14@shop-versand.example")
    msg.set_content(html, subtype="html")
    write("hidden_text_de", msg, {"expect": ["MIME_HIDDEN_TEXT"]})

    # 15 Image-only mail with QR payload supplied in the meta ---------------------------------------------
    png = bytes.fromhex("89504E470D0A1A0A0000000D49484452000000010000000108060000001F15C4890000000D49444154789C"
                        "6360000002000154A24F5D0000000049454E44AE426082")
    msg = base('"IT Service" <it-service@example-firm.example>', "jane@example.org", "MFA re-enrolment required",
               "15@example-firm.example")
    msg.set_content("Scan the code.\n")
    msg.add_attachment(png, maintype="image", subtype="png", filename="qr.png")
    write("qr_payload_meta", msg, {
        "notes": "The app decodes the QR code on device and sends its content in meta.qr_payloads.",
        "meta": {"qr_payloads": ["https://microsoft-login.mfa-renew.example/enrol?id=7731"]},
        "broker": {"listed": {"microsoft-login.mfa-renew.example": ["certpl"]}},
        "expect": ["LINK_FEED_HIT", "LINK_LOOKALIKE"],
    })

    # 16 DMARC spoof of an enforcing domain ---------------------------------------------------------------
    msg = base('"PayPal" <service@paypal.com>', "jane@example.org", "Receipt for your payment", "16@paypal.com")
    msg["Return-Path"] = "<bounce@mailer-cheap.example>"
    msg.set_content("You sent a payment of 249.00 USD to Online Store. If you did not make this payment, please "
                    "review your recent activity in your account at your earliest convenience.\n")
    write("dmarc_spoof_en", msg, {
        "broker": {"dns": {"_dmarc.paypal.com": {"status": "ok", "txt": ["v=DMARC1; p=reject; rua=mailto:d@paypal.com"]}}},
        "expect": ["AUTH_DMARC_FAIL_ENFORCED"],
        "forbid": ["ID_BRAND_NOT_OFFICIAL", "ID_LOOKALIKE_BRAND"],
    })

    # 17 Extortion --------------------------------------------------------------------------------------
    msg = base('"Anonymous" <x8827@mail-anon.example>', "jane@example.org", "Your password is Summer2024",
               "17@mail-anon.example")
    msg.set_content("I hacked your device months ago and recorded you through your webcam while you visited "
                    "adult websites. If you do not pay 1500 USD in bitcoin within 48 hours, I will send the video "
                    "to all your contacts.\n\nMy bitcoin address: bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh\n")
    write("extortion_en", msg, {"expect": ["CLS_EXTORTION", "CLS_CAT_SCAM"]})

    # 18 Callback scam ----------------------------------------------------------------------------------
    msg = base('"Norton Billing" <norton.billing.desk@gmail.com>', "jane@example.org", "Order confirmation #NT-55821",
               "18@gmail.com")
    msg.set_content("Thank you for renewing your Norton 360 subscription. Your account has been charged $399.99 "
                    "today. If you did not authorize this renewal, call our billing team immediately at "
                    "+1 (888) 555-0142 to cancel and receive a full refund.\n")
    write("callback_en", msg, {"expect": ["CLS_ASKS_CALLBACK", "PHONE_CALLBACK_LURE", "ID_BRAND_NOT_OFFICIAL"]})

    # 19 Encrypted ZIP ----------------------------------------------------------------------------------
    msg = base('"Steuerbüro" <kanzlei@steuer-beispiel.example>', "anna@example.de", "Unterlagen",
               "19@steuer-beispiel.example")
    msg.set_content("Hallo,\n\ndie Unterlagen finden Sie im passwortgeschützten Archiv im Anhang. Das Passwort "
                    "lautet 2026 und gilt nur für diese Sendung.\n\nViele Grüße\n")
    msg.add_attachment(zip_bytes({"Unterlagen.pdf": b"%PDF-1.4 dummy"}, encrypt=True), maintype="application",
                       subtype="zip", filename="Unterlagen.zip")
    write("encrypted_zip_de", msg, {"expect": ["ATT_ENCRYPTED"], "forbid": ["ATT_ARCHIVE_RISKY"]})

    # 20 ClickFix ---------------------------------------------------------------------------------------
    msg = base('"Security Check" <verify@captcha-check.example>', "jane@example.org", "Verify you are human",
               "20@captcha-check.example")
    msg.set_content("To finish the verification and unlock your document, press the Windows key + R, paste the "
                    "copied command with Ctrl+V and press Enter. Then click the button below to continue.\n\n"
                    "https://captcha-check.example/continue\n")
    write("clickfix_en", msg, {"expect": ["CLS_CODE_OR_COMMAND"]})

    # 21 PDF with JavaScript -------------------------------------------------------------------------------
    pdf = (b"%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >> endobj\n"
           b"2 0 obj << /Type /Pages /Kids [] /Count 0 >> endobj\n"
           b"3 0 obj << /S /JavaScript /JS (app.alert\\('inert test'\\);) >> endobj\n"
           b"trailer << /Root 1 0 R >>\n%%EOF\n")
    msg = base('"Scanner" <scanner@office-scan.example>', "anna@example.de", "Scan 2026-11-20",
               "21@office-scan.example")
    msg.set_content("Gescanntes Dokument im Anhang. Diese Nachricht wurde automatisch von Ihrem Scanner "
                    "erstellt, bitte antworten Sie nicht direkt auf diese Nachricht.\n")
    msg.add_attachment(pdf, maintype="application", subtype="pdf", filename="Scan_2026-11-20.pdf")
    write("pdf_javascript", msg, {"expect": ["ATT_PDF_ACTIVE"], "forbid": ["ATT_TYPE_MISMATCH"]})

    # 22 Feed-listed sender and disposable reply ---------------------------------------------------------
    msg = base('"Kundendienst" <support@paket-zoll-gebuehr.example>', "anna@example.de",
               "Zollgebühr für Ihre Sendung", "22@paket-zoll-gebuehr.example")
    msg.set_content("Für Ihre Sendung ist eine Zollgebühr von 2,99 € offen. Bitte bezahlen Sie den Betrag "
                    "innerhalb von 24 Stunden, sonst wird das Paket an den Absender zurückgeschickt: "
                    "https://paket-zoll-gebuehr.example/zahlen\n")
    write("feed_listed_sender_de", msg, {
        "broker": {"listed": {"paket-zoll-gebuehr.example": ["certpl"]}},
        "expect": ["FEED_SENDER_HIT", "LINK_FEED_HIT", "CLS_ASKS_PAYMENT", "CLS_URGENCY"],
    })


def write_newsletter() -> None:
    import dkim  # test-only dependency (zlib licence)
    from nacl.signing import SigningKey  # test-only dependency (Apache-2.0)

    key = SigningKey(bytes(range(32)))
    private_b64 = base64.b64encode(bytes(key)).decode()
    public_b64 = base64.b64encode(bytes(key.verify_key)).decode()
    msg = base('"Verlag Beispiel" <news@verlag-beispiel.de>', "anna@example.de", "Unser Wochenrückblick",
               "5@verlag-beispiel.de")
    msg["List-Unsubscribe"] = "<https://verlag-beispiel.de/abmelden?u=42>"
    msg["List-Unsubscribe-Post"] = "List-Unsubscribe=One-Click"
    msg.set_content("Hallo,\n\nin unserem Wochenrückblick finden Sie die wichtigsten Artikel der Woche, Tipps für "
                    "das Wochenende und neue Rezepte aus der Redaktion. Viel Spaß beim Lesen!\n\n"
                    "https://verlag-beispiel.de/rueckblick\n")
    raw = msg.as_bytes(policy=msg.policy.clone(linesep="\r\n"))
    signature = dkim.sign(raw, b"news", b"verlag-beispiel.de", private_b64.encode(), signature_algorithm=b"ed25519-sha256",
                          include_headers=[b"from", b"to", b"subject", b"date", b"message-id", b"list-unsubscribe",
                                           b"list-unsubscribe-post"], canonicalize=(b"relaxed", b"relaxed"))
    raw = signature + raw
    # dkimpy adds t= with the current time; replace it with a fixed value is not possible without
    # re-signing, so the timestamp stays whatever it was at generation time (replay check needs > 24 h AND
    # an unaddressed recipient, which this mail does not have).
    write("newsletter_signed_de", raw, {
        "notes": "Ed25519 DKIM (fixed seed), relaxed/relaxed, covers List-Unsubscribe(-Post); domain publishes p=reject.",
        "broker": {"dns": {
            "news._domainkey.verlag-beispiel.de": {"status": "ok", "txt": [f"v=DKIM1; k=ed25519; p={public_b64}"]},
            "_dmarc.verlag-beispiel.de": {"status": "ok", "txt": ["v=DMARC1; p=reject"]},
        }, "popular": ["verlag-beispiel.de"]},
        "expect": ["BULK_RFC8058_SIGNED"],
        "max_severity": "info",
        "auth": {"dkim_result": "pass", "dmarc_result": "pass"},
    })


if __name__ == "__main__":
    main()
