import asyncio
import base64
import hashlib
import json
import struct

from zetru_analyzer.httpserver import Server
from zetru_analyzer.supervisor import AnalysisTimeout, Busy

RAW = b"From: a@sender.example\r\n\r\nhello"


class FakeSupervisor:
    def __init__(self, error=None):
        self.error = error
        self.calls = []

    async def analyze(self, meta, raw, policy):
        self.calls.append((meta, raw, policy))
        if self.error:
            raise self.error
        return 200, {"schema": 1, "mail_sha256": meta["mail_sha256"]}

    def url_check(self, items):
        return {"results": [], "feeds": []}

    async def health(self):
        return {"status": "ok", "feeds": [], "backends": []}


class Writer:
    def __init__(self):
        self.data = b""

    def write(self, data):
        self.data += data

    async def drain(self):
        pass

    def close(self):
        pass


def analyze_body(raw=RAW):
    meta = {"schema": 1, "mail_sha256": hashlib.sha256(raw).hexdigest(), "account_ref": "0" * 32, "mode": "auto",
            "locale": "en", "catalog_version": 1}
    blob = json.dumps(meta).encode()
    return struct.pack(">I", len(blob)) + blob + raw


def request(method, path, body=b"", headers=None):
    head = f"{method} {path} HTTP/1.1\r\nHost: analyzer\r\nContent-Length: {len(body)}\r\n"
    for key, value in (headers or {}).items():
        head += f"{key}: {value}\r\n"
    return head.encode() + b"\r\n" + body


def exchange(raw_bytes, supervisor=None):
    supervisor = supervisor or FakeSupervisor()

    async def run():
        reader = asyncio.StreamReader(limit=16 * 1024)
        reader.feed_data(raw_bytes)
        reader.feed_eof()
        writer = Writer()
        await Server(supervisor).handle(reader, writer)
        return writer.data

    return asyncio.run(run()), supervisor


def responses(data):
    out = []
    while data:
        head, _, rest = data.partition(b"\r\n\r\n")
        status = int(head.split(b" ")[1])
        length = int(next(l for l in head.split(b"\r\n") if l.lower().startswith(b"content-length")).split(b":")[1])
        out.append((status, head, json.loads(rest[:length])))
        data = rest[length:]
    return out


def test_keep_alive_analyze_and_health():
    policy = base64.urlsafe_b64encode(json.dumps({"backends": ["rules"], "max_mail_bytes": 1000}).encode()).decode()
    data, sup = exchange(request("POST", "/internal/v1/analyze", analyze_body(),
                                 {"X-Zetru-Tenant": "5b0c5c1e-6f0b-4a53-9d0e-2a6f1f1f7c11", "X-Zetru-Policy": policy})
                         + request("GET", "/internal/healthz"))
    (s1, _, b1), (s2, _, b2) = responses(data)
    assert s1 == 200 and b1["mail_sha256"] == hashlib.sha256(RAW).hexdigest()
    assert s2 == 200 and b2["status"] == "ok"
    assert sup.calls[0][2] == {"backends": ["rules"], "max_mail_bytes": 1000}


def test_bad_framing_and_policy_and_unknown_path():
    data, _ = exchange(request("POST", "/internal/v1/analyze", b"\x00\x00\x00\x05{}") +
                       request("POST", "/internal/v1/analyze", analyze_body(), {"X-Zetru-Policy": "@@"}) +
                       request("GET", "/nope"))
    statuses = [(s, b["error"]["code"]) for s, _, b in responses(data)]
    assert statuses == [(400, "bad_request"), (400, "bad_request"), (404, "not_found")]


def test_error_mapping_and_retry_after():
    data, _ = exchange(request("POST", "/internal/v1/analyze", analyze_body()), FakeSupervisor(Busy()))
    status, head, body = responses(data)[0]
    assert status == 503 and body["error"]["code"] == "busy" and b"Retry-After: 30" in head
    data, _ = exchange(request("POST", "/internal/v1/analyze", analyze_body()), FakeSupervisor(AnalysisTimeout()))
    assert responses(data)[0][2]["error"]["code"] == "analysis_timeout"


def test_error_body_never_echoes_input():
    data, _ = exchange(request("POST", "/internal/v1/analyze", b"\x00\x00\x00\x10SECRET-CONTENT!!x"))
    assert b"SECRET" not in data


def test_body_over_limit_is_rejected():
    policy = base64.urlsafe_b64encode(json.dumps({"backends": [], "max_mail_bytes": 10}).encode()).decode()
    big = analyze_body(b"x" * 70_000)
    data, sup = exchange(request("POST", "/internal/v1/analyze", big, {"X-Zetru-Policy": policy}))
    assert responses(data)[0][0] == 413 and not sup.calls


def test_chunked_body():
    body = analyze_body()
    chunked = f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n"
    raw = (b"POST /internal/v1/analyze HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n" + chunked)
    data, _ = exchange(raw)
    assert responses(data)[0][0] == 200


def test_request_smuggling_shapes_are_rejected():
    raw = (b"POST /internal/v1/url/check HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
    assert responses(exchange(raw)[0])[0][0] == 400
    raw = b"POST /internal/v1/url/check HTTP/1.1\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\n{}"
    assert responses(exchange(raw)[0])[0][0] == 400
