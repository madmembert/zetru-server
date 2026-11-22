"""Minimal asyncio HTTP/1.1 server for the internal endpoints (server-internal-api.md):

  POST /internal/v1/analyze     framed body (§11.2), headers X-Zetru-Tenant, X-Zetru-Policy
  POST /internal/v1/url/check   JSON (§11.3)
  GET  /internal/healthz

Error bodies use fixed messages per code (§11.6) and never contain request data.
"""

from __future__ import annotations

import asyncio
import json
import time

from . import framing, logs
from .supervisor import AnalysisTimeout, Busy, Supervisor, Unavailable

MAX_HEAD = 16 * 1024
MAX_HEADERS = 64
IDLE_TIMEOUT_S = 30.0
BODY_TIMEOUT_S = 30.0
MESSAGES = {
    "bad_request": "Malformed request.",
    "busy": "The analyzer is busy. Retry later.",
    "analysis_timeout": "The analysis timed out.",
    "analyzer_unavailable": "The analyzer is not available.",
    "not_found": "Not found.",
    "mail_too_large": "The mail exceeds the size limit.",
}
STATUS_TEXT = {200: "OK", 400: "Bad Request", 404: "Not Found", 413: "Payload Too Large", 503: "Service Unavailable",
               504: "Gateway Timeout"}


class HttpProblem(Exception):
    def __init__(self, status: int, code: str):
        super().__init__(code)
        self.status = status
        self.code = code


def _response(status: int, body: dict, extra: dict | None = None, close: bool = False) -> bytes:
    data = json.dumps(body, separators=(",", ":")).encode("utf-8")
    head = [f"HTTP/1.1 {status} {STATUS_TEXT.get(status, 'Status')}", "Content-Type: application/json",
            f"Content-Length: {len(data)}", "Cache-Control: no-store"]
    for key, value in (extra or {}).items():
        head.append(f"{key}: {value}")
    head.append("Connection: close" if close else "Connection: keep-alive")
    return ("\r\n".join(head) + "\r\n\r\n").encode("ascii") + data


def _error(status: int, code: str, close: bool = False) -> bytes:
    extra = {"Retry-After": "30"} if code in ("busy",) else {"Retry-After": "900"} if code == "analyzer_unavailable" else None
    return _response(status, {"error": {"code": code, "message": MESSAGES[code]}}, extra, close)


async def _read_head(reader: asyncio.StreamReader) -> tuple[str, str, dict] | None:
    try:
        raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), IDLE_TIMEOUT_S)
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError):
        return None
    except asyncio.LimitOverrunError:
        raise HttpProblem(400, "bad_request") from None
    lines = raw[:-4].decode("latin-1").split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) != 3 or not parts[2].startswith("HTTP/1."):
        raise HttpProblem(400, "bad_request")
    headers: dict[str, str] = {}
    for line in lines[1:MAX_HEADERS + 1]:
        name, sep, value = line.partition(":")
        if not sep or not name or name != name.strip():
            raise HttpProblem(400, "bad_request")
        key = name.lower()
        if key in headers and key in ("content-length", "transfer-encoding"):
            raise HttpProblem(400, "bad_request")
        headers[key] = value.strip()
    if len(lines) > MAX_HEADERS + 1:
        raise HttpProblem(400, "bad_request")
    return parts[0], parts[1], headers


async def _read_body(reader: asyncio.StreamReader, headers: dict, limit: int) -> bytes:
    if "transfer-encoding" in headers:
        if headers["transfer-encoding"].lower() != "chunked" or "content-length" in headers:
            raise HttpProblem(400, "bad_request")
        chunks = []
        total = 0
        while True:
            line = await reader.readuntil(b"\r\n")
            try:
                size = int(line.split(b";")[0].strip(), 16)
            except ValueError:
                raise HttpProblem(400, "bad_request") from None
            if size == 0:
                await reader.readuntil(b"\r\n")
                break
            total += size
            if total > limit:
                raise HttpProblem(413, "mail_too_large")
            chunks.append(await reader.readexactly(size))
            await reader.readexactly(2)
        return b"".join(chunks)
    length_text = headers.get("content-length", "0")
    if not length_text.isdigit():
        raise HttpProblem(400, "bad_request")
    length = int(length_text)
    if length > limit:
        raise HttpProblem(413, "mail_too_large")
    return await reader.readexactly(length)


class Server:
    def __init__(self, supervisor: Supervisor):
        self.supervisor = supervisor

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                close = False
                try:
                    head = await _read_head(reader)
                    if head is None:
                        break
                    method, target, headers = head
                    close = headers.get("connection", "").lower() == "close"
                    out = await asyncio.wait_for(self.route(reader, method, target, headers), BODY_TIMEOUT_S + 25)
                except HttpProblem as problem:
                    out, close = _error(problem.status, problem.code, close=True), True
                except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError):
                    out, close = _error(400, "bad_request", close=True), True
                writer.write(out)
                await writer.drain()
                if close:
                    break
        except (ConnectionError, OSError):
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def route(self, reader, method: str, target: str, headers: dict) -> bytes:
        started = time.monotonic()
        path = target.split("?", 1)[0]
        if method == "GET" and path == "/internal/healthz":
            await _read_body(reader, headers, 0)
            return _response(200, await self.supervisor.health())
        if method == "POST" and path == "/internal/v1/url/check":
            body = await asyncio.wait_for(_read_body(reader, headers, 64 * 1024), BODY_TIMEOUT_S)
            try:
                items = framing.parse_url_check(body)
            except framing.BadRequest:
                return _error(400, "bad_request")
            return _response(200, self.supervisor.url_check(items))
        if method == "POST" and path == "/internal/v1/analyze":
            tenant = headers.get("x-zetru-tenant")
            try:
                policy = framing.parse_policy(headers.get("x-zetru-policy"))
            except framing.BadRequest:
                await _read_body(reader, headers, framing.HARD_MAX_MAIL + framing.MAX_META + 4)
                return _error(400, "bad_request")
            limit = policy["max_mail_bytes"] + framing.MAX_META + 4
            body = await asyncio.wait_for(_read_body(reader, headers, limit), BODY_TIMEOUT_S)
            status, code = 200, None
            try:
                meta, raw = framing.parse_analyze(body, policy["max_mail_bytes"])
                del body
                status, payload = await self.supervisor.analyze(meta, raw, policy)
                out = _response(status, payload)
            except framing.BadRequest:
                status, code = 400, "bad_request"
            except Busy:
                status, code = 503, "busy"
            except AnalysisTimeout:
                status, code = 504, "analysis_timeout"
            except Unavailable:
                status, code = 503, "analyzer_unavailable"
            if code is not None:
                out = _error(status, code)
            if status >= 500:  # §11.5: the analyzer logs errors only (class and stage, no request data)
                logs.error("request_failed", endpoint="analyze", status=status, error_class=code or "",
                           tenant=tenant if framing.valid_tenant(tenant) else "invalid",
                           duration_bucket=logs.duration_bucket(time.monotonic() - started))
            return out
        await _read_body(reader, headers, 64 * 1024)
        return _error(404, "not_found")


async def serve(supervisor: Supervisor, host: str, port: int) -> None:
    await supervisor.start()
    server = Server(supervisor)
    srv = await asyncio.start_server(server.handle, host, port, limit=MAX_HEAD, reuse_address=True)
    logs.info("listening", count=port)
    async with srv:
        await srv.serve_forever()
