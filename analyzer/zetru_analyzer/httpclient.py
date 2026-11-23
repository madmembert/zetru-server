"""Minimal asyncio HTTP/1.1 client for plain-HTTP calls on the internal network (inference, lookup).

No threads are used anywhere in the supervisor (host names are resolved synchronously with a short cache
and connections are opened to the numeric address), so forking stays safe. A failed resolution is cached for
5 s and a known address is kept for up to 5 minutes while resolution fails, so an unreachable Docker DNS can block
the event loop at most once per 5 s (security review PY-22). Request bodies are sent as UTF-8 JSON (a state of
non-ASCII text would otherwise grow up to sixfold through \\u escapes, PY-03).
"""

from __future__ import annotations

import asyncio
import json
import socket
import time
import urllib.parse

MAX_RESPONSE = 512 * 1024
_CACHE: dict[tuple[str, int], tuple[float, str]] = {}
_FAILED: dict[tuple[str, int], float] = {}
_TTL = 30.0
_NEGATIVE_TTL = 5.0
_STALE_TTL = 300.0


class HttpError(Exception):
    pass


def resolve(host: str, port: int) -> str:
    key = (host, port)
    hit = _CACHE.get(key)
    now = time.monotonic()
    if hit and now - hit[0] < _TTL:
        return hit[1]
    failed_at = _FAILED.get(key)
    if failed_at is not None and now - failed_at < _NEGATIVE_TTL:
        if hit and now - hit[0] < _STALE_TTL:
            return hit[1]
        raise HttpError("resolve")
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        infos = []
    if not infos:
        _FAILED[key] = now
        if hit and now - hit[0] < _STALE_TTL:
            return hit[1]
        raise HttpError("resolve")
    _FAILED.pop(key, None)
    address = infos[0][4][0]
    _CACHE[key] = (now, address)
    return address


async def request_json(method: str, url: str, body: dict | None = None, timeout: float = 3.0) -> tuple[int, dict]:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "http" or not parts.hostname:
        raise HttpError("url")
    port = parts.port or 80
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    payload = b"" if body is None else json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8", "replace")

    async def run() -> tuple[int, dict]:
        address = resolve(parts.hostname, port)
        reader, writer = await asyncio.open_connection(address, port)
        try:
            head = (f"{method} {path} HTTP/1.1\r\nHost: {parts.hostname}\r\nConnection: close\r\n"
                    f"Accept: application/json\r\nContent-Length: {len(payload)}\r\n")
            if body is not None:
                head += "Content-Type: application/json\r\n"
            writer.write(head.encode("ascii") + b"\r\n" + payload)
            await writer.drain()
            status_line = await reader.readline()
            fields = status_line.split()
            if len(fields) < 2 or not fields[1].isdigit():
                raise HttpError("status")
            status = int(fields[1])
            length = None
            chunked = False
            for _ in range(100):
                line = await reader.readline()
                if line in (b"\r\n", b"\n", b""):
                    break
                name, _, value = line.decode("latin-1").partition(":")
                if name.strip().lower() == "content-length":
                    length = int(value.strip())
                elif name.strip().lower() == "transfer-encoding" and "chunked" in value.lower():
                    chunked = True
            if chunked:
                data = b""
                while True:
                    size = int((await reader.readline()).split(b";")[0].strip() or b"0", 16)
                    if size == 0:
                        break
                    data += await reader.readexactly(size)
                    await reader.readline()
                    if len(data) > MAX_RESPONSE:
                        raise HttpError("too large")
            elif length is not None:
                if length > MAX_RESPONSE:
                    raise HttpError("too large")
                data = await reader.readexactly(length)
            else:
                data = await reader.read(MAX_RESPONSE + 1)
                if len(data) > MAX_RESPONSE:
                    raise HttpError("too large")
            try:
                doc = json.loads(data) if data else {}
            except ValueError:
                raise HttpError("json") from None
            if not isinstance(doc, dict):
                raise HttpError("json")
            return status, doc
        finally:
            writer.close()

    try:
        return await asyncio.wait_for(run(), timeout)
    except asyncio.TimeoutError:
        raise HttpError("timeout") from None
    except (OSError, asyncio.IncompleteReadError, ValueError) as exc:
        raise HttpError(type(exc).__name__) from None
