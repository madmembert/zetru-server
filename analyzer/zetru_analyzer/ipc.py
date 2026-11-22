"""Typed messages between supervisor and worker over a pre-created AF_UNIX stream socket pair.

Frame: u32 total length (big-endian) | u32 JSON length | JSON object (with "t" = message type) | blob.
The worker never needs socket()/connect(): the pair exists before the sandbox is applied.

Worker → supervisor: {"t": "req", dns?, feeds?, ages?, decide?}, {"t": "result", "result": {...}},
                     {"t": "error", "stage": str, "error_class": str}
Supervisor → worker: {"t": "job", "meta": {...}, "policy": {...}, "now": int} + raw mail as blob,
                     {"t": "resp", dns?, feeds?, feeds_status?, ages?, decide?}
"""

from __future__ import annotations

import json
import socket
import struct

MAX_TO_WORKER = 22 * 1024 * 1024
MAX_FROM_WORKER = 1024 * 1024
_HEADER = struct.Struct(">II")


class ProtocolError(Exception):
    pass


def encode(obj: dict, blob: bytes = b"") -> bytes:
    payload = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return _HEADER.pack(4 + len(payload) + len(blob), len(payload)) + payload + blob


def decode(frame_body: bytes) -> tuple[dict, bytes]:
    if len(frame_body) < 4:
        raise ProtocolError("short frame")
    (json_len,) = struct.unpack(">I", frame_body[:4])
    if json_len > len(frame_body) - 4:
        raise ProtocolError("bad json length")
    try:
        obj = json.loads(frame_body[4:4 + json_len])
    except ValueError:
        raise ProtocolError("bad json") from None
    if not isinstance(obj, dict) or not isinstance(obj.get("t"), str):
        raise ProtocolError("bad message")
    return obj, frame_body[4 + json_len:]


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    chunks = []
    remaining = n
    while remaining:
        chunk = sock.recv(min(remaining, 1 << 20))
        if not chunk:
            raise ProtocolError("eof")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def send_frame(sock: socket.socket, obj: dict, blob: bytes = b"") -> None:
    sock.sendall(encode(obj, blob))


def recv_frame(sock: socket.socket, max_size: int) -> tuple[dict, bytes]:
    (total,) = struct.unpack(">I", _recv_exact(sock, 4))
    if total < 4 or total > max_size:
        raise ProtocolError("frame size")
    return decode(_recv_exact(sock, total))


async def read_frame(reader, max_size: int) -> tuple[dict, bytes]:
    head = await reader.readexactly(4)
    (total,) = struct.unpack(">I", head)
    if total < 4 or total > max_size:
        raise ProtocolError("frame size")
    return decode(await reader.readexactly(total))
