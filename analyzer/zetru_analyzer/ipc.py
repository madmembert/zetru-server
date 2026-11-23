"""Typed messages between supervisor and worker over a pre-created AF_UNIX stream socket pair.

Frame: u32 total length (big-endian) | u32 JSON length | JSON object (with "t" = message type) | blob.
The worker never needs socket()/connect(): the pair exists before the sandbox is applied.

Worker → supervisor: {"t": "req", dns?, feeds?, ages?, decide?}, {"t": "result", "result": {...}},
                     {"t": "error", "stage": str, "error_class": str}
Supervisor → worker: {"t": "job", "meta": {...}, "policy": {...}, "now": int} + raw mail as blob,
                     {"t": "resp", dns?, feeds?, feeds_status?, ages?, decide?}

Frame limits: a job frame carries at most the largest mail the HTTP layer accepts (framing.HARD_MAX_MAIL) plus
the JSON of meta and policy (PY-17); a reply frame is at most MAX_RESP, which the supervisor enforces when it
builds the reply (PY-06); worker frames are at most MAX_FROM_WORKER.
"""

from __future__ import annotations

import json
import socket
import struct

from .framing import HARD_MAX_MAIL

JOB_JSON_MAX = 512 * 1024              # meta ≤ 64 KiB of UTF-8, JSON-escaped at most 12 bytes per character
MAX_TO_WORKER = HARD_MAX_MAIL + JOB_JSON_MAX
MAX_FROM_WORKER = 1024 * 1024
MAX_RESP = 512 * 1024
_HEADER = struct.Struct(">II")


class ProtocolError(Exception):
    pass


def encode_head(obj: dict, blob_len: int = 0) -> bytes:
    """Frame header and JSON part; the blob follows separately (no copy of a 20 MB mail, PY-19)."""
    payload = json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return _HEADER.pack(4 + len(payload) + blob_len, len(payload)) + payload


def encode(obj: dict, blob: bytes = b"") -> bytes:
    return encode_head(obj, len(blob)) + bytes(blob)


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
