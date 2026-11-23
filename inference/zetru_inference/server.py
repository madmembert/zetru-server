"""HTTP server: POST /v1/systemone, GET /healthz (internal `core` network only, server-internal-api.md).

Logs carry only the endpoint, status and a duration bucket; never state text, questions or answers.

Load bounds (security review PY-04): at most `ZETRU_INFERENCE_CONCURRENCY` requests (default 8) are handled at
once; further connections get `503 busy` at once instead of a new thread. Each connection has a 15 s socket
timeout, and the router answers within its 6 s deadline, so no request can hold a thread for long.
"""

from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import SERVICE_VERSION
from .router import Router

MAX_BODY = 1024 * 1024   # a 64 Ki-character state, JSON-escaped at up to 12 bytes per character, plus questions
MAX_STATE = 64 * 1024
DEFAULT_CONCURRENCY = 8
SOCKET_TIMEOUT_S = 15.0
MAX_QUESTIONS = 32
_QID = re.compile(r"[a-z][a-z0-9_]{0,63}")
_TYPES = ("choice", "noul", "score")
_BACKENDS = ("rules", "encoder", "llm", "openjev", "jev")
_ERRORS = {"bad_request": "Malformed request.", "not_found": "Not found.", "internal": "Internal error.",
           "too_large": "Request too large.", "busy": "The inference service is busy. Retry later."}


def log(event: str, **fields) -> None:
    record = {"ts": int(time.time()), "svc": "inference", "event": event}
    record.update({k: v for k, v in fields.items() if k in ("status", "path", "duration_bucket", "error_class", "backend")})
    try:
        sys.stderr.write(json.dumps(record) + "\n")
    except Exception:  # logging must never break request handling
        pass


def validate_request(doc) -> tuple[str, list[dict], str | None, list[str]]:
    if not isinstance(doc, dict):
        raise ValueError("body")
    state = doc.get("state")
    if not isinstance(state, str) or not state or len(state) > MAX_STATE:
        raise ValueError("state")
    if doc.get("state_version") != "state-1":
        raise ValueError("state_version")
    hint = doc.get("language_hint")
    if hint not in (None, "de", "en"):
        raise ValueError("language_hint")
    questions = doc.get("questions")
    if not isinstance(questions, list) or not 1 <= len(questions) <= MAX_QUESTIONS:
        raise ValueError("questions")
    clean = []
    seen = set()
    for q in questions:
        if not isinstance(q, dict) or not isinstance(q.get("id"), str) or not _QID.fullmatch(q["id"]) or q["id"] in seen:
            raise ValueError("question")
        if q.get("type") not in _TYPES:
            raise ValueError("question_type")
        instructions = q.get("instructions", "")
        if not isinstance(instructions, str) or len(instructions) > 2000:
            raise ValueError("instructions")
        criteria = q.get("criteria")
        if criteria is not None and not isinstance(criteria, (list, dict)):
            raise ValueError("criteria")
        seen.add(q["id"])
        clean.append({"id": q["id"], "type": q["type"], "instructions": instructions, "criteria": criteria})
    policy = doc.get("policy") or {}
    backends = policy.get("backends", ["rules"]) if isinstance(policy, dict) else None
    if not isinstance(backends, list) or not all(isinstance(b, str) and b in _BACKENDS for b in backends):
        raise ValueError("policy")
    return state, clean, hint, backends


def make_handler(router: Router):
    class Handler(BaseHTTPRequestHandler):
        server_version = "zetru-inference"
        sys_version = ""
        protocol_version = "HTTP/1.1"
        timeout = SOCKET_TIMEOUT_S   # an idle or slow client cannot keep a handler thread

        def log_message(self, fmt, *args):  # silence default access log (it would contain the client address)
            return

        def _send(self, status: int, body: dict) -> None:
            data = json.dumps(body, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _error(self, status: int, code: str) -> None:
            self._send(status, {"error": {"code": code, "message": _ERRORS[code]}})

        def do_GET(self):
            if self.path == "/healthz":
                self._send(200, {"status": "ok", "version": SERVICE_VERSION, "backends": router.health()})
            else:
                self._error(404, "not_found")

        def do_POST(self):
            started = time.monotonic()
            if self.path != "/v1/systemone":
                self._error(404, "not_found")
                return
            try:
                length = int(self.headers.get("Content-Length", "-1"))
            except ValueError:
                length = -1
            if length < 0:
                self._error(400, "bad_request")
                return
            if length > MAX_BODY:
                self._error(413, "too_large")
                self.close_connection = True
                return
            try:
                doc = json.loads(self.rfile.read(length))
                state, questions, hint, backends = validate_request(doc)
            except (ValueError, UnicodeDecodeError):
                self._error(400, "bad_request")
                return
            try:
                answers = router.decide(state, questions, hint, backends)
            except Exception as exc:  # never leak details; the analyzer treats this as classifier "failed"
                log("decide_error", error_class=type(exc).__name__)
                self._error(500, "internal")
                return
            self._send(200, {"answers": [a.to_json() for a in answers]})
            elapsed = time.monotonic() - started
            if elapsed > 5:  # §11.5: errors and anomalies only, never request data
                log("slow_request", status=200, duration_bucket="ge5s")

    return Handler


_BUSY_BODY = json.dumps({"error": {"code": "busy", "message": _ERRORS["busy"]}}, separators=(",", ":")).encode()
_BUSY = (b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nRetry-After: 5\r\n"
         b"Connection: close\r\nContent-Length: " + str(len(_BUSY_BODY)).encode() + b"\r\n\r\n" + _BUSY_BODY)


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer with a fixed number of handler threads; excess connections are refused with 503."""

    daemon_threads = True

    def __init__(self, address, handler, max_concurrent: int = DEFAULT_CONCURRENCY, bind_and_activate: bool = True):
        self.slots = threading.BoundedSemaphore(max(1, max_concurrent))
        super().__init__(address, handler, bind_and_activate)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            try:
                request.settimeout(1.0)
                request.sendall(_BUSY)
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


def _concurrency(env=os.environ) -> int:
    try:
        return max(1, min(64, int(env.get("ZETRU_INFERENCE_CONCURRENCY", DEFAULT_CONCURRENCY))))
    except ValueError:
        return DEFAULT_CONCURRENCY


def serve(host: str = "0.0.0.0", port: int | None = None) -> None:
    port = port or int(os.environ.get("ZETRU_INFERENCE_PORT", "8082"))
    router = Router.from_env()
    httpd = BoundedThreadingHTTPServer((host, port), make_handler(router), _concurrency())
    log("listening", path=f":{port}")
    httpd.serve_forever()
