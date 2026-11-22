"""HTTP server: POST /v1/systemone, GET /healthz (internal `core` network only, server-internal-api.md).

Logs carry only the endpoint, status and a duration bucket; never state text, questions or answers.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import SERVICE_VERSION
from .router import Router

MAX_BODY = 256 * 1024
MAX_STATE = 64 * 1024
MAX_QUESTIONS = 32
_QID = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_TYPES = ("choice", "noul", "score")
_BACKENDS = ("rules", "encoder", "llm", "openjev", "jev")
_ERRORS = {"bad_request": "Malformed request.", "not_found": "Not found.", "internal": "Internal error.",
           "too_large": "Request too large."}


def log(event: str, **fields) -> None:
    record = {"ts": int(time.time()), "svc": "inference", "event": event}
    record.update({k: v for k, v in fields.items() if k in ("status", "path", "duration_bucket", "error_class", "backend")})
    sys.stderr.write(json.dumps(record) + "\n")


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
        if not isinstance(q, dict) or not isinstance(q.get("id"), str) or not _QID.match(q["id"]) or q["id"] in seen:
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


def serve(host: str = "0.0.0.0", port: int | None = None) -> None:
    port = port or int(os.environ.get("ZETRU_INFERENCE_PORT", "8082"))
    router = Router.from_env()
    httpd = ThreadingHTTPServer((host, port), make_handler(router))
    httpd.daemon_threads = True
    log("listening", path=f":{port}")
    httpd.serve_forever()
