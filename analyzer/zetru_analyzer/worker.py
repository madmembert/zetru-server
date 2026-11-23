"""Worker body: runs in a freshly forked, sandboxed child of the zygote, handles exactly one mail, exits."""

from __future__ import annotations

import os
import socket
import time

from . import ipc, logs, pipeline, sandbox
from .domains import PublicSuffixList
from .packs import Packs

JOB_MAX = ipc.MAX_TO_WORKER


class ChannelBroker:
    """Requests outside information from the supervisor over the worker's socket."""

    def __init__(self, sock: socket.socket):
        self.sock = sock

    def request(self, *, dns=None, feeds=None, ages=None, decide=None) -> dict:
        message: dict = {"t": "req"}
        if dns is not None:
            message["dns"] = dns
        if feeds is not None:
            message["feeds"] = feeds
        if ages is not None:
            message["ages"] = ages
        if decide is not None:
            message["decide"] = decide
        ipc.send_frame(self.sock, message)
        reply, _ = ipc.recv_frame(self.sock, ipc.MAX_RESP)
        if reply.get("t") != "resp":
            raise ipc.ProtocolError("unexpected reply")
        return reply


def run(fd: int, psl: PublicSuffixList, packs: Packs, enforce_sandbox: bool) -> int:
    """Entry point inside the forked child. Never returns normally to the caller's stack (caller _exits)."""
    stage = "sandbox"
    sock = None
    try:
        fd = sandbox.close_inherited_fds(fd)
        sock = socket.socket(fileno=fd)
        sandbox.harden_worker(enforce=enforce_sandbox)
        stage = "job"
        job, raw = ipc.recv_frame(sock, JOB_MAX)
        if job.get("t") != "job":
            raise ipc.ProtocolError("expected job")
        now = job.get("now")
        ctx = pipeline.Context(meta=job.get("meta") or {}, policy=job.get("policy") or {}, psl=psl, packs=packs,
                               now=now if isinstance(now, int) and now > 0 else int(time.time()))
        stage = "analyze"
        result = pipeline.analyze(raw, ctx, ChannelBroker(sock))
        del raw
        stage = "result"
        ipc.send_frame(sock, {"t": "result", "result": result})
        return 0
    except (MemoryError, RecursionError) as exc:
        _report(sock, stage, "resources", type(exc).__name__)
        return 3
    except sandbox.SandboxError:
        logs.error("sandbox_failed", stage=stage)
        _report(sock, stage, "sandbox", "SandboxError")
        return 4
    except BaseException as exc:  # noqa: BLE001 - the worker must always report and exit
        logs.error("worker_error", stage=stage, error_class=type(exc).__name__)
        _report(sock, stage, "internal", type(exc).__name__)
        return 5


def _report(sock, stage: str, kind: str, error_class: str) -> None:
    if sock is None:
        try:
            sock = socket.socket(fileno=3)
        except OSError:
            return
    try:
        ipc.send_frame(sock, {"t": "error", "stage": stage, "kind": kind, "error_class": error_class[:64]})
    except Exception:
        pass


def exit_now(code: int) -> None:
    os._exit(code)
