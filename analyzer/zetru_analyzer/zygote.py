"""Pre-warmed zygote: a lean process (started with exec, so it holds none of the supervisor's feed data)
that imports and initialises everything a worker needs, then forks one fresh worker per mail.

Control channel: AF_UNIX datagram socket to the supervisor (one JSON message per datagram).
  supervisor → zygote: {"op": "spawn", "id": n} with the worker's socket end attached (SCM_RIGHTS)
  zygote → supervisor: {"op": "spawned", "id": n} | {"op": "spawn_failed", "id": n}
                       {"op": "exit", "id": n, "reason": "ok"|"timeout"|"signal"|"error", "code": int, "signal": int}
The zygote kills a worker after the 15 s wall-clock limit and reaps every child.
"""

from __future__ import annotations

import json
import os
import select
import signal
import socket
import sys
import time

WALL_CLOCK_S = 15.0


def _warm_up() -> None:
    """Initialise lazily loaded code before forking so workers need no imports or file access later."""
    import email.policy  # noqa: F401
    import encodings.idna  # noqa: F401
    import html.parser  # noqa: F401
    import zlib  # noqa: F401

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    sig = key.sign(b"x", padding.PKCS1v15(), hashes.SHA256())
    key.public_key().verify(sig, b"x", padding.PKCS1v15(), hashes.SHA256())
    ed = ed25519.Ed25519PrivateKey.generate()
    ed.public_key().verify(ed.sign(b"x"), b"x")
    Cipher(algorithms.AES(b"\0" * 16), modes.CBC(b"\0" * 16)).encryptor().update(b"\0" * 16)
    for codec in ("utf-8", "latin-1", "cp1252", "iso-8859-15", "utf-16-le", "cp437", "punycode", "idna", "ascii",
                  "iso-2022-jp", "shift_jis", "euc-jp", "gb2312", "gbk", "big5", "koi8-r", "windows-1251"):
        try:
            b"abcd".decode(codec, errors="replace")
        except (LookupError, UnicodeError):
            pass
    from . import attachments, confusables, mimeparse, pipeline  # noqa: F401

    confusables.table()
    pipeline.analyze  # noqa: B018


def main() -> int:
    fd = int(os.environ["ZETRU_ZYGOTE_FD"])
    feeds_dir = os.environ.get("ZETRU_FEEDS_DIR", "/feeds")
    enforce = os.environ.get("ZETRU_SANDBOX", "enforce") != "off"
    ctrl = socket.socket(fileno=fd)
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ImportError, ValueError, OSError):
        pass
    if sys.platform.startswith("linux"):
        try:
            import ctypes

            libc = ctypes.CDLL(None, use_errno=True)
            libc.prctl(1, signal.SIGKILL, 0, 0, 0)  # PR_SET_PDEATHSIG: die with the supervisor
        except OSError:
            pass

    from . import domains, logs, packs, worker

    psl = domains.load_psl(feeds_dir)
    pack_data = packs.default_packs()
    _warm_up()
    children: dict[int, dict] = {}

    def send(msg: dict) -> None:
        try:
            ctrl.send(json.dumps(msg).encode("ascii"))
        except OSError:
            pass

    send({"op": "ready"})
    logs.info("zygote_ready", pid_role="zygote")

    while True:
        timeout = 0.2 if children else 1.0
        readable, _, _ = select.select([ctrl], [], [], timeout)
        if readable:
            try:
                data, fds, _flags, _addr = socket.recv_fds(ctrl, 4096, 1)
            except OSError:
                break
            if not data:
                break
            try:
                msg = json.loads(data)
            except ValueError:
                msg = {}
            if msg.get("op") == "spawn" and fds and isinstance(msg.get("id"), int):
                job_id = msg["id"]
                worker_fd = fds[0]
                try:
                    pid = os.fork()
                except OSError:
                    os.close(worker_fd)
                    send({"op": "spawn_failed", "id": job_id})
                    continue
                if pid == 0:
                    code = 70
                    try:
                        ctrl.close()
                        code = worker.run(worker_fd, psl, pack_data, enforce)
                    finally:
                        os._exit(code)
                os.close(worker_fd)
                children[pid] = {"id": job_id, "start": time.monotonic(), "killed": False}
                send({"op": "spawned", "id": job_id})
            else:
                for extra in fds:
                    os.close(extra)
        now = time.monotonic()
        for pid, info in children.items():
            if not info["killed"] and now - info["start"] > WALL_CLOCK_S:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                info["killed"] = True
        while children:
            try:
                pid, status = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                break
            if pid == 0:
                break
            info = children.pop(pid, None)
            if info is None:
                continue
            if info["killed"]:
                reason, code, sig = "timeout", -1, signal.SIGKILL
            elif os.WIFSIGNALED(status):
                sig = os.WTERMSIG(status)
                reason, code = ("timeout" if sig == signal.SIGXCPU else "signal"), -1
            else:
                code, sig = os.WEXITSTATUS(status), 0
                reason = "ok" if code == 0 else "error"
            send({"op": "exit", "id": info["id"], "reason": reason, "code": code, "signal": int(sig)})
    for pid in list(children):
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
