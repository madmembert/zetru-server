"""Entry point: `python -m zetru_analyzer` starts the supervisor (which execs the zygote)."""

import asyncio
import os
import signal
import sys

from . import logs, sandbox
from .config import Config
from .httpserver import serve
from .supervisor import Supervisor


def main() -> int:
    os.umask(0o077)
    # PID 1 holds every queued mail: not dumpable, so /proc/1/mem is closed to workers of the same uid, and
    # SIGINT (the only signal Python would otherwise act on) is ignored (security review PY-07, PY-08). The
    # zygote inherits the ignored SIGINT through exec.
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    config = Config.from_env()
    if not sys.platform.startswith("linux"):
        logs.warning("sandbox_skipped", reason="not_linux")
    elif sandbox.machine_arch() is None:
        logs.error("unsupported_architecture")
        return 2
    elif not sandbox.set_not_dumpable() and config.sandbox == "enforce":
        logs.error("not_dumpable_failed")
        return 2
    logs.info("starting", workers=config.workers, queue=config.queue)
    try:
        asyncio.run(serve(Supervisor(config), "0.0.0.0", config.port))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
