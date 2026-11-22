"""Entry point: `python -m zetru_analyzer` starts the supervisor (which execs the zygote)."""

import asyncio
import os
import sys

from . import logs, sandbox
from .config import Config
from .httpserver import serve
from .supervisor import Supervisor


def main() -> int:
    os.umask(0o077)
    config = Config.from_env()
    if not sys.platform.startswith("linux"):
        logs.warning("sandbox_skipped", reason="not_linux")
    elif sandbox.machine_arch() is None:
        logs.error("unsupported_architecture")
        return 2
    logs.info("starting", workers=config.workers, queue=config.queue)
    try:
        asyncio.run(serve(Supervisor(config), "0.0.0.0", config.port))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
