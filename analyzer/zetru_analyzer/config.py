"""Environment configuration (server-internal-api.md, "Environment variables")."""

from __future__ import annotations

import os
from dataclasses import dataclass

PROFILES = {"pi": (2, 8), "vps": (4, 32)}


def _int(env, name: str, default: int, low: int, high: int) -> int:
    try:
        value = int(env.get(name, default))
    except (TypeError, ValueError):
        value = default
    return max(low, min(high, value))


@dataclass(frozen=True)
class Config:
    profile: str
    workers: int
    queue: int
    port: int
    inference_url: str
    lookup_url: str
    resolver_host: str
    feeds_dir: str
    sandbox: str                    # enforce | off (off only for local development)
    request_timeout_s: float = 20.0
    dns_timeout_s: float = 2.5
    age_timeout_s: float = 3.0
    inference_timeout_s: float = 8.0

    @classmethod
    def from_env(cls, env=os.environ) -> "Config":
        profile = env.get("ZETRU_PROFILE", "pi")
        if profile not in PROFILES:
            profile = "pi"
        workers_default, queue_default = PROFILES[profile]
        return cls(
            profile=profile,
            workers=_int(env, "ZETRU_WORKERS", workers_default, 1, 16),
            queue=_int(env, "ZETRU_QUEUE", queue_default, 0, 256),
            port=_int(env, "ZETRU_ANALYZER_PORT", 8081, 1, 65535),
            inference_url=env.get("ZETRU_INFERENCE_URL", "http://inference:8082").rstrip("/"),
            lookup_url=env.get("ZETRU_LOOKUP_URL", "http://lookup:8083").rstrip("/"),
            resolver_host=env.get("ZETRU_RESOLVER_HOST", "resolver"),
            feeds_dir=env.get("ZETRU_FEEDS_DIR", "/feeds"),
            sandbox="off" if env.get("ZETRU_SANDBOX") == "off" else "enforce",
        )
