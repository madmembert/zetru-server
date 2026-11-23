# Zetru updater (concept §3.2, §6.7). Build context: updater
#   docker build -t zetru/updater:1.0.0 updater
# Standard library only. /feeds and /models are created here owned by uid 10005 so that fresh named
# volumes inherit that ownership; everything it publishes is 0755/0644 (readable by uid 10002/10003).
ARG PYTHON_IMAGE=python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df

FROM ${PYTHON_IMAGE} AS build
ENV PYTHONDONTWRITEBYTECODE=1
COPY zetru_updater /app/zetru_updater
RUN python -m compileall -q /app

FROM ${PYTHON_IMAGE}
LABEL org.opencontainers.image.title="zetru-updater" org.opencontainers.image.version="1.0.0"
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    ZETRU_FEEDS_DIR=/feeds \
    ZETRU_STAGING_DIR=/feeds/.staging
# ca-certificates ship with the python slim image (system trust store for HTTPS).
RUN python -m pip uninstall -y pip setuptools wheel >/dev/null 2>&1 || true \
 && mkdir -p /feeds /models \
 && chown 10005:10005 /feeds /models \
 && chmod 0755 /feeds /models
COPY --from=build /app /app
USER 10005:10005
WORKDIR /app
HEALTHCHECK --interval=5m --timeout=10s --start-period=15m --retries=3 \
  CMD ["python3", "-c", "import json, sys, time; d = json.load(open('/feeds/psl/current.json')); sys.exit(0 if time.time() - d['fetched_at'] < 3 * 86400 else 1)"]
CMD ["python3", "-m", "zetru_updater"]
