# Zetru analyzer (concept §3.2). Build context: analyzer
#   docker build -t zetru/analyzer:1.0.0 analyzer
# PYTHON_IMAGE is pinned by digest; refresh it with deploy/pin-images.sh update.
ARG PYTHON_IMAGE=python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df

FROM ${PYTHON_IMAGE} AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1
COPY requirements.txt /build/requirements.txt
# Binary wheels only: no compiler in the image, reproducible dependency set.
RUN python -m pip install --only-binary=:all: --prefix=/install -r /build/requirements.txt
COPY zetru_analyzer /app/zetru_analyzer
RUN python -m compileall -q /app /install

FROM ${PYTHON_IMAGE}
LABEL org.opencontainers.image.title="zetru-analyzer" org.opencontainers.image.version="1.0.0"
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    ZETRU_FEEDS_DIR=/feeds \
    ZETRU_ANALYZER_PORT=8081
# The runtime needs neither pip nor setuptools.
RUN python -m pip uninstall -y pip setuptools wheel >/dev/null 2>&1 || true
COPY --from=build /install /usr/local
COPY --from=build /app /app
# Owned by the updater (uid 10005), its only writer: whichever container mounts the empty named volume
# first hands its directory owner to the volume, so every image must agree (deploycheck test).
RUN mkdir -p /feeds && chown 10005:10005 /feeds && chmod 0755 /feeds
USER 10002:10002
WORKDIR /app
EXPOSE 8081
# Compose overrides this with the same check (python3 on PATH, internal health endpoint).
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD ["python3", "-c", "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8081/internal/healthz', timeout=4).status == 200 else 1)"]
CMD ["python3", "-m", "zetru_analyzer"]
