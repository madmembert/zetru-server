# Zetru inference (concept §3.2, §9). Build context: inference
#   docker build -t zetru/inference:1.0.0 inference
#   docker build --build-arg WITH_ENCODER=1 ...   (optional ONNX encoder runtime; off by default)
ARG PYTHON_IMAGE=python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df

FROM ${PYTHON_IMAGE} AS build
ARG WITH_ENCODER=0
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1
COPY requirements.txt requirements-encoder.txt /build/
RUN python -m pip install --only-binary=:all: --prefix=/install -r /build/requirements.txt \
 && if [ "$WITH_ENCODER" = "1" ]; then python -m pip install --only-binary=:all: --prefix=/install -r /build/requirements-encoder.txt; fi
COPY zetru_inference /app/zetru_inference
RUN python -m compileall -q /app /install

FROM ${PYTHON_IMAGE}
LABEL org.opencontainers.image.title="zetru-inference" org.opencontainers.image.version="1.0.0"
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    ZETRU_INFERENCE_PORT=8082 \
    ZETRU_INFERENCE_BACKENDS=rules \
    ZETRU_MODELS_DIR=/models
RUN python -m pip uninstall -y pip setuptools wheel >/dev/null 2>&1 || true
COPY --from=build /install /usr/local
COPY --from=build /app /app
RUN mkdir -p /models && chmod 0755 /models
USER 10003:10003
WORKDIR /app
EXPOSE 8082
HEALTHCHECK --interval=30s --timeout=5s --start-period=120s --retries=3 \
  CMD ["python3", "-c", "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8082/healthz', timeout=4).status == 200 else 1)"]
CMD ["python3", "-m", "zetru_inference"]
