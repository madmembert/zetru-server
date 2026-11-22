# syntax=docker/dockerfile:1
# Zetru gateway: one static Go binary on distroless/static, non-root (uid 10001).
# Base images are build arguments so that they can be pinned by digest at release time.
ARG GO_IMAGE=golang:1.27-alpine
ARG BASE_IMAGE=gcr.io/distroless/static-debian12:nonroot

FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/zetru-gateway ./cmd/zetru-gateway \
 && mkdir -p /out/data && chmod 0700 /out/data

FROM ${BASE_IMAGE}
COPY --from=build /out/zetru-gateway /usr/local/bin/zetru-gateway
# The empty /data directory owned by the gateway user is copied into the named volume on first use.
COPY --from=build --chown=10001:10001 /out/data /data
ENV ZETRU_DATA_DIR=/data
USER 10001:10001
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/zetru-gateway"]
CMD ["serve"]
