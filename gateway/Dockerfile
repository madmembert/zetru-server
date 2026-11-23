# syntax=docker/dockerfile:1.29.0@sha256:572cebbc2b15e6f84c077742952674889cb63cd5e9b80abdffcbe587b6f19183
# Zetru gateway: one static Go binary on distroless/static, non-root (uid 10001).
# The Dockerfile frontend and the base images are pinned by digest (GO-06); refresh them with
# deploy/pin-images.sh update, which also checks that nothing is left unpinned.
ARG GO_IMAGE=golang:1.27.4-alpine3.24@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280
ARG BASE_IMAGE=gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

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
