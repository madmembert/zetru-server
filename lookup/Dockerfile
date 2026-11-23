# syntax=docker/dockerfile:1.29.0@sha256:572cebbc2b15e6f84c077742952674889cb63cd5e9b80abdffcbe587b6f19183
# Zetru lookup: RDAP domain ages. One static Go binary on distroless/static, non-root (uid 10006).
# Frontend and base images pinned by digest (deploy/pin-images.sh update refreshes them).
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
    go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/zetru-lookup ./cmd/zetru-lookup \
 && mkdir -p /out/cache && chmod 0700 /out/cache

FROM ${BASE_IMAGE}
# distroless/static ships the CA certificates used for the RDAP HTTPS connections.
COPY --from=build /out/zetru-lookup /usr/local/bin/zetru-lookup
COPY --from=build --chown=10006:10006 /out/cache /cache
ENV ZETRU_LOOKUP_CACHE_DIR=/cache
USER 10006:10006
EXPOSE 8083
ENTRYPOINT ["/usr/local/bin/zetru-lookup"]
CMD ["serve"]
