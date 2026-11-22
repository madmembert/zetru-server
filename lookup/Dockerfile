# syntax=docker/dockerfile:1
# Zetru lookup: RDAP domain ages. One static Go binary on distroless/static, non-root (uid 10006).
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
