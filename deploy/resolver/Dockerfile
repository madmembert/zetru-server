# syntax=docker/dockerfile:1.29.0@sha256:572cebbc2b15e6f84c077742952674889cb63cd5e9b80abdffcbe587b6f19183
# Zetru resolver: stock Unbound (BSD licence) from Alpine, recursive and DNSSEC-validating, no
# forwarders, non-root (uid 10004), read-only root file system with a tmpfs for runtime state.
# Frontend, base image and packages are pinned (GO-06). Alpine keeps only the newest build of a
# package in a branch: when a security update replaces one of these versions the build fails with
# "unable to select packages"; run deploy/pin-images.sh update and rebuild.
ARG BASE_IMAGE=alpine:3.22.8@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f
FROM ${BASE_IMAGE}
RUN apk add --no-cache unbound=1.25.2-r1 unbound-libs=1.25.2-r1 drill=1.8.4-r0 ldns=1.8.4-r0 \
 && addgroup -S -g 10004 resolver \
 && adduser -S -D -H -u 10004 -G resolver -s /sbin/nologin resolver
# Root trust anchor snapshot (RFC 5011 state file) taken at build time with unbound-anchor, which
# validates IANA's root-anchors.xml against its built-in ICANN certificate. Exit code 1 means
# "anchor written or updated"; anything above is an error. The entrypoint refreshes the anchor at
# every start (GO-19), so an old image keeps validating across a root key rollover.
RUN unbound-anchor -a /etc/unbound/root.key; rc=$?; \
    test "$rc" -le 1 && grep -Eq 'DNSKEY|[[:space:]]DS[[:space:]]' /etc/unbound/root.key \
 && chmod 0644 /etc/unbound/root.key
COPY unbound.conf.in /etc/unbound/unbound.conf.in
COPY entrypoint.sh /usr/local/bin/zetru-resolver
RUN chmod 0755 /usr/local/bin/zetru-resolver
USER 10004:10004
EXPOSE 53/udp 53/tcp
ENTRYPOINT ["/usr/local/bin/zetru-resolver"]
