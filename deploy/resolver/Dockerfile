# syntax=docker/dockerfile:1
# Zetru resolver: stock Unbound (BSD licence) from Alpine, recursive and DNSSEC-validating, no
# forwarders, non-root (uid 10004), read-only root file system with a tmpfs for runtime state.
ARG BASE_IMAGE=alpine:3.22
FROM ${BASE_IMAGE}
RUN apk add --no-cache unbound drill \
 && addgroup -S -g 10004 resolver \
 && adduser -S -D -H -u 10004 -G resolver -s /sbin/nologin resolver
# Root trust anchor snapshot (RFC 5011 state file) taken at build time with unbound-anchor, which
# validates IANA's root-anchors.xml against its built-in ICANN certificate. Exit code 1 means
# "anchor written or updated"; anything above is an error.
RUN unbound-anchor -a /etc/unbound/root.key; rc=$?; \
    test "$rc" -le 1 && grep -Eq 'DNSKEY|[[:space:]]DS[[:space:]]' /etc/unbound/root.key \
 && chmod 0644 /etc/unbound/root.key
COPY unbound.conf.in /etc/unbound/unbound.conf.in
COPY entrypoint.sh /usr/local/bin/zetru-resolver
RUN chmod 0755 /usr/local/bin/zetru-resolver
USER 10004:10004
EXPOSE 53/udp 53/tcp
ENTRYPOINT ["/usr/local/bin/zetru-resolver"]
