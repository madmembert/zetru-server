#!/bin/sh
# Renders the Unbound configuration for the dns network's subnet into the tmpfs /run/unbound,
# seeds the writable trust-anchor state from the build-time snapshot, refreshes it and runs
# Unbound in the foreground.
set -eu
subnet="${ZETRU_DNS_SUBNET:-172.30.53.0/24}"
case "$subnet" in
  *[!0-9./]* | "" ) echo "zetru-resolver: ZETRU_DNS_SUBNET must be an IPv4 CIDR such as 172.30.53.0/24" >&2; exit 1 ;;
esac
umask 077
sed "s#@DNS_SUBNET@#${subnet}#g" /etc/unbound/unbound.conf.in > /run/unbound/unbound.conf
cp /etc/unbound/root.key /run/unbound/root.key
# Refresh the root trust anchor (RFC 5011 from the snapshot, else IANA's root-anchors.xml checked
# against the ICANN certificate built into unbound-anchor), so an image built before a root key
# rollover keeps validating (GO-19). Exit code 1 means "updated"; above 1 is a failure (for
# example no network yet), and the build-time snapshot is used.
rc=0
unbound-anchor -a /run/unbound/root.key || rc=$?
if [ "$rc" -gt 1 ]; then
  echo "zetru-resolver: unbound-anchor failed (exit $rc); using the build-time trust anchor" >&2
  cp /etc/unbound/root.key /run/unbound/root.key
fi
exec unbound -d -c /run/unbound/unbound.conf
