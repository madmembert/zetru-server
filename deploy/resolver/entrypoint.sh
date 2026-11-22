#!/bin/sh
# Renders the Unbound configuration for the dns network's subnet into the tmpfs /run/unbound,
# seeds the writable trust-anchor state from the build-time snapshot and runs Unbound in the
# foreground.
set -eu
subnet="${ZETRU_DNS_SUBNET:-172.30.53.0/24}"
case "$subnet" in
  *[!0-9./]* | "" ) echo "zetru-resolver: ZETRU_DNS_SUBNET must be an IPv4 CIDR such as 172.30.53.0/24" >&2; exit 1 ;;
esac
umask 077
sed "s#@DNS_SUBNET@#${subnet}#g" /etc/unbound/unbound.conf.in > /run/unbound/unbound.conf
cp /etc/unbound/root.key /run/unbound/root.key
exec unbound -d -c /run/unbound/unbound.conf
