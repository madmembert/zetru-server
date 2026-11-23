#!/bin/sh
# gateway-egress-firewall.sh: optional host firewall for the Zetru gateway (concept §3.2: the
# gateway initiates no connections; GO-16).
#
#   sudo ./gateway-egress-firewall.sh apply    add the rules (idempotent)
#   sudo ./gateway-egress-firewall.sh remove   delete them
#   sudo ./gateway-egress-firewall.sh status   show them
#
# The gateway is the only container on the "edge" network, whose Linux bridge compose names
# zetru-edge. The rules drop every NEW connection that arrives from that bridge: towards the
# internet and the LAN (DOCKER-USER chain, which Docker evaluates first for forwarded traffic and
# never flushes) and towards the host itself (INPUT chain). Answers to connections the app opens to
# the published port belong to existing connections and pass. The gateway resolves "analyzer"
# through Docker's DNS inside its own network namespace, which these rules do not touch.
#
# Needs iptables (legacy or nft-backed) and root; ip6tables is used too when Docker has IPv6. The
# rules do not survive a reboot: run "apply" after Docker has started, for example with the
# systemd unit shown in README.md. ZETRU_EDGE_BRIDGE overrides the bridge name.
set -eu

bridge="${ZETRU_EDGE_BRIDGE:-zetru-edge}"
tag="zetru-gateway-egress"

# One rule per line: chain, then the match and target.
rules() {
  printf '%s\n' \
    "DOCKER-USER -i $bridge -m conntrack --ctstate NEW -m comment --comment $tag -j DROP" \
    "INPUT -i $bridge -m conntrack --ctstate NEW -m comment --comment $tag -j DROP"
}

tables() {
  echo iptables
  if command -v ip6tables >/dev/null 2>&1 && ip6tables -w -n -L DOCKER-USER >/dev/null 2>&1; then
    echo ip6tables
  fi
}

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "gateway-egress-firewall: run as root (sudo)" >&2
    exit 1
  fi
  if ! iptables -w -n -L DOCKER-USER >/dev/null 2>&1; then
    echo "gateway-egress-firewall: chain DOCKER-USER not found; start Docker first" >&2
    exit 1
  fi
}

apply() {
  require_root
  if ! ip link show "$bridge" >/dev/null 2>&1; then
    echo "gateway-egress-firewall: bridge $bridge does not exist yet; the rules take effect once the stack runs" >&2
  fi
  for t in $(tables); do
    rules | while read -r chain spec; do
      # shellcheck disable=SC2086 # spec is a list of iptables arguments
      if ! $t -w -C "$chain" $spec 2>/dev/null; then
        $t -w -I "$chain" 1 $spec
        echo "$t: added to $chain: $spec"
      fi
    done
  done
}

remove() {
  require_root
  for t in $(tables); do
    rules | while read -r chain spec; do
      # shellcheck disable=SC2086
      while $t -w -C "$chain" $spec 2>/dev/null; do
        $t -w -D "$chain" $spec
        echo "$t: removed from $chain: $spec"
      done
    done
  done
}

status() {
  require_root
  for t in $(tables); do
    for chain in DOCKER-USER INPUT; do
      $t -w -S "$chain" | grep -- "$tag" || echo "$t $chain: no rule"
    done
  done
}

case "${1:-}" in
  apply) apply ;;
  remove) remove ;;
  status) status ;;
  *) sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
esac
