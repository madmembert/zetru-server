# Zetru analysis server: installation and operation

The Zetru server analyses mails that the Zetru app submits and returns signed findings. It stores
no mail content. It runs as six containers on a Raspberry Pi 5 (8 GB) or a small VPS.
Architecture and security model: `docs/concept.md` §3–§4 and §11; container interfaces:
`docs/server-internal-api.md`; implementation decisions: `server/gateway/DECISIONS.md`.

| Container | Role | Networks | Talks to the internet |
|---|---|---|---|
| `gateway` | TLS 1.3, device authentication, limits, campaign counters, signed responses | `edge` (port 8443), `core` | no (inbound only) |
| `analyzer` | parses and analyses one mail per sandboxed worker | `core`, `dns` | no; DNS only via `resolver` |
| `inference` | typed decisions (rules, later encoder) | `core` | no |
| `resolver` | Unbound: recursive, DNSSEC-validating, no forwarders | `dns`, `egress` | DNS (port 53) |
| `updater` | downloads, validates and publishes feeds and models | `egress` | HTTPS to feed hosts |
| `lookup` | RDAP domain age with a 30-day cache | `core`, `egress` | HTTPS to RDAP servers |

`core` and `dns` are internal Docker networks without a route to the outside. Every container
runs as its own non-root user with a read-only root file system, no capabilities,
`no-new-privileges`, memory/CPU/process limits, core dumps off and size-capped logs.

## 1. Requirements

| | Raspberry Pi 5 | VPS |
|---|---|---|
| Hardware | 8 GB RAM, active cooler, 5 V/5 A supply, SSD recommended (USB 3 or NVMe) | ≥ 4 vCPU, ≥ 8 GB RAM, amd64 or arm64 |
| OS | Raspberry Pi OS (64-bit) or Ubuntu Server 24.04+ for arm64 | Debian 12+/Ubuntu 24.04+ |
| Compose profile | `pi` | `vps` |
| Expected RAM in use | ≈ 2.5 GB | ≈ 3.5 GB |

Software: Docker Engine with the Compose plugin (v2), `git`. Install Docker from your
distribution or from Docker's repository, then add your user to the `docker` group (or use `sudo`).

The app pins the server's key, so no public CA certificate and no domain are needed. Choose how
the app reaches the server: a LAN address, a VPN (for example WireGuard or Tailscale), a public
host name, or several of them (up to three URLs, tried in order).

## 2. Prepare the host (do this first)

Mail content exists only in container memory. Make sure memory never reaches a disk (§14.2).

**Swap off (or encrypted).**

```sh
sudo swapoff -a
# Raspberry Pi OS with dphys-swapfile:
sudo systemctl disable --now dphys-swapfile 2>/dev/null || true
# Ubuntu/Debian: remove or comment out swap lines in /etc/fstab
sudo sed -i.bak '/\sswap\s/s/^/#/' /etc/fstab
```

Compressed RAM swap (zram) never touches a disk and may stay. Swap on a disk must be off or
encrypted. The compose file additionally sets each mail-handling container's swap limit equal to
its memory limit, so those containers never swap even if host swap exists.

**Core dumps and crash reporters off.**

```sh
echo 'kernel.core_pattern=|/bin/false
fs.suid_dumpable=0' | sudo tee /etc/sysctl.d/90-zetru.conf
sudo sysctl --system
sudo mkdir -p /etc/systemd/coredump.conf.d
printf '[Coredump]\nStorage=none\nProcessSizeMax=0\n' | sudo tee /etc/systemd/coredump.conf.d/zetru.conf
sudo systemctl disable --now apport 2>/dev/null || true   # Ubuntu
```

**Memory limits must work.** Run `docker info`. If it warns `No memory limit support`, add
`cgroup_enable=memory cgroup_memory=1` to the single line in `/boot/firmware/cmdline.txt`
(Raspberry Pi) and reboot.

**Firewall.** Docker publishes ports past `ufw`. Either bind the gateway to one interface with
`ZETRU_BIND_ADDRESS` (step 3), or filter in the `DOCKER-USER` chain. Only port 8443/TCP needs to
be reachable, and only from the networks the app uses.

## 3. Install

```sh
git clone <repository> zetru && cd zetru/server/deploy
cp env.example .env
```

Edit `.env`:

- `COMPOSE_PROFILES=pi` or `vps`.
- `ZETRU_BIND_ADDRESS`: `0.0.0.0` for all interfaces, or the LAN/VPN address only.
- `ZETRU_PORT`: published port (default 8443).
- Leave `ZETRU_DNS_SUBNET` unless `172.30.53.0/24` collides with a network on the host.

## 4. Initialise and pair the first device

Run `init` **before** the first `up`. It creates the TLS key pair, a backup TLS key pair, the
Ed25519 server identity key and the campaign key `K_fp`, writes the configuration, creates the
first tenant and prints the first pairing code.

```sh
./zetru-server init --name "Home server" \
    --url https://192.168.1.20:8443 \
    --url https://zetru.example.net:8443
./zetru-server up
./zetru-server status        # all six containers should become "healthy"
```

`--name` is shown in the app's consent screen (max. 40 characters). The URLs are written into
pairing codes; the first one that works is used. `init` names the first tenant `default`
(`--tenant <name>` to change it).

The pairing code is printed as a QR code in the terminal and as text. It is valid for
**10 minutes** and works **once**. In the app, scan it (or paste the text), then compare the
**server identity fingerprint** the app shows (`abcd efgh ijkl mnop`) with the one printed next
to the QR code. Confirm only if they match.

If the QR code does not scan: use `--qr plain` on terminals with a dark background, enlarge the
terminal window, or paste the text code into the app.

More devices or a new code: `./zetru-server pair --tenant default`.

## 5. Tenants and policies

A tenant is a customer boundary (a household, a company). Devices belong to one tenant.

```sh
./zetru-server tenant list
./zetru-server tenant create office
./zetru-server pair --tenant office
./zetru-server tenant policy office --daily-quota 5000 --cross-tenant on
./zetru-server tenant policy office --backends rules
./zetru-server tenant delete office --yes      # removes its devices and counters
```

Policy values of `0` mean the profile default (pi: 30 analyses per device and minute, 3,000 per
day; vps: 60 and 10,000; mails up to 20 MB). Cross-tenant campaign counting is off by default;
with one tenant it has no effect.

## 6. Devices and revocation

```sh
./zetru-server devices                 # ID, tenant, label, paired, last seen, status
./zetru-server revoke <device-id>      # immediate: the next request is rejected
```

The app can also unpair itself or remove another device of the same tenant. A revoked device
gets `device_revoked` and stops submitting; to use it again, pair it again.

## 7. Key rotation

**Planned TLS rotation** (for example yearly):

```sh
./zetru-server rotate-tls
```

The gateway publishes a signed pin set with the old, the new and the backup key. The old key
stays in use for 30 days; apps fetch the new pin set whenever they contact the server. After
30 days the gateway switches to the new key by itself. Devices that did not contact the server in
those 30 days must pair again. `./zetru-server rotate-tls --complete` switches early.

**The TLS key is lost or compromised:**

```sh
./zetru-server rotate-tls --activate-backup
```

The backup key (already pinned by every app) is served immediately, a new backup key is created
and the lost key is removed from the pin set. If you keep the backup key offline, copy it back to
`backup/tls.pem` in the `gateway-data` volume first (see below).

**The server identity key is lost or compromised:** there is no remote recovery by design.
Initialise a new data volume and pair every device again.

**Keep the backup key offline (optional):**

```sh
docker run --rm --network none --user 10001:10001 -v zetru_gateway-data:/data alpine:3.22 \
    cat /data/backup/tls.pem > zetru-backup-tls.pem      # store it safely, e.g. encrypted
docker run --rm --network none --user 10001:10001 -v zetru_gateway-data:/data alpine:3.22 \
    rm /data/backup/tls.pem
# to restore before --activate-backup:
docker run --rm -i --network none --user 10001:10001 -v zetru_gateway-data:/data alpine:3.22 \
    sh -c 'umask 077; cat > /data/backup/tls.pem' < zetru-backup-tls.pem
```

## 8. Backups

```sh
./zetru-server backup > zetru-gateway-$(date +%F).tar.gz
```

The archive contains the server keys, the device registry and the configuration; it leaves out
request logs and counters on purpose (14- and 30-day retention). **It contains private keys:**
encrypt it (for example with `age` or `gpg`) and keep it off the server. Restore onto a stopped
server:

```sh
./zetru-server down
./zetru-server restore < zetru-gateway-2026-11-23.tar.gz
./zetru-server up
```

Feeds, models and the RDAP cache are downloaded again and need no backup.

## 9. Updates, logs, status

```sh
git pull && ./zetru-server up          # rebuilds and restarts changed containers
./zetru-server status
./zetru-server logs gateway-pi         # or gateway-vps, analyzer-pi, lookup, resolver, …
```

Request logs (time, endpoint, tenant ID, device ID, status, duration bucket, size bucket; never
content, addresses, domains, URLs or IP addresses) are written to `logs/` in the `gateway-data`
volume, one file per day, and deleted after 14 days. Container logs are capped at 3 × 10 MB.

Check reachability from another machine: `curl -k https://<host>:8443/healthz` must print
`{"status":"ok"}` (`-k` because the certificate is self-signed; the app pins its key instead).

## 10. Troubleshooting

- **A container keeps restarting with "permission denied" on its volume.** Named volumes take the
  owner of the image's directory when they are first created. If a volume was created by another
  container first, fix the owner once, for example
  `docker run --rm -v zetru_feeds:/v alpine:3.22 chown -R 10005:10005 /v` (feeds and models:
  10005, gateway-data: 10001, lookup-cache: 10006).
- **The gateway restarts right after `up`.** `init` has not been run (`server configuration: …
  run init first`).
- **The app says "Server identity changed".** The served key is not in the app's pin set: the
  device missed a rotation window or the data volume was replaced. Pair the device again.
- **`503 busy`.** The analyzer queue is full; the app retries after `Retry-After`.
- **Resolver unhealthy.** Outbound DNS (UDP/TCP 53) must be allowed for the host.

## Reference

| Path | Content |
|---|---|
| `server/deploy/docker-compose.yml` | services, networks, volumes, limits for `pi` and `vps` |
| `server/deploy/env.example` | settings (`.env`) |
| `server/deploy/zetru-server` | helper: up/down/status/logs, gateway CLI, backup/restore |
| `server/deploy/resolver/` | Unbound image and configuration |
| `server/gateway/` | gateway (Go); CLI commands `serve`, `init`, `pair`, `devices`, `revoke`, `rotate-tls`, `tenant`, `set-urls`, `healthcheck` |
| `server/lookup/` | RDAP lookup service (Go) |

Data volume `gateway-data` (mode 0600 files): `identity.key`, `fingerprint.key`,
`tls-state.json` (TLS keys and signed pin set), `backup/tls.pem`, `registry.json` (+ `.bak`),
`server.json`, `state/` (campaign counters, quotas), `logs/` (request logs).

Building the images needs internet access for the base images and the Python packages; the Go
services use the standard library only. Base images are build arguments (`GO_IMAGE`,
`BASE_IMAGE`) so that they can be pinned by digest.
