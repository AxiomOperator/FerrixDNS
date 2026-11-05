# Installing and running a node

FerrixDNS is early development software. Try it alongside your existing DNS before relying on it, and
give devices a second DNS server, because a single node has no redundancy.

## Packages

Release builds attach `.deb` and `.rpm` packages for amd64 and arm64. They need glibc 2.36 or newer,
which covers Debian 12, Ubuntu 24.04 and current Fedora.

```sh
sudo apt install ./ferrixdns_0.1.0_amd64.deb   # or: sudo dnf install ./ferrixdns-0.1.0-1.x86_64.rpm
sudoedit /etc/ferrixdns/ferrixdns.env
sudo systemctl enable --now ferrixdns
journalctl -u ferrixdns | grep setup_token
```

Installing doesn't start the service, because that would change how the machine answers DNS.
Removing the package leaves `/etc/ferrixdns` and the state in `/var/lib/ferrixdns`.

**Port 53 conflicts:** `systemd-resolved` usually holds `127.0.0.53:53`. Binding this machine's LAN
address avoids that. If you bind `0.0.0.0:53`, first set `DNSStubListener=no` in
`/etc/systemd/resolved.conf`, and make sure the machine doesn't use itself as its only resolver.

## Container

```sh
sudo scripts/docker-deploy.sh                      # uses this machine's main address
sudo scripts/docker-deploy.sh --address 10.0.0.5   # or choose one
```

This builds the image, starts it with `packaging/docker/compose.yaml`, waits until DNS answers, and
prints the dashboard address and setup token. Run it again to upgrade. `--down` stops the node and
keeps its data, and `--help` lists the other options. `--controller` deploys a central controller, and
`--node-only` deploys a node with no dashboard that it manages. See
[Central controller](controller.md).

`sudo` isn't needed if your user can already use Docker, but a rootless Docker or Podman can't use
port 53 with host networking.

The node only answers loopback and private networks by default. If this machine's network is public
address space, the script also allows that one network. Set `FERRIXDNS_ALLOW` to choose the list yourself.

**Use host networking.** With published ports, containers usually see all queries coming from one
gateway address, so per-client rules, client statistics and MAC addresses can't work. The image runs as a non-root
user with a read-only root filesystem, and needs only `NET_BIND_SERVICE`. The binary holds that as a file
capability, so the container can't use `no-new-privileges`, and it won't start if `NET_BIND_SERVICE` is dropped.

## Reaching the dashboard

By default it stays on loopback. To reach it from elsewhere, choose one:

| Method | Settings | Notes |
|---|---|---|
| Your own certificate | `FERRIXDNS_WEB_TLS_CERT`, `FERRIXDNS_WEB_TLS_KEY` | Best. Also turns on HSTS. Restart to load a renewed certificate. |
| Self-signed | `FERRIXDNS_WEB_TLS_SELF_SIGNED=true` | Browsers warn. Check the certificate against the `sha256` in the node's log. |
| A TLS proxy | Keep loopback, and set `FERRIXDNS_WEB_HOST` | The proxy must send the original host name. |

Also set `FERRIXDNS_WEB_LISTEN` to a network address, and `FERRIXDNS_WEB_HOST` to every name or address people will
use, such as `dns.home.arpa,192.168.1.10`. Other names are refused, which is what stops DNS rebinding
attacks. Plain HTTP on a network address needs `--web-insecure-remote`, which exposes passwords and
query logs to anyone on the network path.

## Encrypted upstreams

Give the certificate's name and an IP address, because this node can't look up its own upstream:

```sh
FERRIXDNS_UPSTREAM=tls://cloudflare-dns.com@1.1.1.1,tls://dns.quad9.net@9.9.9.9
FERRIXDNS_UPSTREAM=https://cloudflare-dns.com/dns-query@1.1.1.1
```

A certificate failure counts as a failed upstream and never falls back to plain DNS. Certificates are
checked against the Mozilla root list built into the binary.

## DNSSEC validation

Set `FERRIXDNS_DNSSEC_VALIDATE=true` to validate answers on this node. It's off by default.

- Upstreams must return signatures. Most public resolvers do, but some home routers don't, and then
  signed domains fail.
- The system clock must be right, because signatures have validity periods. Devices without a
  battery-backed clock should sync time without depending on this node's DNS.
- A failed check returns SERVFAIL with Extended DNS Error 6. `dig +cd` shows the answer without
  validation, to tell a broken domain from a broken node.

## Monitoring

`ferrixdns health --address 192.168.1.10:53` exits non-zero if the node isn't answering DNS. It queries a name
the node answers itself, so upstream problems don't affect it.

## Upgrading

Install the new package and restart. A brief DNS gap is expected, which is why devices should have a
second server. Back up first: database migrations run automatically, and downgrading after one isn't
supported yet.

## Changing settings later

Every setting except the data folder can be changed in the dashboard, under **Settings**. See
[Node settings](settings.md) for how this combines with the environment file, and how to recover.
