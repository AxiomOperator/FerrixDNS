# Node settings

Every setting of a node can be changed in the dashboard, under **Settings**.

| Tab | Settings | Startup option |
| --- | --- | --- |
| DNS | Upstream servers, DNSSEC validation, time limits, requests in flight | `--upstream`, `--dnssec-validate`, `--attempt-timeout-ms`, `--query-timeout-ms`, `--max-concurrent-requests` |
| DNS | DNS addresses, networks allowed to query | `--listen`, `--allow` |
| DNS | Cache memory, longest times to keep answers | `--cache-mib`, `--cache-max-ttl`, `--cache-negative-ttl` |
| Dashboard | Address, names, TLS, plain HTTP on a network | `--web-listen`, `--web-host`, `--web-tls-self-signed`, `--web-tls-cert`, `--web-tls-key`, `--web-insecure-remote` |
| System | NTP addresses | `--ntp-listen` |
| System | Data folder, log filter, policy file, list downloads from private addresses | `--state-dir`, `RUST_LOG`, `--policy`, `--allow-private-list-urls` |

The **Blocking and logs** tab holds the block response, query limit and query log settings. They're part of
the policy, so they apply immediately, without a restart, and are included in backups. The **Account** tab
holds your password and theme.

## How startup values and saved values combine

The command line and environment give the starting values. The dashboard saves only what differs from
them, in `node-settings.json` in the data folder:

- A value changed in the dashboard wins over the command line and environment. The node logs which
  settings this applies to when it starts.
- A value nobody changed in the dashboard keeps following the command line and environment.
- **Use startup values** on the Settings page removes every saved change.

Backups leave this file out, because addresses and certificate paths belong to one machine.

The folder given by `--state-dir` always holds `node-settings.json`, even after the data moves, because
that's where the node looks when it starts. So that folder must stay in place. Commands such as `ferrixdns
backup` and `ferrixdns admin reset-password` still take that folder and follow the move.

## Moving the data folder

The new folder must be empty, or already hold this node's data, which is then used as it is. Saving copies
the data to it at the restart, and the old folder stays as it was, so delete it yourself once you're happy.

The service must be allowed to write there. The packaged systemd unit only allows its own state directory, so
for another folder add `ReadWritePaths=` in an override. A container needs a volume there. Otherwise saving
explains the problem and nothing changes.

If you undo a change, or one undoes itself, the node returns to the old folder, and anything written to the
new one since the move stays behind there.

## What saving does

Saving restarts the node in place, keeping its process ID, environment and capabilities. DNS stops
answering until it's back, which takes as long as compiling your lists. A blocking pause ends and the
cache starts empty. Query counts from the last 2 seconds may be lost.

## What protects you from a bad change

1. **Before saving**, the node checks every value and tries to open each new address, so a port that's
   taken is an error message and nothing restarts.
2. **While restarting**, if the node can't start with the change, it restores the previous settings and
   restarts. The Settings page says what went wrong.
3. **After a change to dashboard access**, you have 2 minutes to choose **Keep change** in the dashboard.
   If you can't reach it, the previous settings come back by themselves.

Settings that already worked are never discarded because of a failure at boot, because an address can
be missing for a moment while a machine starts. The node keeps retrying under its service manager and
logs how to recover.

## Recovering from the command line

If saved settings stop a node from starting, or you can't reach the dashboard:

```sh
ferrixdns admin reset-settings --state-dir /var/lib/ferrixdns
systemctl restart ferrixdns
```

The node then uses its command line and environment again. Rules, lists and accounts aren't affected,
unless you had moved the data folder: the node then returns to the original folder and the data in it.

## In containers

The node's health check reads any saved DNS address, so it follows a change made in the dashboard.

Published ports (`docker run -p`) are the one thing the dashboard can't change, because the host's container
runtime owns them, not the node. If a container uses published ports and you change an address's port, also
change the published port. The packaged `compose.yaml` uses host networking, so it isn't affected.
