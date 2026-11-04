# ADR-014: Node settings from the dashboard

**Status:** Accepted  
**Date:** 2026-11-04

## Context

Addresses, upstreams, cache size, TLS and similar settings could only be changed with command-line
options or environment variables. Operators expect to manage all of them in the dashboard. Some of them
can also cut off the dashboard itself, or stop the node from starting.

## Decision

- **Applying.** A change restarts the process in place with `exec`. This reuses the normal startup path
  and its checks for every setting, instead of giving each one a separate live-reload path. It behaves
  the same under systemd, in a container and in a shell, and it never leaves stale tasks running. The cost
  is a short DNS outage on save, which the dashboard states before saving.
- **Storage.** Only values that differ from the startup values are saved, in `node-settings.json` in the
  state directory. It's a plain file so it can be read before anything else starts, and so that a damaged
  file can't stop DNS: it's logged and ignored. It's left out of backups, because it describes one machine.
- **Precedence.** Saved values win over the command line and environment. Otherwise the packaged service,
  whose environment file sets the addresses and upstreams, could never be changed from the dashboard.
  The node logs which values are overridden, and `ferrixdns admin reset-settings` removes them.
- **Rollback.** A change starts as a trial holding the previous values. If startup fails during a trial,
  the previous values return. A change to dashboard access must also be confirmed within 2 minutes.
  Failures outside a trial don't discard anything, so a slow network at boot can't lose settings.
- **The state directory can move, but the settings file can't.** The file stays in the folder given by
  `--state-dir`, which is the only place the node can look when it starts. Moving copies the data at the
  next start, database last, so the database's presence means the copy finished. The old folder is kept.

## Consequences

- Saving takes DNS down for as long as startup takes, including compiling lists.
- A blocking pause doesn't survive a restart, so saving ends it. Blocking coming back is the safe direction.
- File paths are entered by an administrator and read by the node, so they're limited to regular files of
  a bounded size, and errors don't repeat file contents.
