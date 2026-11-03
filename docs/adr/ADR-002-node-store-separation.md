# ADR-002: Node config, snapshot and telemetry store separation

**Status:** Accepted  
**Date:** 2026-11-03

## Decision

A node keeps three stores:

| Store | Contents | On failure |
|---|---|---|
| `config.db` | Revisions, rules, lists, clients, zones, local audit events | DNS keeps serving the loaded policy; config writes return 503 |
| Snapshot files | Checksummed list artifacts and compiled snapshots | Fall back to an earlier known-good snapshot |
| `telemetry/` | `rollups.db` and daily `queries-YYYY-MM-DD.db` files | DNS keeps serving; drops are counted; the store is recreated |

The controller's PostgreSQL database is authoritative for managed data. It never changes node
storage directly. Nodes receive signed bundles and acknowledge them.

## Query history

The default is full local history, capped at 7 days and 2 GiB, whichever is reached first. It is
shown in the setup wizard. Retention deletes whole segment files, and the UI shows the window
actually retained.

## Why

With one database, query-log growth or corruption could block config commits or stop a node from
booting. At 10,000 QPS, 7 days is about 6 billion rows, so a single ever-growing table can't be the
default design.

## Consequences

- There are no foreign keys across stores, so references from telemetry are soft.
- `seq` is assigned by the telemetry writer so it stays monotonic across segment files.
- Backups exclude telemetry by default.
- The 150 bytes per event estimate behind the 2 GiB default must be measured in Phase 2.
