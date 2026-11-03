# ADR-012: Local config revisions, table projections and layered snapshots

**Status:** Accepted  
**Date:** 2026-11-03

## Decision

- The active revision's document is authoritative. Tables such as `rules` are projections, rewritten
  in the same transaction that activates a revision.
- There are no local drafts. A successful config write validates the change, commits a new revision
  and publishes it before returning.
- A rollback copies an earlier revision forward as a new revision.
- `PolicySnapshot` has a **list layer** (compiled subscribed lists) and a **rule overlay** (rules,
  groups, client mappings and local exceptions). A rule edit rebuilds only the overlay.
- A timer publishes a new overlay at the earliest `expires_at`, so the hot path reads no clock to
  check rule validity. Expiry doesn't create a revision and is recorded in the audit log.

## Why

If rules lived only in tables and revisions only in JSON documents, a rollback might not restore
rules. Rule edits and temporary exceptions also need to take effect quickly, which rules out
recompiling a list of millions of domains each time.

## Consequences

- A success response means the change is active on that node.
- List content changes are asynchronous and return `202 Accepted` with a job ID.
- In managed mode, controller-owned rows come from the applied bundle. Rows with `origin = 'local'`
  hold time-bounded exceptions and survive bundle activation.
