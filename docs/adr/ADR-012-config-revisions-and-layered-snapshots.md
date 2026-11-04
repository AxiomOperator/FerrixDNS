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

## Current implementation

DNS-005 implements the snapshot and durability parts, with a policy file standing in for the future
API and `config.db`:

- A revision is the SHA-256 of the policy file's bytes. Each valid file is stored in
  `<state-dir>/policy/`, with write, fsync and atomic rename, and the last three are kept.
- Revisions store the **source document, not compiled indexes**, and are recompiled at boot. The
  compiled format is still open (spec section 13), and boot time on large lists needs measuring.
- If the file is missing or invalid at boot, the newest stored revision that verifies and compiles
  is used. If `--policy` was given and nothing usable exists, `fx` refuses to start. This is a
  provisional answer to the boot-behavior question in spec section 13.
- A SIGHUP reload that fails leaves the active policy unchanged, and rule edits reuse the compiled
  list layer when lists are unchanged.
- If a valid policy can't be persisted, for example on a full disk, it still activates and an error
  is logged, because DNS must keep working (FR-010).

The API works the same way: each change validates, compiles and durably stores a new revision before
it publishes and returns. A policy file makes the API read-only, so the file and the dashboard can't
disagree about which one is authoritative.

Table projections aren't implemented, because nothing reads them yet. Policy lives only in revision
files, and `config.db` holds accounts, sessions, list fetch state and the audit log. A downloaded
list's content is pinned in the revision by hash, so a rollback restores exactly what was enforced.

## Consequences

- A success response means the change is active on that node.
- List content changes are asynchronous and return `202 Accepted` with a job ID.
- In managed mode, controller-owned rows come from the applied bundle. Rows with `origin = 'local'`
  hold time-bounded exceptions and survive bundle activation.
