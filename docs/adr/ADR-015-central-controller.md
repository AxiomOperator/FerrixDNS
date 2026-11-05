# ADR-015: Central controller

**Status:** Accepted  
**Date:** 2026-11-04

## Context

Managing several nodes means repeating every policy change on each one. Spec sections 3.6 and 5.3 describe
a controller. Its core invariant is that no DNS query waits for it.

## Decision

- **One binary.** `ferrixdns controller` runs the controller, in the same image and package as the node.
  There's less to build and deploy, and the dashboard is shared. The role comes back in the session, and the
  dashboard shows fleet pages or node pages from it.
- **SQLite, not PostgreSQL.** The spec expects PostgreSQL. A controller for dozens of nodes writes little, and
  SQLite keeps it to one container and one volume, using the storage code the project already has. Nothing in
  the node protocol depends on this, so it can change if fleets outgrow it.
- **Policy editing reuses the node API.** Each site has a `PolicyManager` serving no DNS, and an instance of
  the node API, reached at `/api/v1/sites/{id}/...` through an allow list of policy paths. This keeps node and
  site editing identical, including validation and revisions, instead of building a second policy model.
- **Signed requests instead of mTLS.** The spec allows either. A node signs each request's method, path, time
  and body hash with an Ed25519 key that never leaves it. It works through any TLS setup, including a proxy
  that ends TLS. Signatures are accepted for 5 minutes either side, and replaying one only repeats an idempotent
  report or a read.
- **Signed bundles.** The controller signs the exact manifest bytes, which pin each file's hash. A node needs
  only the controller's public key, from its token, so TLS or the controller's storage alone can't push it
  a policy. Generations only go up, and a rollback is a new generation.
- **The token carries trust.** It holds the controller's address, its signing key, and the fingerprint of a
  self-signed certificate. This answers the spec's open question of how a node first trusts its controller.
  Tokens last an hour by default, up to 7 days, longer than the spec's 10 minutes, because the first run of the
  deploy script builds the image. They still work only once, and only their hash is stored.
- **Short polling.** Nodes report every 10 seconds rather than holding a connection open. It's simple, works
  through anything that allows HTTPS, and doubles as the health signal.
- **Counts only.** Reports carry per-minute counts by result. Query names and client addresses stay on nodes.
- **Metrics live in the dashboard.** There's no Prometheus or other scrape endpoint. This replaces the series
  listed in spec section 7.3.

## Consequences

- Node settings such as upstreams stay with each node, because applying them needs a restart and they often
  differ per machine.
- A managed node's policy is read-only locally. A restart uses its newest stored revision, with no controller.
- Not built yet: roles and single sign-on, a global policy shared between sites, list update guards, signing key
  rotation and delta downloads. `docs/operations/controller.md` lists what operators should know.
