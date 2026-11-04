# ADR-001: Hickory forwarding first, recursion deferred

**Status:** Accepted  
**Date:** 2026-11-03

## Decision

FerrixDNS forwards queries and does not implement recursion. It uses `hickory-server` for listeners
and message encoding, and `hickory-proto` for message types. It does **not** use `hickory-resolver`.
The `dns-upstreams` crate is our own UDP/TCP client.

## Why

The spec needs ordered failover pools, per-route selection, and a cache that holds only upstream
answers so policy can run on every cache hit. Those need direct control of each upstream exchange,
and a resolver with its own cache gets in the way.

## Findings from reading `hickory-server` 0.26.3

- `RequestHandler` gives us full control of responses, and the server handles framing.
- The server answers malformed requests that have a readable header with FORMERR, silently drops
  shorter messages, and ignores messages with the response bit set.
- The UDP loop spawns one task per datagram with no limit. Admission control therefore belongs in
  our handler, and each rejected request must finish quickly.
- `Server::with_access` checks source networks before parsing the message body. Denying `0.0.0.0/0`
  and `::/0` and then allowing specific networks gives a default-deny resolver ACL.

## Consequences

- We own transaction matching, TCP fallback and timeouts, and must test them directly.
- Hickory is pre-1.0, so its API may change between releases. Keep the dependency in `dns-runtime`
  and `dns-upstreams`, and out of `dns-policy`.
- DNSSEC validation uses `hickory-net`'s `DnssecDnsHandle`, which is generic over a handle, on top of
  our pool and cache. Upstreams are asked with CD set, so the node validates independently. AD is only
  ever this node's own conclusion, and is cleared when validation is off.
- Encrypted upstreams use our own DoT and DoH transports, so failover, statistics and the cache work the
  same for every upstream type.
- Throughput was measured well above the 10,000 QPS target. See `docs/performance.md`.
- The UDP loop's unbounded task spawning held up in flood testing, because rejected and blocked requests
  finish quickly and upstream work is capped by the in-flight limit.
