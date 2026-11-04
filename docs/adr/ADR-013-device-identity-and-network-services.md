# ADR-013: Device identity, conditional forwarding, query limits and NTP

**Status:** Accepted  
**Date:** 2026-11-03

## Decision

- **The DNS path only reads a published device table.** A background task reads the neighbor table
  over netlink and does reverse lookups. A query waits up to 200 ms on an unknown address, only when
  policy has clients that depend on a MAC address or host name.
- **Identity order is exact address, MAC address, host name, longest network.** It extends "narrowest
  scope wins" from ADR-003. These identifiers aren't authentication.
- **Reverse lookups never use the default upstreams.** They only reach local records and forward zones,
  so private addresses don't leak.
- **Forward zones fail closed.** A failed server gives SERVFAIL, never a retry with public upstreams.
  Cache keys include the route, so answers can't cross between servers after a policy change.
- **A pause is memory-only and on the monotonic clock.** Failure modes end a pause and never extend
  it. Emergency denies still apply, and CNAME targets get the same emergency-only check.
- **Query limits run first, and a flood is reported once a minute.** Otherwise the limited client could
  push real history out of the query log. They're on by default at 3,000 a minute, which is high enough
  to avoid false alarms. Loopback is exempt, so local tools and load tests aren't affected.
- **NTP serves the host's clock and doesn't discipline it.** Replies report the kernel's sync state. Only
  this needs `unsafe`, for one read-only `adjtimex` call, so it's isolated in the `node-ntp` crate.

## Alternatives rejected

- Reading ARP on each query, because it adds system calls and latency to the hot path.
- Parsing `ip neigh`, because container images don't include it. `/proc/net/arp` has no IPv6.
- Keeping pause state in the policy document, because that creates revisions for a temporary state, fails
  in file-managed mode, and would survive a restart.
- An SNTP client that steers the served time, because that duplicates a time service and can disagree
  with the machine's own clock.

## Consequences

The service unit needs `AF_NETLINK`, and it drops `ProtectClock`, since that also blocks reading clock
state. It allows `adjtimex` and `clock_adjtime`, and keeps `CAP_SYS_TIME` out of its capabilities, so it
still can't set the clock. Filtered system calls now fail with `EPERM` rather than killing the process,
so that a feature's system call can't take DNS down. Anything that adds a system call has to be tested
under the real unit, and with the code path that makes the call actually running.
