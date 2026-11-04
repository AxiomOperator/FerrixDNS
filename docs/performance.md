# Performance

These are measurements from one machine, not a published benchmark or a promise. The load generator,
upstream and node all shared the machine's 16 CPUs, so they competed with each other. The harness
doesn't yet cover the full profile in spec section 8.6, such as slow CPUs, TCP mixes or NIC limits.

Reproduce them with `scripts/load_test.py`, which builds a release binary and runs against a scripted
upstream on loopback.

## DNS under load

Release build, 1,000,000-entry blocklist, default settings, with full query logging on.

| Scenario | QPS | p50 | p95 | p99 | Lost |
|---|---:|---:|---:|---:|---:|
| Max rate: 95% cacheable, 5% unique | 147,490 | 0.35 ms | 0.89 ms | 1.32 ms | 0 |
| Max rate: 50% blocked, 45% cacheable | 145,380 | 0.35 ms | 0.89 ms | 1.32 ms | 0 |
| Max rate: all unique, no cache hits | 92,954 | 0.59 ms | 1.24 ms | 2.80 ms | 0 |
| Paced 10,000 QPS: mixed | 10,002 | 0.34 ms | 0.86 ms | 1.83 ms | 0 |
| Paced 1,000 QPS: mixed | 1,004 | 0.36 ms | 0.70 ms | 1.65 ms | 0 |
| Paced 10,000 QPS, list recompiling throughout | 10,000 | 0.37 ms | 0.98 ms | 2.01 ms | 0 |

Latency here includes the generator's own scheduling on a shared machine, so the cache-hit target of
p99 under 5 ms is met with room to spare.

- **Query log:** no events were dropped at 10,000 QPS. At maximum rate about 1.4 million of 3.3 million
  detailed events were dropped by design, with counters still accurate and DNS unaffected.
- **Startup:** ready in 0.66 s, including compiling the 1M-entry list.
- **Memory:** about 300 MiB RSS at the end of these runs, with the 64 MiB cache full. It reached about
  370 MiB while a list recompiled repeatedly.

## Under a 1 GiB memory limit

The container image, capped with `--memory=1g --memory-swap=1g`, at 5,000 QPS for 25 seconds with the
list recompiling about every 1 to 2 seconds throughout. It still had this machine's 16 fast CPUs, so
this tests memory limits and not a small device's speed.

| Generated list | Ready in | p99 | Timeouts | Recompiles | Peak memory | Out of memory |
|---:|---:|---:|---:|---:|---:|---|
| 1,000,000 | 0.66 s | 2.99 ms | 0 | 20 | 201 MB | No |
| 5,000,000 | 3.18 s | 2.75 ms | 0 | 10 | 441 MB | No |

## Overload

Against an upstream taking 500 ms, with 6,000 concurrent clients and the 4,096 in-flight limit:

- Excess load was shed immediately as SERVFAIL (958,084 of them), and no client timed out.
- Afterward the node had 24 threads and 29 open files, so nothing leaked.
- Blocked queries kept being answered, because they don't need upstream capacity.

UDP bursts depend on the socket buffer. The node asks for 8 MiB, which the kernel caps at
`net.core.rmem_max`, so raising that sysctl helps on busy nodes.

## Blocklist memory

Lists are stored as finite state transducers, which share common prefixes and suffixes. This replaced
hash maps, which used about 651 MiB for 5M domains.

| List | Entries | Artifact | Index | Peak while compiling | Lookup p99 |
|---|---:|---:|---:|---:|---:|
| hagezi Ultimate, real domains | 286,890 | 6 MiB | about 15 MiB | about 28 MiB | 215 ns |
| Generated | 1,000,000 | 26 MiB | about 14 MiB | about 63 MiB | 527 ns |
| Generated | 5,000,000 | 137 MiB | about 40 MiB | about 291 MiB | 740 ns |

These are process memory growth, so small lists include allocator overhead. Generated names are
unusually regular and compress better than real ones, so use the real list's row for capacity planning.
It suggests a real 5M-domain list would use a few hundred MiB rather than 40 MiB, which is an estimate
to confirm with a list that size. Measure with:

```sh
cargo run --release -p dns-policy --example bench_policy -- 0 path/to/domains.txt
```

The old and new index coexist during an update, and the peak above is on top of that.
