# FerrixDNS

A self-hostable, Rust-native DNS filtering and management platform. The design is in
[`docs/Rust_DNS_Platform_Engineering_Specification.md`](docs/Rust_DNS_Platform_Engineering_Specification.md),
and decisions are recorded in [`docs/adr/`](docs/adr/).

**Status:** early development, not yet production-tested. A standalone node filters and caches DNS,
serves local zones, supports encrypted upstreams, conditional forwarding and DNSSEC validation, and
has a web dashboard with backup and restore. The central controller for managing many nodes isn't
built yet.

- [Installing and running a node](docs/operations/install.md): packages, containers, TLS and upgrades
- [Backup and restore](docs/operations/backup.md)
- [Network features](docs/operations/network.md): pausing, device identity, forwarding, query limits and NTP
- [Performance measurements](docs/performance.md)

## Try the dashboard

You need Rust, Node.js and pnpm. This builds everything and starts a node serving DNS and the
dashboard:

```sh
scripts/start.sh
```

`scripts/start.sh --help` lists its settings, such as the ports and upstream server.

1. Find the `setup_token` in the node's log. It's printed only until an administrator exists.
2. Open <http://127.0.0.1:8080> and create your administrator with that token.
3. Send it some DNS from a second terminal, and watch it appear under **Query Explorer**:

   ```sh
   dig @127.0.0.1 -p 5300 example.com
   ```

4. To see blocking, add a rule under **Rules**, or add a list under **Sources**, such as
   `https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts` in hosts file format.

Avoid port 5353, which is reserved for mDNS and is usually taken by Avahi or systemd-resolved. Port
53 needs extra privileges. Only loopback and private source addresses are served by default. Use
`--allow <CIDR>` to replace that list.

The dashboard stays on loopback by default. The [install guide](docs/operations/install.md) covers
reaching it from other devices over TLS.

Lost your password? This sets a new one from standard input and ends all sessions:

```sh
ferrixdns admin reset-password --state-dir .ferrix-state --username admin
```

## Changing settings

Every setting is in the dashboard, under **Settings**: addresses, upstreams, DNSSEC, the cache, TLS, the
time server, the data folder, logging and more. The command line and environment only give the starting
values. Saving these restarts the node for a few seconds. If a change would stop the node starting or cut off the dashboard, the previous
settings come back by themselves. See [Node settings](docs/operations/settings.md).

## Managing policy

With `--state-dir` and no `--policy`, you manage policy in the dashboard. Each change is validated
and stored before it applies, and **System** can restore any of the last three revisions.

You can also manage policy in a file. The dashboard is then read-only for policy, so the two can't
disagree. [`examples/policy.toml`](examples/policy.toml) shows the options.

```sh
ferrixdns serve --listen 127.0.0.1:5300 --upstream 1.1.1.1:53 --policy my-policy.toml --state-dir .ferrix-state
ferrixdns policy validate my-policy.toml    # check a file without applying it
kill -HUP "$(pidof ferrixdns)"              # apply changes without restarting
```

- A bad file never replaces the active policy. A failed reload is logged and changes nothing.
- If the file is later missing or invalid, the node restarts on the newest stored policy that works.
- If `--policy` is set but invalid and nothing is stored, `ferrixdns` refuses to start instead of serving
  unfiltered DNS.

## Query data and privacy

By default the node keeps each query, including which device asked, for 7 days or 2 GiB, whichever
comes first. It stays on the node. You can reduce this under **Settings**.

## Development

```sh
scripts/start.sh --dev               # the node, plus the UI with hot reload on port 5173
pnpm --dir frontend gen:api          # regenerate UI types after changing the API
```

Checks, which CI also runs:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
scripts/check-layering.sh
pnpm --dir frontend typecheck
pnpm --dir frontend build && cargo build -p node-bin && pnpm --dir frontend test:e2e
```

The browser tests drive the real `ferrixdns` binary with real DNS queries, and run accessibility checks on
each page. They need Playwright's browser: `pnpm --dir frontend exec playwright install chromium`.

To measure throughput and latency, or the policy engine with a large list:

```sh
scripts/load_test.py
cargo run --release -p dns-policy --example bench_policy -- 1000000
```

## License

FerrixDNS is available under either of these licenses, at your choice:

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

Unless you say otherwise, any contribution you submit for inclusion is dual licensed the same way,
with no additional terms.
