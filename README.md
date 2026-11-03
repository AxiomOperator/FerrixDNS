# FerrixDNS

A self-hostable, Rust-native DNS filtering and management platform. The design is in
[`docs/Rust_DNS_Platform_Engineering_Specification.md`](docs/Rust_DNS_Platform_Engineering_Specification.md),
and decisions are recorded in [`docs/adr/`](docs/adr/).

**Status:** early development, not ready for production. `fx serve` filters and forwards DNS over
UDP and TCP using a policy file. There's no cache, blocklist downloads, query log, API or dashboard
yet.

## Try it

```sh
cargo run -p node-bin -- serve --listen 127.0.0.1:5300 --upstream 1.1.1.1:53 \
    --policy examples/policy.toml --state-dir /tmp/ferrix-state
```

Then, in a second terminal because `fx serve` stays in the foreground:

```sh
dig @127.0.0.1 -p 5300 example.com          # forwarded
dig @127.0.0.1 -p 5300 a.tracker.example    # blocked by the example policy: NXDOMAIN
```

Avoid port 5353, which is reserved for mDNS and is usually taken by Avahi or systemd-resolved. Port
53 needs extra privileges.

Only loopback and private source addresses are served by default. Use `--allow <CIDR>` to replace
that list.

## Policy

[`examples/policy.toml`](examples/policy.toml) shows every option.

```sh
fx policy validate my-policy.toml    # check a file without applying it
kill -HUP "$(pidof fx)"              # apply changes without restarting
```

- A bad file never replaces the active policy. A failed reload is logged and changes nothing.
- With `--state-dir`, each valid policy is stored durably. If the file is later missing or invalid,
  the node restarts on the newest stored policy that still works. The last three are kept.
- If `--policy` is set but invalid and nothing is stored, `fx` refuses to start instead of serving
  unfiltered DNS.
- Rules with `expires_at` stop applying at that time, with no restart or reload.

## Checks

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
scripts/check-layering.sh
```

To measure the policy engine with a large list:

```sh
cargo run --release -p dns-policy --example bench_policy -- 1000000
```
