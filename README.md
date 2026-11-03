# FerrixDNS

A self-hostable, Rust-native DNS filtering and management platform. The design is in
[`docs/Rust_DNS_Platform_Engineering_Specification.md`](docs/Rust_DNS_Platform_Engineering_Specification.md),
and decisions are recorded in [`docs/adr/`](docs/adr/).

**Status:** early development, not ready for production. `fx serve` forwards DNS over UDP and TCP.
It does not filter queries yet: the policy engine exists as a library but isn't wired into the server.

## Try it

```sh
cargo run -p node-bin -- serve --listen 127.0.0.1:5300 --upstream 1.1.1.1:53
dig @127.0.0.1 -p 5300 example.com
```

Run `dig` in a second terminal, because `fx serve` stays in the foreground. Avoid port 5353, which is
reserved for mDNS and is usually taken by Avahi or systemd-resolved. Port 53 needs extra privileges.

Only loopback and private source addresses are served by default. Use `--allow <CIDR>` to replace
that list.

## Checks

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
scripts/check-layering.sh
```
