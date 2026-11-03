#!/usr/bin/env bash
# Spec section 3.3: dns-policy must not depend on Axum, a SQL implementation or the DNS stack.
set -euo pipefail

tree="$(cargo tree --package dns-policy --edges normal --prefix none --locked)"
if forbidden="$(grep -E '^(axum|hyper|sqlx|rusqlite|tokio|hickory-[a-z]+) ' <<<"$tree")"; then
    echo "dns-policy has forbidden dependencies:" >&2
    echo "$forbidden" >&2
    exit 1
fi
echo "dns-policy layering OK"
