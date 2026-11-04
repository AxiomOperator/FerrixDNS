#!/usr/bin/env bash
# Starts a local FerrixDNS node, serving both DNS and the dashboard.
#
#   scripts/start.sh                 Build the UI and start the node
#   scripts/start.sh --dev           Also run the Vite dev server, for UI hot reload
#   scripts/start.sh -- --allow ...  Pass everything after -- to `fx serve`
#
# Settings, with their defaults:
#   FX_DNS_LISTEN=127.0.0.1:5300   FX_WEB_LISTEN=127.0.0.1:8080
#   FX_UPSTREAM=1.1.1.1:53         FX_STATE_DIR=.ferrix-state
#   FX_VITE_PORT=5173
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

dns_listen="${FX_DNS_LISTEN:-127.0.0.1:5300}"
web_listen="${FX_WEB_LISTEN:-127.0.0.1:8080}"
upstream="${FX_UPSTREAM:-1.1.1.1:53}"
state_dir="${FX_STATE_DIR:-.ferrix-state}"
vite_port="${FX_VITE_PORT:-5173}"

dev=false
extra_args=()
while (($# > 0)); do
    case "$1" in
        --dev) dev=true ;;
        --) shift; extra_args=("$@"); break ;;
        -h | --help) sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown option: $1 (see --help)" >&2; exit 2 ;;
    esac
    shift
done

for tool in cargo pnpm; do
    if ! command -v "$tool" >/dev/null; then
        echo "$tool is required but isn't installed." >&2
        exit 1
    fi
done

if [[ ! -d frontend/node_modules ]]; then
    echo "==> Installing UI dependencies"
    pnpm --dir frontend install --frozen-lockfile
fi

echo "==> Building the UI"
pnpm --dir frontend build >/dev/null

echo "==> Building the node"
cargo build --package node-bin

fx=(target/debug/fx serve
    --listen "$dns_listen"
    --upstream "$upstream"
    --state-dir "$state_dir"
    --web-listen "$web_listen"
    ${extra_args[@]+"${extra_args[@]}"})

echo
echo "    DNS:        $dns_listen   (try: dig @${dns_listen%:*} -p ${dns_listen##*:} example.com)"
if [[ "$dev" == true ]]; then
    echo "    Dashboard:  http://localhost:$vite_port/   (with hot reload)"
else
    echo "    Dashboard:  http://$web_listen/"
fi
echo "    State:      $state_dir"
echo "    First run:  copy setup_token from the log below. Press Ctrl-C to stop."
echo

if [[ "$dev" != true ]]; then
    exec "${fx[@]}"
fi

pids=()
stop() {
    trap - EXIT INT TERM
    ((${#pids[@]} > 0)) && kill "${pids[@]}" 2>/dev/null
    wait 2>/dev/null || true
}
trap stop EXIT
trap 'exit 0' INT TERM

"${fx[@]}" &
pids+=($!)
(
    cd frontend
    export FX_WEB_LISTEN="$web_listen"
    exec ./node_modules/.bin/vite --port "$vite_port" --strictPort --clearScreen false
) &
pids+=($!)

# If either one stops, stop the other, so a failed start doesn't look like it's working.
wait -n
