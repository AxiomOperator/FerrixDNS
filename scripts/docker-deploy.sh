#!/usr/bin/env bash
# Builds the FerrixDNS container image and deploys it on this machine. Run it again to upgrade.
# The node's data and saved settings stay in a volume.
#
#   scripts/docker-deploy.sh                    Build, start, and wait until DNS answers
#   scripts/docker-deploy.sh --address 10.0.0.5 Serve on this address, not the detected one
#   scripts/docker-deploy.sh --no-build         Start the image that's already built
#   scripts/docker-deploy.sh --down             Stop the node, keeping its data
#   scripts/docker-deploy.sh --controller       Deploy a central controller, not a node
#   scripts/docker-deploy.sh --node-only        Deploy a node with no dashboard, managed by a
#                                               controller. Needs FERRIXDNS_ENROLL_TOKEN the first time
#
# Settings, with their defaults:
#   FERRIXDNS_ADDRESS=<this machine's main address>
#   FERRIXDNS_DNS_PORT=53                       FERRIXDNS_WEB_PORT=8443
#   FERRIXDNS_CONTROLLER_PORT=8444              FERRIXDNS_PUBLIC_URL=https://<address>:<port>
#   FERRIXDNS_ENROLL_TOKEN=<from the controller, under Nodes>
#   FERRIXDNS_UPSTREAM=<Cloudflare and Quad9 over TLS>
#   FERRIXDNS_ALLOW=<private networks, plus this machine's network if it isn't private>
#   FERRIXDNS_ENGINE=<docker if usable, otherwise podman>
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

COMPOSE_FILE=packaging/docker/compose.yaml
CONTAINER=ferrixdns
HEALTH_WAIT_SECONDS=30
DEFAULT_ALLOW=127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,::1/128,fc00::/7,fe80::/10

fail() {
    echo "Error: $*" >&2
    exit 1
}

build=true
down=false
role=node
while (($# > 0)); do
    case "$1" in
        --address)
            (($# >= 2)) || fail "--address needs a value"
            FERRIXDNS_ADDRESS="$2"
            shift
            ;;
        --no-build) build=false ;;
        --down) down=true ;;
        --controller) role=controller ;;
        --node-only) role=node-only ;;
        -h | --help) sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown option: $1 (see --help)" >&2; exit 2 ;;
    esac
    shift
done

engine="${FERRIXDNS_ENGINE:-}"
if [[ -z "$engine" ]]; then
    if command -v docker >/dev/null && docker info >/dev/null 2>&1; then
        engine=docker
    elif command -v podman >/dev/null; then
        engine=podman
    elif command -v docker >/dev/null; then
        fail "this user can't reach Docker. Run: sudo $0"
    else
        fail "this needs Docker or Podman, and neither is installed."
    fi
fi
"$engine" info >/dev/null 2>&1 || fail "$engine isn't reachable. Is it running, and is this user allowed to use it?"

# `podman compose` otherwise prefers Docker's plugin, which needs Podman's API socket to be turned on.
if [[ "$engine" == podman ]] && command -v podman-compose >/dev/null; then
    export PODMAN_COMPOSE_PROVIDER="${PODMAN_COMPOSE_PROVIDER:-podman-compose}"
fi
case "$role" in
    controller)
        COMPOSE_FILE=packaging/docker/compose.controller.yaml
        CONTAINER=ferrixdns-controller
        ;;
    node-only) COMPOSE_FILE=packaging/docker/compose.node-only.yaml ;;
esac

"$engine" compose version >/dev/null 2>&1 || fail "$engine has no compose command. Install the compose plugin."

compose() {
    "$engine" compose -f "$COMPOSE_FILE" "$@"
}

if [[ "$down" == true ]]; then
    compose down
    echo "==> Stopped. Its data is still in its volume."
    exit 0
fi

is_running() {
    [[ "$("$engine" inspect --format '{{.State.Running}}' "$CONTAINER" 2>/dev/null)" == true ]]
}

address="${FERRIXDNS_ADDRESS:-}"
if [[ -z "$address" ]]; then
    address="$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p')"
    [[ -n "$address" ]] || fail "couldn't detect this machine's address. Use --address."
fi
case "$address" in
    0.0.0.0) fail "use a specific address, because it's also where people reach the dashboard." ;;
    *:*) fail "use an IPv4 address here. IPv6 can be added in the dashboard afterwards." ;;
esac
ip -o addr show | grep -qF " $address/" || fail "$address isn't an address of this machine."

dns_port="${FERRIXDNS_DNS_PORT:-53}"
web_port="${FERRIXDNS_WEB_PORT:-8443}"
controller_port="${FERRIXDNS_CONTROLLER_PORT:-8444}"
export FERRIXDNS_ADDRESS="$address" FERRIXDNS_DNS_PORT="$dns_port" FERRIXDNS_WEB_PORT="$web_port"
export FERRIXDNS_CONTROLLER_PORT="$controller_port"
case "$role" in
    node) ports=("$dns_port" "$web_port") ;;
    node-only) ports=("$dns_port") ;;
    controller) ports=("$controller_port") ;;
esac

# The node only serves loopback and private networks by default. If this machine's own network is
# something else, add just that network, or every device on it would be refused.
network_of() {
    local cidr length octets value mask
    cidr="$(ip -o -4 addr show | awk -v a="$1" '{ split($4, p, "/"); if (p[1] == a) { print $4; exit } }')"
    length="${cidr#*/}"
    IFS=. read -r -a octets <<<"${cidr%/*}"
    value=$(((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]))
    mask=$(((0xffffffff << (32 - length)) & 0xffffffff))
    value=$((value & mask))
    echo "$((value >> 24 & 255)).$((value >> 16 & 255)).$((value >> 8 & 255)).$((value & 255))/$length"
}
if [[ "$role" != controller ]]; then
case "$address" in
    127.* | 10.* | 192.168.* | 169.254.* | 172.1[6-9].* | 172.2[0-9].* | 172.3[01].*) ;;
    *)
        if [[ -z "${FERRIXDNS_ALLOW:-}" ]]; then
            network="$(network_of "$address")"
            export FERRIXDNS_ALLOW="$DEFAULT_ALLOW,$network"
            echo "==> $network isn't a private network, so it's being allowed explicitly"
        fi
        ;;
esac
fi

# Without a root engine, a container on the host's network can't use a port below this.
lowest_open_port="$(cat /proc/sys/net/ipv4/ip_unprivileged_port_start 2>/dev/null || echo 1024)"
if [[ "$role" != controller ]] && ((dns_port < lowest_open_port)) && "$engine" info 2>/dev/null | grep -qi 'rootless.*true\|name=rootless'; then
    fail "$engine is running without root, so it can't use port $dns_port with host networking.
Run: sudo $0"
fi

# A running node holds its own ports, so there's only something to check before the first start.
if command -v ss >/dev/null && ! is_running; then
    for port in "${ports[@]}"; do
        holders="$(ss -Hlntu "sport = :$port" | awk -v a="$address" '{ n = $5; sub(/:[^:]*$/, "", n); sub(/%.*/, "", n)
            if (n == a || n == "0.0.0.0" || n == "*" || n == "[::]") print $5 }')"
        if [[ -n "$holders" ]]; then
            fail "port $port is already in use at $address, by:
$holders"
        fi
    done
fi

if [[ "$build" == true ]]; then
    echo "==> Building the image"
    # Podman's default image format would drop the image's health check.
    if [[ "$engine" == podman ]]; then
        podman build --format docker -f packaging/docker/Dockerfile -t ferrixdns .
    else
        docker build -f packaging/docker/Dockerfile -t ferrixdns .
    fi
fi

echo "==> Starting the $role on $address"
# Always a new start, so the log read below describes this deployment.
compose up -d --no-build --force-recreate

if [[ "$role" == controller ]]; then
    echo "==> Waiting for the controller to answer"
    health=(/usr/bin/ferrixdns health --controller "$address:$controller_port")
else
    echo "==> Waiting for DNS to answer"
    health=(/usr/bin/ferrixdns health)
fi
for ((second = 0; ; second++)); do
    if health_output="$("$engine" exec "$CONTAINER" "${health[@]}" 2>&1)"; then
        break
    fi
    if ((second >= HEALTH_WAIT_SECONDS)); then
        echo "Error: it didn't start answering within $HEALTH_WAIT_SECONDS seconds." >&2
        echo "$health_output" >&2
        echo "Its log:" >&2
        "$engine" logs --tail 20 "$CONTAINER" >&2 || true
        exit 1
    fi
    sleep 1
done

# Read these from this start's part of the log, because saved settings can override the address and
# a setup token is only valid until the administrator exists.
log="$("$engine" logs "$CONTAINER" 2>&1)"
url="$(sed -n 's/.*web UI ready url=\([^ ]*\).*/\1/p' <<<"$log" | tail -n 1)"
token="$(awk '/web UI ready/ { token = "" } match($0, /setup_token=[0-9a-f]+/) { token = substr($0, RSTART + 12, RLENGTH - 12) } END { print token }' <<<"$log")"
fingerprint="$(sed -n 's/.*self-signed certificate.*sha256=\([0-9a-f]*\).*/\1/p' <<<"$log" | tail -n 1)"

echo
if [[ "$role" != controller ]]; then
    echo "    DNS:         $address:$dns_port   (try: dig @$address -p $dns_port example.com)"
fi
if [[ "$role" != node-only ]]; then
    echo "    Dashboard:   ${url:-unknown, check: $engine logs $CONTAINER}"
    if [[ -n "$fingerprint" ]]; then
        echo "    Certificate: self-signed, so browsers warn. Its sha256 is $fingerprint"
    fi
    if [[ -n "$token" ]]; then
        echo "    Setup token: $token"
    fi
fi
echo "    Logs:        $engine logs -f $CONTAINER"
echo
case "$role" in
    node) echo "    Settings saved in the dashboard win over the address and upstreams used here." ;;
    controller)
        echo "    Nodes reach this at ${FERRIXDNS_PUBLIC_URL:-https://$address:$controller_port}. Set FERRIXDNS_PUBLIC_URL if"
        echo "    they use another name or address, before creating tokens."
        ;;
    node-only)
        echo "    This node has no dashboard. Manage it on its controller."
        if [[ -n "${FERRIXDNS_ENROLL_TOKEN:-}" ]]; then
            echo "==> Joining the controller"
            for ((second = 0; second < HEALTH_WAIT_SECONDS; second++)); do
                log="$("$engine" logs "$CONTAINER" 2>&1)"
                if grep -q "joined the controller" <<<"$log"; then
                    echo "    Joined. It's now listed on the controller, under Nodes."
                    break
                fi
                if grep -q "couldn't join its controller" <<<"$log"; then
                    grep "couldn't join its controller" <<<"$log" | tail -n 1 >&2
                    echo "Error: DNS is running, but this node isn't getting policy from the controller." >&2
                    exit 1
                fi
                sleep 1
            done
            if ((second >= HEALTH_WAIT_SECONDS)); then
                echo "    Not joined yet. If it joined before, that's expected. Otherwise check: $engine logs $CONTAINER"
            fi
        fi
        ;;
esac

warn_about_firewall() {
    local port="$1" protocol="$2" zone
    if command -v firewall-cmd >/dev/null && [[ "$(firewall-cmd --state 2>/dev/null)" == running ]]; then
        zone="$(firewall-cmd --get-zone-of-interface="$interface" 2>/dev/null || firewall-cmd --get-default-zone 2>/dev/null)" || return 0
        if ! firewall-cmd --zone="$zone" --query-port="$port/$protocol" >/dev/null 2>&1 &&
            ! { [[ "$port" == 53 ]] && firewall-cmd --zone="$zone" --query-service=dns >/dev/null 2>&1; }; then
            echo
            echo "Warning: the firewall blocks port $port/$protocol, so other devices can't reach it. To open it:"
            echo "    sudo firewall-cmd --permanent --zone=$zone --add-port=$port/$protocol && sudo firewall-cmd --reload"
        fi
    elif command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then
        if ! ufw status 2>/dev/null | grep -qE "^$port(/$protocol)?[[:space:]]+ALLOW"; then
            echo
            echo "Warning: the firewall may block port $port/$protocol, so other devices can't reach it. To open it:"
            echo "    sudo ufw allow $port/$protocol"
        fi
    fi
}
interface="$(ip -o -4 addr show | awk -v a="$address" '{ split($4, p, "/"); if (p[1] == a) { print $2; exit } }')"
if [[ "$role" != controller ]]; then
    warn_about_firewall "$dns_port" udp
    warn_about_firewall "$dns_port" tcp
fi
case "$role" in
    node) warn_about_firewall "$web_port" tcp ;;
    controller) warn_about_firewall "$controller_port" tcp ;;
esac
if ip -o -4 addr show | grep -F " $address/" | grep -q dynamic; then
    echo
    echo "Warning: $address comes from DHCP, so it can change. Others point at this address, and this"
    echo "listens only on it, so give this machine a fixed address."
fi
