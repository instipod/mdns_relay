#!/bin/sh
# Confirms that real Avahi clients work through the relay, and only with a rule.
# Must run as root, such as in a privileged container.
set -eu

SERVICE_TYPE=_relaytest._tcp
RULES_FILE=$(mktemp -d)/rules.json
RELAY_PID=""

cleanup() {
    [ -n "$RELAY_PID" ] && kill "$RELAY_PID" 2>/dev/null || true
    for ns in client provider relay; do
        ip netns pids "$ns" 2>/dev/null | xargs -r kill 2>/dev/null || true
        ip netns del "$ns" 2>/dev/null || true
    done
}
trap cleanup EXIT

for ns in client provider relay; do
    ip netns add "$ns"
    ip netns exec "$ns" ip link set lo up
    ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=0
    ip netns exec "$ns" sysctl -qw net.ipv6.conf.default.disable_ipv6=0
done

ip link add c0 type veth peer name r-client
ip link set c0 netns client
ip link set r-client netns relay
ip link add p0 type veth peer name r-provider
ip link set p0 netns provider
ip link set r-provider netns relay

ip netns exec client ip addr add 10.0.1.2/24 dev c0
ip netns exec client ip link set c0 up
ip netns exec relay ip addr add 10.0.1.1/24 dev r-client
ip netns exec relay ip link set r-client up
ip netns exec relay ip addr add 10.0.2.1/24 dev r-provider
ip netns exec relay ip link set r-provider up
ip netns exec provider ip addr add 10.0.2.2/24 dev p0
ip netns exec provider ip link set p0 up

# Each Avahi instance gets its own /run, D-Bus and hostname. The command runs in
# a private mount and UTS namespace for that.
in_avahi() {
    ns=$1
    shift
    ip netns exec "$ns" unshare -m -u sh -c "
        hostname avahi-$ns
        mount -t tmpfs tmpfs /run
        mkdir -p /run/dbus /run/avahi-daemon
        chown messagebus /run/dbus 2>/dev/null || true
        dbus-daemon --system --fork
        avahi-daemon --no-drop-root --no-chroot --no-rlimits --daemonize
        sleep 2
        $*
    "
}

in_avahi provider "avahi-publish -s RelayedService $SERVICE_TYPE 8123 k=v" &
sleep 8

browse() {
    in_avahi client "timeout 12 avahi-browse -rpt $SERVICE_TYPE 2>/dev/null || true"
}

# Avahi on the relay host holds port 5353 as root, while the relay runs as an
# unprivileged user. This covers both coexistence and running without root.
in_avahi relay "sleep 300" &
sleep 4

chmod 777 "$(dirname "$RULES_FILE")"
ip netns exec relay setpriv --reuid=65534 --regid=65534 --clear-groups python -m mdns_relay \
    --rules-file "$RULES_FILE" --interface r-client --interface r-provider &
RELAY_PID=$!
sleep 3
kill -0 "$RELAY_PID" || { echo "FAILED: the relay didn't start as an unprivileged user"; exit 1; }

api() {
    ip netns exec relay curl -fsS "$@"
}

echo "--- Without a rule, the client must not see the service"
OUTPUT=$(browse)
echo "$OUTPUT"
if echo "$OUTPUT" | grep -q RelayedService; then
    echo "FAILED: the service was visible with no rule"
    exit 1
fi

echo "--- The relay's monitor must see it anyway"
api http://127.0.0.1:8080/api/services | grep -q RelayedService \
    || { echo "FAILED: the service isn't in the monitor"; exit 1; }

echo "--- With a rule, the client must discover and resolve it"
api -X POST -H 'Content-Type: application/json' \
    -d "{\"service_type\":\"$SERVICE_TYPE\",\"provider_iface\":\"r-provider\",\"client_iface\":\"r-client\"}" \
    http://127.0.0.1:8080/api/rules >/dev/null
OUTPUT=$(browse)
echo "$OUTPUT"
if ! echo "$OUTPUT" | grep '^=' | grep RelayedService | grep -q '10\.0\.2\.2;8123'; then
    echo "FAILED: the client didn't resolve the service to 10.0.2.2:8123"
    exit 1
fi

echo "PASSED: avahi-browse behaved correctly with and without a rule"
