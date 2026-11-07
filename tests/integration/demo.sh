#!/bin/sh
# Runs the app with simulated networks and services, for trying the web interface.
# docker run --rm --privileged -p 8080:8080 mdns-relay-test sh tests/integration/demo.sh
set -eu

TOKEN=${MDNS_RELAY_AUTH_TOKEN:-demo-token-not-for-production}

for segment in lan iot; do
    ip netns add "$segment"
    ip netns exec "$segment" ip link set lo up
done

ip link add demo-lan type veth peer name eth1
ip link set eth1 netns lan
ip addr add 10.10.1.1/24 dev demo-lan
ip link set demo-lan up
ip netns exec lan ip addr add 10.10.1.2/24 dev eth1
ip netns exec lan ip link set eth1 up

ip link add demo-iot type veth peer name eth1
ip link set eth1 netns iot
ip addr add 10.10.2.1/24 dev demo-iot
ip link set demo-iot up
ip netns exec iot ip addr add 10.10.2.2/24 dev eth1
ip netns exec iot ip link set eth1 up

ip netns exec lan python tests/integration/demo_services.py eth1 lan &
ip netns exec iot python tests/integration/demo_services.py eth1 iot &

echo "Open http://localhost:8080/ and sign in with: $TOKEN"
exec mdns-relay --rules-file /tmp/demo-rules.json --http-host 0.0.0.0 --auth-token "$TOKEN"
