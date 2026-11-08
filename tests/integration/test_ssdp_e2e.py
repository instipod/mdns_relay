"""End-to-end SSDP behaviour across real network namespaces."""

from __future__ import annotations

import select
import socket
import struct
import time

import pytest
from conftest import netns

from mdns_relay.transport import SSDP_GROUPS, SSDP_PORT

TV = "urn:schemas-upnp-org:device:MediaRenderer:1"
ADDRESSES = {
    "client": {socket.AF_INET: "10.0.1.2", socket.AF_INET6: "fd01::2"},
    "provider": {socket.AF_INET: "10.0.2.2", socket.AF_INET6: "fd02::2"},
}
_counter = 0


def unique_usn() -> str:
    global _counter
    _counter += 1
    return f"uuid:device-{_counter}"


class SsdpEndpoint:
    """Listens on the SSDP group, and sends from the segment's routable address."""

    def __init__(self, ns: str, iface: str, family: int) -> None:
        self.family = family
        self.address = ADDRESSES[ns][family]
        with netns(ns):
            self.index = socket.if_nametoindex(iface)
            self.listener = socket.socket(family, socket.SOCK_DGRAM)
            self.sender = socket.socket(family, socket.SOCK_DGRAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        group = socket.inet_pton(family, SSDP_GROUPS[family])
        if family == socket.AF_INET:
            self.listener.bind(("0.0.0.0", SSDP_PORT))
            mreqn = struct.pack("=4s4si", group, b"\0\0\0\0", self.index)
            self.listener.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreqn)
            self.sender.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, mreqn)
            self.sender.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
        else:
            self.listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            self.listener.bind(("::", SSDP_PORT))
            self.listener.setsockopt(
                socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, struct.pack("=16sI", group, self.index)
            )
            self.sender.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, self.index)
            self.sender.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 0)
        self.sender.bind((self.address, 0))

    def send_multicast(self, data: bytes) -> None:
        if self.family == socket.AF_INET:
            self.sender.sendto(data, (SSDP_GROUPS[self.family], SSDP_PORT))
        else:
            self.sender.sendto(data, (SSDP_GROUPS[self.family], SSDP_PORT, 0, self.index))

    @staticmethod
    def _wait(sock: socket.socket, seconds: float):
        ready, _, _ = select.select([sock], [], [], seconds)
        return sock.recvfrom(9000) if ready else None

    def receive_multicast(self, seconds: float = 3.0):
        return self._wait(self.listener, seconds)

    def receive_unicast(self, seconds: float = 3.0):
        return self._wait(self.sender, seconds)

    def close(self) -> None:
        self.listener.close()
        self.sender.close()


@pytest.fixture
def pair(relay, family):
    client = SsdpEndpoint("client", "c0", family)
    provider = SsdpEndpoint("provider", "p0", family)
    yield client, provider
    client.close()
    provider.close()


def location(address: str, family: int) -> str:
    host = f"[{address}]" if family == socket.AF_INET6 else address
    return f"http://{host}:8200/d.xml"


def notify(provider: SsdpEndpoint, usn: str) -> bytes:
    return (
        "NOTIFY * HTTP/1.1\r\nCACHE-CONTROL: max-age=60\r\n"
        f"LOCATION: {location(provider.address, provider.family)}\r\n"
        f"NT: {TV}\r\nNTS: ssdp:alive\r\nUSN: {usn}\r\n\r\n"
    ).encode()


def search(target: str = TV) -> bytes:
    return f'M-SEARCH * HTTP/1.1\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST: {target}\r\n\r\n'.encode()


def add_rule(relay) -> None:
    relay.add_rule(TV, "r-provider", "r-client", protocol="ssdp")


def test_no_rule_relays_nothing_but_device_is_listed(relay, pair):
    client, provider = pair
    usn = unique_usn()
    provider.send_multicast(notify(provider, usn))
    assert client.receive_multicast(0.6) is None
    client.send_multicast(search())
    assert provider.receive_multicast(0.6) is None

    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if any(s["instance"] == usn and s["protocol"] == "ssdp" for s in relay.services()):
            return
        time.sleep(0.05)
    pytest.fail("device was not listed")


def test_notify_relayed_unchanged(relay, pair):
    client, provider = pair
    add_rule(relay)
    data = notify(provider, unique_usn())
    provider.send_multicast(data)
    received = client.receive_multicast()
    assert received is not None
    assert received[0] == data


def test_search_round_trip(relay, pair):
    client, provider = pair
    add_rule(relay)
    client.send_multicast(search())
    received = provider.receive_multicast()
    assert received is not None
    assert received[0] == search()

    answer = (
        "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=60\r\n"
        f"LOCATION: {location(provider.address, provider.family)}\r\n"
        f"ST: {TV}\r\nUSN: {unique_usn()}\r\n\r\n"
    ).encode()
    provider.sender.sendto(answer, received[1])
    forwarded = client.receive_unicast()
    assert forwarded is not None
    assert forwarded[0] == answer


def test_reply_outside_rule_is_not_forwarded(relay, pair):
    client, provider = pair
    add_rule(relay)
    client.send_multicast(search("ssdp:all"))
    received = provider.receive_multicast()
    assert received is not None
    answer = (
        "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=60\r\n"
        f"LOCATION: {location(provider.address, provider.family)}\r\n"
        f"ST: upnp:rootdevice\r\nUSN: {unique_usn()}\r\n\r\n"
    ).encode()
    provider.sender.sendto(answer, received[1])
    assert client.receive_unicast(0.6) is None


def test_foreign_location_is_not_relayed(relay, pair):
    client, provider = pair
    add_rule(relay)
    data = notify(provider, unique_usn()).replace(
        location(provider.address, provider.family).encode(),
        location(client.address, client.family).encode(),
    )
    provider.send_multicast(data)
    assert client.receive_multicast(0.6) is None
