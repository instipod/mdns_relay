import socket

import pytest

from mdns_relay.interfaces import InterfaceInfo
from mdns_relay.relay import Relay
from mdns_relay.rules import RuleStore
from mdns_relay.ssdp_relay import SsdpRelay
from mdns_relay.transport import SSDP_IPV4_GROUP, SSDP_PORT, ReceivedPacket

FAMILY = socket.AF_INET
TV = "urn:x:device:Tv:1"
INTERFACES = [
    InterfaceInfo("prov", 1, True, False, True, ("10.0.1.1",), ()),
    InterfaceInfo("cli", 2, True, False, True, ("10.0.2.1",), ()),
]
INDEX = {"prov": 1, "cli": 2}
RULE = {"protocol": "ssdp", "service_type": TV, "provider_iface": "prov", "client_iface": "cli"}
DEVICE = "10.0.1.5"
CLIENT = "10.0.2.5"
LOCATION = f"http://{DEVICE}:80/d.xml"


def notify(nts="ssdp:alive", usn="uuid:a", target=TV, location=LOCATION):
    return (
        f"NOTIFY * HTTP/1.1\r\nCACHE-CONTROL: max-age=100\r\nLOCATION: {location}\r\n"
        f"NT: {target}\r\nNTS: {nts}\r\nUSN: {usn}\r\n\r\n"
    ).encode()


def search(target=TV, mx=1):
    return f'M-SEARCH * HTTP/1.1\r\nMAN: "ssdp:discover"\r\nMX: {mx}\r\nST: {target}\r\n\r\n'.encode()


def reply(usn="uuid:a", target=TV, location=LOCATION):
    return (
        f"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=100\r\nLOCATION: {location}\r\n"
        f"ST: {target}\r\nUSN: {usn}\r\n\r\n"
    ).encode()


class FakeTransport:
    def __init__(self):
        self.sent = []
        self.unicast = []
        self.joined = set()

    def join(self, ifindex):
        self.joined.add(ifindex)

    def leave(self, ifindex):
        self.joined.discard(ifindex)

    def send(self, ifindex, data):
        self.sent.append((ifindex, data))

    def send_unicast(self, ifindex, data, host, port):
        self.unicast.append((ifindex, data, host, port))


class FakeSearch:
    def __init__(self, ifindex):
        self.ifindex = ifindex
        self.sent = []
        self.closed = False

    def send(self, data):
        self.sent.append(data)

    def close(self):
        self.closed = True


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class Env:
    def __init__(self, tmp_path, **limits):
        self.store = RuleStore(tmp_path / "rules.json")
        self.clock = Clock()
        self.interfaces = list(INTERFACES)
        self.relay = Relay(
            self.store, browse=False, interface_lister=lambda: self.interfaces, clock=self.clock
        )
        self.searches = []
        self.fail_open = False
        self.ssdp = SsdpRelay(self.relay, self.open_search, **limits)
        self.relay.ssdp = self.ssdp
        self.transport = FakeTransport()
        self.relay.add_ssdp_transport(FAMILY, self.transport)
        self.relay.sync_interfaces()

    def open_search(self, family, ifindex, on_packet):
        if self.fail_open:
            raise OSError("no sockets")
        handle = FakeSearch(ifindex)
        handle.on_packet = on_packet
        self.searches.append(handle)
        return handle

    def multicast(self, iface, data, source=DEVICE, port=4000, destination=SSDP_IPV4_GROUP):
        self.ssdp.handle_packet(
            ReceivedPacket(FAMILY, INDEX[iface], source, port, destination, data)
        )

    def client_search(self, data=None, source=CLIENT, port=5000):
        self.multicast("cli", data or search(), source=source, port=port)

    def device_reply(self, handle, data=None, iface="prov", source=DEVICE):
        handle.on_packet(
            ReceivedPacket(FAMILY, INDEX[iface], source, SSDP_PORT, "10.0.1.1", data or reply())
        )


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


def test_no_rule_monitors_only(env):
    env.multicast("prov", notify())
    env.client_search()
    assert env.transport.sent == []
    assert env.searches == []
    assert env.ssdp.table.snapshot(env.clock())[0]["instance"] == "uuid:a"
    assert env.relay.activity[-1]["protocol"] == "ssdp"
    assert env.relay.activity[-1]["reason"] == "no_rule"


def test_notify_relayed_unchanged_to_client_only(env):
    env.store.add(RULE)
    data = notify()
    env.multicast("prov", data)
    assert env.transport.sent == [(INDEX["cli"], data)]
    assert env.relay.activity[-1]["action"] == "relayed"


def test_notify_not_relayed_toward_provider(env):
    env.store.add(RULE)
    env.multicast("cli", notify(location=f"http://{CLIENT}/d.xml"), source=CLIENT)
    assert env.transport.sent == []


def test_notify_with_foreign_location_dropped_and_not_learned(env):
    env.store.add(RULE)
    env.multicast("prov", notify(location="http://192.0.2.9/d.xml"))
    assert env.transport.sent == []
    assert env.relay.counters["drop_bad_location"] == 1
    assert env.ssdp.table.snapshot(env.clock()) == []


def test_byebye_removes_device_and_is_relayed(env):
    env.store.add(RULE)
    env.multicast("prov", notify())
    env.multicast("prov", b"NOTIFY * HTTP/1.1\r\nNT: " + TV.encode() + b"\r\nNTS: ssdp:byebye\r\nUSN: uuid:a\r\n\r\n")
    assert len(env.transport.sent) == 2
    assert env.ssdp.table.snapshot(env.clock()) == []


def test_unicast_and_malformed_dropped(env):
    env.store.add(RULE)
    env.multicast("prov", notify(), destination="10.0.1.1")
    env.multicast("prov", b"garbage")
    assert env.relay.counters["drop_unicast"] == 1
    assert env.relay.counters["drop_malformed"] == 1
    assert env.transport.sent == []


def test_search_round_trip(env):
    env.store.add(RULE)
    data = search()
    env.client_search(data)
    assert len(env.searches) == 1
    assert env.searches[0].ifindex == INDEX["prov"]
    assert env.searches[0].sent == [data]
    answer = reply()
    env.device_reply(env.searches[0], answer)
    assert env.transport.unicast == [(INDEX["cli"], answer, CLIENT, 5000)]
    assert env.ssdp.table.snapshot(env.clock())[0]["iface"] == "prov"


def test_ssdp_all_replies_filtered_by_rule(env):
    env.store.add(RULE)
    env.client_search(search("ssdp:all"))
    env.device_reply(env.searches[0], reply(target="urn:x:device:Other:1", usn="uuid:b"))
    assert env.transport.unicast == []
    assert env.relay.counters["drop_nothing_permitted"] == 1


def test_reply_on_wrong_interface_dropped(env):
    env.store.add(RULE)
    env.client_search()
    env.device_reply(env.searches[0], iface="cli")
    assert env.transport.unicast == []
    assert env.relay.counters["drop_wrong_interface"] == 1


def test_reply_with_foreign_location_dropped(env):
    env.store.add(RULE)
    env.client_search()
    env.device_reply(env.searches[0], reply(location="http://192.0.2.9/"))
    assert env.transport.unicast == []
    assert env.relay.counters["drop_bad_location"] == 1


def test_retransmit_reuses_entry_and_is_sent_again(env):
    env.store.add(RULE)
    env.client_search()
    env.client_search()
    assert len(env.searches) == 1
    assert len(env.searches[0].sent) == 2


def test_identical_search_from_second_client_is_not_suppressed(env):
    env.store.add(RULE)
    env.client_search()
    env.client_search(source="10.0.2.6")
    assert len(env.searches) == 2
    assert all(len(handle.sent) == 1 for handle in env.searches)


def test_entry_expires_and_late_reply_ignored(env):
    env.store.add(RULE)
    env.client_search(search(mx=1))
    handle = env.searches[0]
    env.clock.now += 2.5
    env.device_reply(handle)
    assert env.transport.unicast == []
    env.ssdp.expire()
    assert handle.closed
    assert env.ssdp.pending_count == 0


def test_mx_wait_is_capped(env):
    env.store.add(RULE)
    env.client_search(search(mx=120))
    env.clock.now += 6.5
    env.ssdp.expire()
    assert env.searches[0].closed


def test_per_client_limit(tmp_path):
    env = Env(tmp_path, max_per_client=2)
    env.store.add(RULE)
    for port in (1, 2, 3):
        env.client_search(port=port)
    assert len(env.searches) == 2
    assert env.relay.counters["drop_search_limit"] == 1


def test_total_limit(tmp_path):
    env = Env(tmp_path, max_searches=2)
    env.store.add(RULE)
    for host in (5, 6, 7):
        env.client_search(source=f"10.0.2.{host}")
    assert len(env.searches) == 2


def test_socket_open_failure_is_a_drop(env):
    env.store.add(RULE)
    env.fail_open = True
    env.client_search()
    assert env.relay.counters["drop_search_limit"] == 1


def test_inactive_interface_closes_searches_and_forgets_devices(env):
    env.store.add(RULE)
    env.multicast("prov", notify())
    env.client_search()
    env.interfaces = [INTERFACES[1]]
    env.relay.sync_interfaces()
    assert env.searches[0].closed
    assert env.ssdp.table.snapshot(env.clock()) == []
    assert 1 not in env.transport.joined


def test_browse_learns_without_forwarding(env):
    env.store.add(RULE)
    env.ssdp.browse_once()
    assert {handle.ifindex for handle in env.searches} == {1, 2}
    handle = next(h for h in env.searches if h.ifindex == 1)
    assert b"ST: ssdp:all" in handle.sent[0]
    env.device_reply(handle)
    assert env.transport.unicast == []
    assert env.ssdp.table.snapshot(env.clock())[0]["instance"] == "uuid:a"


def test_relay_targets_respect_protocol(env):
    env.store.add(RULE)
    env.multicast("prov", notify())
    device = env.ssdp.table.snapshot(env.clock())[0]
    assert env.relay.relay_targets(device) == ["cli"]
    assert env.relay.relay_targets({**device, "protocol": "mdns"}) == []


def test_table_expires_from_max_age(env):
    env.multicast("prov", notify())
    env.clock.now += 101
    env.ssdp.table.prune(env.clock())
    assert env.ssdp.table.snapshot(env.clock()) == []
