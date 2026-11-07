import socket

import pytest
from helpers import a, n, ptr, query, response, rule, srv, type_name

from mdns_relay.dns import TYPE_PTR, Question, encode_message, parse_message
from mdns_relay.interfaces import InterfaceInfo
from mdns_relay.relay import Relay
from mdns_relay.rules import RuleStore
from mdns_relay.transport import MDNS_IPV4_GROUP, MDNS_PORT, ReceivedPacket

HTTP = "_http._tcp"
FAMILY = socket.AF_INET
INTERFACES = [
    InterfaceInfo("prov", 1, True, False, True, ("10.0.1.1",), ("fd00::1",)),
    InterfaceInfo("cli", 2, True, False, True, ("10.0.2.1",), ("fd01::1",)),
]
INDEX = {"prov": 1, "cli": 2}
RULE = {"service_type": HTTP, "provider_iface": "prov", "client_iface": "cli"}


class FakeTransport:
    def __init__(self):
        self.sent = []
        self.joined = set()
        self.fail = False

    def join(self, ifindex):
        self.joined.add(ifindex)

    def leave(self, ifindex):
        self.joined.discard(ifindex)

    def send(self, ifindex, data):
        if self.fail:
            raise OSError("send failed")
        self.sent.append((ifindex, data))


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


@pytest.fixture
def env(tmp_path):
    store = RuleStore(tmp_path / "rules.json")
    clock = Clock()
    relay = Relay(store, browse=False, interface_lister=lambda: INTERFACES, clock=clock)
    transport = FakeTransport()
    relay.add_transport(FAMILY, transport)
    relay.sync_interfaces()
    return relay, store, transport, clock


def packet(iface, message, *, port=MDNS_PORT, destination=MDNS_IPV4_GROUP, data=None):
    return ReceivedPacket(
        FAMILY, INDEX[iface], "10.0.0.9", port, destination,
        data if data is not None else encode_message(message),
    )


def announce():
    return response(
        [ptr(HTTP, "Web")], [srv(HTTP, "Web", "h.local"), a("h.local", "192.0.2.1")]
    )


def test_no_rules_sends_nothing_but_monitors(env):
    relay, _, transport, clock = env
    relay.handle_packet(packet("prov", announce()))
    assert transport.sent == []
    assert relay.table.snapshot(clock())[0]["instance"] == "Web"
    assert relay.activity[-1]["reason"] == "no_rule"


def test_rule_relays_response_to_client_only(env):
    relay, store, transport, _ = env
    store.add(RULE)
    relay.handle_packet(packet("prov", announce()))
    assert [index for index, _ in transport.sent] == [INDEX["cli"]]
    assert relay.counters["relayed"] == 1


def test_rule_takes_effect_and_ends_without_restart(env):
    relay, store, transport, clock = env
    relay.handle_packet(packet("prov", response([ptr(HTTP, "A")])))
    assert transport.sent == []
    created = store.add(RULE)
    relay.handle_packet(packet("prov", response([ptr(HTTP, "B")])))
    assert len(transport.sent) == 1
    store.update(created.id, {"enabled": False})
    relay.handle_packet(packet("prov", response([ptr(HTTP, "C")])))
    assert len(transport.sent) == 1
    store.update(created.id, {"enabled": True})
    relay.handle_packet(packet("prov", response([ptr(HTTP, "D")])))
    assert len(transport.sent) == 2
    store.delete(created.id)
    relay.handle_packet(packet("prov", response([ptr(HTTP, "E")])))
    assert len(transport.sent) == 2


def test_relayed_address_learned_from_earlier_packet(env):
    relay, store, transport, _ = env
    store.add(RULE)
    relay.handle_packet(packet("prov", response([srv(HTTP, "Web", "h.local")])))
    relay.handle_packet(packet("prov", response([a("h.local", "192.0.2.1")])))
    assert parse_message(transport.sent[-1][1]).answers == [a("h.local", "192.0.2.1")]


@pytest.mark.parametrize(
    "kwargs,reason",
    [
        ({"destination": "10.0.1.1"}, "drop_unicast"),
        ({"data": b"garbage"}, "drop_malformed"),
        ({"port": 40000}, "drop_legacy_source_port"),
    ],
)
def test_ineligible_packets_are_dropped(env, kwargs, reason):
    relay, store, transport, _ = env
    store.add(RULE)
    relay.handle_packet(packet("prov", announce(), **kwargs))
    assert transport.sent == []
    assert relay.counters[reason] == 1


def test_non_standard_opcode_is_dropped(env):
    relay, store, transport, clock = env
    store.add(RULE)
    message = announce()
    message.flags |= 0x2800
    relay.handle_packet(packet("prov", message))
    assert transport.sent == []
    assert relay.table.snapshot(clock()) == []


def test_response_from_other_port_does_not_update_monitor(env):
    relay, _, _, clock = env
    relay.handle_packet(packet("prov", announce(), port=40000))
    assert relay.table.snapshot(clock()) == []


def test_inactive_interface_is_ignored(env):
    relay, store, transport, clock = env
    store.add(RULE)
    relay.handle_packet(
        ReceivedPacket(FAMILY, 99, "10.0.0.9", MDNS_PORT, MDNS_IPV4_GROUP, encode_message(announce()))
    )
    assert transport.sent == []
    assert relay.table.snapshot(clock()) == []


def test_our_own_echo_is_dropped(env):
    relay, store, transport, clock = env
    store.add(RULE)
    store.add({**RULE, "provider_iface": "cli", "client_iface": "prov"})
    relay.handle_packet(packet("prov", announce()))
    _, sent = transport.sent[0]
    relay.handle_packet(packet("cli", None, data=sent))
    assert len(transport.sent) == 1
    assert relay.counters["drop_echo"] == 1


def test_same_output_is_not_sent_twice_within_window(env):
    relay, store, transport, clock = env
    store.add(RULE)
    relay.handle_packet(packet("prov", announce()))
    relay.handle_packet(packet("prov", announce()))
    assert len(transport.sent) == 1
    assert relay.counters["drop_duplicate"] == 1
    clock.now += 1.5
    relay.handle_packet(packet("prov", announce()))
    assert len(transport.sent) == 2


def test_send_failure_is_counted_and_survived(env):
    relay, store, transport, _ = env
    store.add(RULE)
    transport.fail = True
    relay.handle_packet(packet("prov", announce()))
    assert relay.counters["send_errors"] == 1
    assert relay.counters["relayed"] == 0


def test_internal_error_drops_packet(env, monkeypatch):
    relay, store, transport, _ = env
    store.add(RULE)

    def explode(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr("mdns_relay.policy.filter_packet", explode)
    relay.handle_packet(packet("prov", announce()))
    assert transport.sent == []
    assert relay.counters["drop_internal_error"] == 1


def test_disabling_interface_leaves_groups_and_forgets_services(env):
    relay, store, transport, clock = env
    relay.handle_packet(packet("prov", announce()))
    store.set_interface_enabled("prov", False)
    relay.sync_interfaces()
    assert transport.joined == {INDEX["cli"]}
    assert relay.table.snapshot(clock()) == []
    assert relay.rule_status(rule()) == ["Provider interface prov is not active"]


def test_pinned_interfaces_override_saved_settings(tmp_path):
    store = RuleStore(tmp_path / "rules.json")
    relay = Relay(store, pinned_interfaces=["cli"], interface_lister=lambda: INTERFACES)
    transport = FakeTransport()
    relay.add_transport(FAMILY, transport)
    relay.sync_interfaces()
    assert relay.active_names() == ["cli"]


def test_ineligible_interfaces_are_not_used(tmp_path):
    interfaces = [
        InterfaceInfo("lo", 1, True, True, False, ("127.0.0.1",)),
        InterfaceInfo("down0", 2, False, False, True, ("10.0.0.1",)),
        InterfaceInfo("nomc0", 3, True, False, False, ("10.0.0.2",)),
    ]
    relay = Relay(RuleStore(tmp_path / "r.json"), interface_lister=lambda: interfaces)
    transport = FakeTransport()
    relay.add_transport(FAMILY, transport)
    relay.sync_interfaces()
    assert relay.active_names() == []
    assert transport.joined == set()


def test_rule_status_for_missing_interface(env):
    relay, _, _, _ = env
    assert relay.rule_status(rule(provider="gone")) == ["Provider interface gone does not exist"]
    assert relay.rule_status(rule()) == []


def test_relay_targets(env):
    relay, store, _, _ = env
    store.add(RULE)
    service = {"iface": "prov", "service_type": HTTP, "instance": "Web"}
    assert relay.relay_targets(service) == ["cli"]
    assert relay.relay_targets({**service, "service_type": "_ipp._tcp"}) == []
    assert relay.relay_targets({**service, "iface": "cli"}) == []


def test_browse_stays_on_each_interface_and_covers_gaps(env):
    relay, _, transport, _ = env
    relay.handle_packet(
        packet("prov", response([ptr(HTTP, "NoSrv"), srv(HTTP, "NoAddr", "h.local")]))
    )
    relay.browse_once()
    assert {index for index, _ in transport.sent} == {INDEX["prov"], INDEX["cli"]}
    provider_names = {
        q.name
        for index, data in transport.sent
        if index == INDEX["prov"]
        for q in parse_message(data).questions
    }
    assert type_name(HTTP) in provider_names
    assert n("h.local") in provider_names
    assert any(name[0] == b"NoSrv" for name in provider_names)
    client_names = {
        q.name
        for index, data in transport.sent
        if index == INDEX["cli"]
        for q in parse_message(data).questions
    }
    assert type_name(HTTP) not in client_names


def test_browse_splits_large_question_lists(env):
    relay, _, _, _ = env
    relay.handle_packet(
        packet("prov", response([ptr(f"_t{i}._tcp", "S") for i in range(50)]))
    )
    messages = relay.build_browse_messages("prov")
    assert len(messages) > 1
    assert all(len(m.questions) <= 20 for m in messages)


def test_query_is_relayed_to_provider_with_qu_cleared(env):
    relay, store, transport, _ = env
    store.add(RULE)
    relay.handle_packet(
        packet("cli", query(Question(type_name(HTTP), TYPE_PTR, unicast=True)))
    )
    index, data = transport.sent[0]
    assert index == INDEX["prov"]
    assert parse_message(data).questions[0].unicast is False
