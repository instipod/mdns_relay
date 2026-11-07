"""End-to-end relay behaviour. Each test uses unique names so echo windows don't overlap."""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import time

import pytest
from conftest import RelayProcess

from mdns_relay.dns import (
    FLAG_QR,
    TYPE_A,
    TYPE_AAAA,
    TYPE_PTR,
    TYPE_SRV,
    TYPE_TXT,
    Message,
    Question,
    Record,
    SrvData,
    name_from_text,
)

HTTP = "_http._tcp"
IPP = "_ipp._tcp"
QUIET = 0.6
_counter = 0


def unique(prefix: str) -> str:
    global _counter
    _counter += 1
    return f"{prefix}{_counter}"


def tname(service_type: str):
    return (*name_from_text(service_type), b"local")


def iname(instance: str, service_type: str):
    return (instance.encode(), *name_from_text(service_type), b"local")


def announcement(instance: str, service_type: str = HTTP, host: str | None = None, extra=()):
    host_name = name_from_text(f"{host or instance.lower()}.local")
    return Message(
        flags=FLAG_QR | 0x0400,
        answers=[Record(tname(service_type), TYPE_PTR, 4500, iname(instance, service_type))],
        additionals=[
            Record(iname(instance, service_type), TYPE_SRV, 120, SrvData(0, 0, 8080, host_name)),
            Record(iname(instance, service_type), TYPE_TXT, 4500, b"\x03a=1"),
            Record(host_name, TYPE_A, 120, socket.inet_aton("10.0.2.2")),
            Record(host_name, TYPE_AAAA, 120, socket.inet_pton(socket.AF_INET6, "fd02::2")),
            *extra,
        ],
    )


def ptr_query(service_type: str = HTTP, unicast: bool = False, instance_q: str | None = None):
    questions = [Question(tname(service_type), TYPE_PTR, unicast=unicast)]
    if instance_q:
        questions.append(Question(iname(instance_q, service_type), TYPE_SRV))
    return Message(questions=questions)


def instances(message: Message) -> list[bytes]:
    return [r.rdata[0] for r in message.answers if r.rtype == TYPE_PTR]


def eventually(check, seconds: float = 3.0):
    deadline = time.monotonic() + seconds
    while True:
        result = check()
        if result or time.monotonic() > deadline:
            return result
        time.sleep(0.05)


def test_no_rule_relays_nothing_but_service_is_monitored(relay, client, provider, family):
    name = unique("NoRule")
    provider.send(announcement(name), family)
    assert client.receive(family) == []

    client.send(ptr_query(), family)
    assert provider.receive(family) == []

    service = eventually(
        lambda: next((s for s in relay.services() if s["instance"] == name), None)
    )
    assert service is not None
    assert service["iface"] == "r-provider"
    assert service["port"] == 8080
    assert service["relayed_to"] == []


def test_rule_added_through_api_takes_effect_without_restart(relay, client, provider, family):
    before = unique("Before")
    provider.send(announcement(before), family)
    assert client.receive(family) == []

    relay.add_rule(HTTP, "r-provider", "r-client")

    # Query goes from client to provider, with the unicast-response bit cleared.
    client.send(ptr_query(unicast=True), family)
    query = provider.wait_for(family, lambda m: not m.is_response)
    assert query is not None
    assert query.questions[0].name == tname(HTTP)
    assert query.questions[0].unicast is False

    # Response goes back from provider to client, with its records intact.
    name = unique("After")
    provider.send(announcement(name), family)
    response = client.wait_for(family, lambda m: m.is_response)
    assert response is not None
    assert instances(response) == [name.encode()]
    assert {r.rtype for r in response.additionals} == {TYPE_SRV, TYPE_TXT, TYPE_A, TYPE_AAAA}

    services = relay.services()
    assert next(s for s in services if s["instance"] == name)["relayed_to"] == ["r-client"]


def test_client_services_are_not_exposed_to_provider(relay, client, provider, family):
    relay.add_rule(HTTP, "r-provider", "r-client")
    client.send(announcement(unique("ClientSide")), family)
    assert provider.receive(family) == []
    provider.send(ptr_query(), family)
    assert client.receive(family) == []


def test_unrelated_service_in_same_packet_is_removed(relay, client, provider, family):
    relay.add_rule(HTTP, "r-provider", "r-client")
    wanted = unique("Wanted")
    hidden = unique("Hidden")
    message = announcement(wanted)
    message.answers.append(Record(tname(IPP), TYPE_PTR, 4500, iname(hidden, IPP)))
    message.additionals.append(Record(iname(hidden, IPP), TYPE_TXT, 4500, b"\x08secret=1"))
    provider.send(message, family)

    response = client.wait_for(family, lambda m: m.is_response)
    assert response is not None
    assert instances(response) == [wanted.encode()]
    assert not any(r.name[0] == hidden.encode() for r in response.additionals)


def test_instance_pattern_blocks_other_instances(relay, client, provider, family):
    prefix = unique("Living")
    relay.add_rule(HTTP, "r-provider", "r-client", instance_pattern=f"{prefix}*")

    provider.send(announcement(unique("Kitchen")), family)
    assert client.receive(family) == []

    name = f"{prefix} Room"
    provider.send(announcement(name, host=unique("livinghost")), family)
    response = client.wait_for(family, lambda m: m.is_response)
    assert response is not None
    assert instances(response) == [name.encode()]


def test_link_local_addresses_are_removed(relay, client, provider, family):
    relay.add_rule(HTTP, "r-provider", "r-client")
    host = unique("llhost")
    host_name = name_from_text(f"{host}.local")
    extra = (
        Record(host_name, TYPE_A, 120, socket.inet_aton("169.254.9.9")),
        Record(host_name, TYPE_AAAA, 120, socket.inet_pton(socket.AF_INET6, "fe80::99")),
    )
    provider.send(announcement(unique("LinkLocal"), host=host, extra=extra), family)
    response = client.wait_for(family, lambda m: m.is_response)
    assert response is not None
    addresses = [r.rdata for r in response.additionals if r.rtype in (TYPE_A, TYPE_AAAA)]
    assert socket.inet_aton("10.0.2.2") in addresses
    assert socket.inet_aton("169.254.9.9") not in addresses
    assert socket.inet_pton(socket.AF_INET6, "fe80::99") not in addresses


def test_disable_and_delete_stop_relaying_immediately(relay, client, provider, family):
    rule = relay.add_rule(HTTP, "r-provider", "r-client")
    provider.send(announcement(unique("On")), family)
    assert client.wait_for(family, lambda m: m.is_response) is not None

    relay.api("PATCH", f"/api/rules/{rule['id']}", {"enabled": False})
    provider.send(announcement(unique("Disabled")), family)
    assert client.receive(family) == []

    relay.api("PATCH", f"/api/rules/{rule['id']}", {"enabled": True})
    provider.send(announcement(unique("Enabled")), family)
    assert client.wait_for(family, lambda m: m.is_response) is not None

    relay.api("DELETE", f"/api/rules/{rule['id']}")
    provider.send(announcement(unique("Deleted")), family)
    assert client.receive(family) == []


def test_malformed_and_legacy_packets_are_not_relayed(relay, client, provider, family):
    relay.add_rule(HTTP, "r-provider", "r-client")
    relay.add_rule(HTTP, "r-client", "r-provider")
    before = relay.api("GET", "/api/status")["counters"]

    provider.send_raw(b"\xff" * 40, family)
    client.send_from_other_port(ptr_query(), family)
    assert client.receive(family) == []
    assert provider.receive(family) == []

    after = eventually(
        lambda: (
            data
            if (data := relay.api("GET", "/api/status")["counters"]).get("drop_malformed", 0)
            > before.get("drop_malformed", 0)
            and data.get("drop_legacy_source_port", 0) > before.get("drop_legacy_source_port", 0)
            else None
        )
    )
    assert after, "both drops should be counted"

    # The relay survived and still works.
    provider.send(announcement(unique("StillWorks")), family)
    assert client.wait_for(family, lambda m: m.is_response) is not None


def test_probe_is_not_relayed(relay, client, provider, family):
    relay.add_rule(HTTP, "r-provider", "r-client")
    name = unique("Probe")
    message = Message(
        questions=[Question(iname(name, HTTP), 255)],
        authorities=[
            Record(iname(name, HTTP), TYPE_SRV, 120, SrvData(0, 0, 1, name_from_text("x.local")))
        ],
    )
    client.send(message, family)
    assert provider.receive(family) == []


def test_two_relays_do_not_cause_a_storm(relay, client, provider, family, tmp_path):
    second = RelayProcess("relay2", ["r2-client", "r2-provider"], tmp_path / "rules.json")
    second.start()
    try:
        # Rules in both directions on both relays are the worst case for loops.
        relay.add_rule(HTTP, "r-provider", "r-client")
        relay.add_rule(HTTP, "r-client", "r-provider")
        second.add_rule(HTTP, "r2-provider", "r2-client")
        second.add_rule(HTTP, "r2-client", "r2-provider")

        provider.send(announcement(unique("Storm")), family)
        seen_by_client = client.receive(family, 2.5)
        seen_by_provider = provider.receive(family, 0.1)
        assert 1 <= len(seen_by_client) <= 4
        assert len(seen_by_provider) <= 4
        # And it has fully stopped.
        assert client.receive(family, 1.0) == []
    finally:
        second.stop()


def test_rules_survive_restart(topology, client, provider, family, tmp_path):
    # A separate relay process so the shared one's state isn't disturbed. It runs
    # in the second namespace, so the two can't both relay the same packet.
    process = RelayProcess("relay2", ["r2-client", "r2-provider"], tmp_path / "rules.json")
    process.start()
    try:
        created = process.add_rule(HTTP, "r2-provider", "r2-client", note="keep me")
    finally:
        process.stop()

    saved = json.loads((tmp_path / "rules.json").read_text())
    assert [rule["id"] for rule in saved["rules"]] == [created["id"]]

    process.start()
    try:
        rules = process.api("GET", "/api/rules")["rules"]
        assert [rule["note"] for rule in rules] == ["keep me"]
        client.drain()
        name = unique("Persisted")
        provider.send(announcement(name), family)
        response = client.wait_for(family, lambda m: m.is_response)
        assert response is not None
        assert instances(response) == [name.encode()]
    finally:
        process.stop()


def test_corrupt_rules_file_stops_startup_and_is_preserved(tmp_path):
    path = tmp_path / "rules.json"
    path.write_text("{ not json")
    result = subprocess.run(
        [sys.executable, "-m", "mdns_relay", "--rules-file", str(path), "--http-port", "8099"],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 2
    assert "invalid rules file" in result.stderr
    assert path.read_text() == "{ not json"


def test_non_loopback_without_auth_is_refused(tmp_path):
    result = subprocess.run(
        [
            sys.executable, "-m", "mdns_relay",
            "--rules-file", str(tmp_path / "rules.json"),
            "--http-host", "0.0.0.0",
        ],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 2
    assert "--auth-token" in result.stderr


def test_real_api_rejects_cross_origin_and_foreign_host(relay):
    status, _ = relay.request(
        "POST",
        "/api/rules",
        {"service_type": HTTP, "provider_iface": "r-provider", "client_iface": "r-client"},
        {"Origin": "http://evil.example"},
    )
    assert status == 403
    status, _ = relay.request("GET", "/api/rules", headers={"Host": "evil.example"})
    assert status == 403
    assert relay.api("GET", "/api/rules")["rules"] == []
