import json

import pytest

from mdns_relay.rules import RuleError, RuleFileError, RuleStore, build_rule

VALID = {"service_type": "_http._tcp", "provider_iface": "eth0", "client_iface": "eth1"}


def test_missing_file_means_no_rules(tmp_path):
    store = RuleStore(tmp_path / "rules.json")
    store.load()
    assert store.rules == ()


def test_rules_persist_across_reload(tmp_path):
    path = tmp_path / "rules.json"
    store = RuleStore(path)
    created = store.add({**VALID, "note": "hello"})
    store.set_interface_enabled("eth5", False)

    reloaded = RuleStore(path)
    reloaded.load()
    assert reloaded.rules == (created,)
    assert reloaded.disabled_interfaces == {"eth5"}


@pytest.mark.parametrize(
    "content",
    [
        b"not json",
        b"[]",
        b'{"version": 2, "rules": []}',
        b'{"version": 1, "rules": {}}',
        b'{"version": 1, "rules": [{"service_type": "_http._tcp"}]}',
        b'{"version": 1, "rules": [{"id": "a", "service_type": "bad", '
        b'"provider_iface": "a", "client_iface": "b"}]}',
        b'{"version": 1, "disabled_interfaces": [1]}',
        b"\xff\xfe",
    ],
)
def test_corrupt_file_fails_and_is_not_overwritten(tmp_path, content):
    path = tmp_path / "rules.json"
    path.write_bytes(content)
    store = RuleStore(path)
    with pytest.raises(RuleFileError):
        store.load()
    assert store.rules == ()
    assert path.read_bytes() == content


def test_duplicate_ids_fail(tmp_path):
    path = tmp_path / "rules.json"
    item = {"id": "a", **VALID}
    path.write_text(json.dumps({"version": 1, "rules": [item, item]}))
    with pytest.raises(RuleFileError):
        RuleStore(path).load()


@pytest.mark.parametrize(
    "changes",
    [
        {"service_type": "http"},
        {"service_type": "_http._sctp"},
        {"service_type": ""},
        {"service_type": 5},
        {"provider_iface": "eth1"},
        {"provider_iface": "bad/name"},
        {"provider_iface": "much-too-long-interface"},
        {"client_iface": None},
        {"instance_pattern": ""},
        {"instance_pattern": "a\nb"},
        {"instance_pattern": "x" * 256},
        {"enabled": "yes"},
        {"note": "x" * 201},
        {"unknown": 1},
    ],
)
def test_invalid_fields_are_rejected(changes):
    with pytest.raises(RuleError):
        build_rule({**VALID, **changes})


@pytest.mark.parametrize("missing", ["service_type", "provider_iface", "client_iface"])
def test_required_fields(missing):
    data = {key: value for key, value in VALID.items() if key != missing}
    with pytest.raises(RuleError):
        build_rule(data)


@pytest.mark.parametrize(
    "value,expected",
    [
        ("_HTTP._TCP", "_http._tcp"),
        ("_http._tcp.local", "_http._tcp"),
        ("_http._tcp.local.", "_http._tcp"),
        (" _http._udp ", "_http._udp"),
        ("*", "*"),
    ],
)
def test_service_type_is_normalized(value, expected):
    assert build_rule({**VALID, "service_type": value}).service_type == expected


def test_instance_pattern_matching():
    rule = build_rule({**VALID, "instance_pattern": "Living*"})
    assert rule.matches_instance("_http._tcp", "living room")
    assert not rule.matches_instance("_http._tcp", "Kitchen")
    assert not rule.matches_instance("_ipp._tcp", "Living Room")


def test_update_and_delete(tmp_path):
    store = RuleStore(tmp_path / "rules.json")
    created = store.add(VALID)
    updated = store.update(created.id, {"enabled": False})
    assert updated.enabled is False
    assert store.get(created.id).enabled is False
    assert store.update("missing", {"enabled": False}) is None
    assert store.delete(created.id) is True
    assert store.delete(created.id) is False
    assert store.rules == ()


def test_invalid_update_leaves_rule_unchanged(tmp_path):
    store = RuleStore(tmp_path / "rules.json")
    created = store.add(VALID)
    with pytest.raises(RuleError):
        store.update(created.id, {"service_type": "bad"})
    with pytest.raises(RuleError):
        store.update(created.id, {"id": "other"})
    assert store.get(created.id) == created


def test_identical_rule_is_rejected(tmp_path):
    store = RuleStore(tmp_path / "rules.json")
    store.add(VALID)
    with pytest.raises(RuleError):
        store.add(VALID)
    assert len(store.rules) == 1


def test_failed_save_does_not_change_rules(tmp_path):
    store = RuleStore(tmp_path / "missing-dir" / "rules.json")
    with pytest.raises(OSError):
        store.add(VALID)
    assert store.rules == ()


def test_save_leaves_no_temp_files(tmp_path):
    store = RuleStore(tmp_path / "rules.json")
    store.add(VALID)
    assert [p.name for p in tmp_path.iterdir()] == ["rules.json"]


def test_rule_without_protocol_is_mdns():
    assert build_rule(
        {"service_type": "_http._tcp", "provider_iface": "a", "client_iface": "b"}
    ).protocol == "mdns"


@pytest.mark.parametrize(
    "target",
    ["*", "upnp:rootdevice", "uuid:abc-123", "urn:schemas-upnp-org:device:MediaServer:1"],
)
def test_ssdp_targets_accepted(target):
    built = build_rule(
        {"protocol": "ssdp", "service_type": target, "provider_iface": "a", "client_iface": "b"}
    )
    assert built.protocol == "ssdp"
    assert built.service_type == target.lower()


@pytest.mark.parametrize("target", ["ssdp:all", "_http._tcp", "urn:x:thing:y:1", ""])
def test_ssdp_invalid_targets_rejected(target):
    with pytest.raises(RuleError):
        build_rule(
            {"protocol": "ssdp", "service_type": target, "provider_iface": "a", "client_iface": "b"}
        )


def test_unknown_protocol_rejected():
    with pytest.raises(RuleError):
        build_rule(
            {"protocol": "bonjour", "service_type": "*", "provider_iface": "a", "client_iface": "b"}
        )


def test_same_match_differs_by_protocol(tmp_path):
    store = RuleStore(tmp_path / "rules.json")
    base = {"service_type": "*", "provider_iface": "a", "client_iface": "b"}
    store.add(base)
    store.add({**base, "protocol": "ssdp"})
    with pytest.raises(RuleError):
        store.add({**base, "protocol": "ssdp"})


def test_file_without_protocol_loads_as_mdns(tmp_path):
    path = tmp_path / "rules.json"
    path.write_text(json.dumps({"version": 1, "rules": [{
        "id": "r1", "enabled": True, "service_type": "_http._tcp", "instance_pattern": "*",
        "provider_iface": "a", "client_iface": "b", "note": "",
    }]}))
    store = RuleStore(path)
    store.load()
    assert store.rules[0].protocol == "mdns"
