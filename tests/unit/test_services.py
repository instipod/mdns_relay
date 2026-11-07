from helpers import a, aaaa, meta_ptr, n, ptr, query, response, srv, txt

from mdns_relay.dns import Question, TYPE_PTR
from mdns_relay.services import MAX_ADDRESSES_PER_HOST, MAX_TXT_ITEMS, ServiceTable, parse_txt

HTTP = "_http._tcp"
NOW = 1000.0


def full_table():
    table = ServiceTable()
    table.update(
        "eth0",
        response(
            [ptr(HTTP, "Web")],
            [
                srv(HTTP, "Web", "host.local", 8080),
                txt(HTTP, "Web", "a=1"),
                a("host.local", "192.0.2.1"),
                aaaa("host.local", "fe80::1"),
            ],
        ),
        "IPv4",
        NOW,
    )
    return table


def test_response_creates_full_service():
    service = full_table().snapshot(NOW)[0]
    assert service["iface"] == "eth0"
    assert service["instance"] == "Web"
    assert service["service_type"] == HTTP
    assert service["host"] == "host.local"
    assert service["port"] == 8080
    assert service["txt"] == ["a=1"]
    assert service["addresses"] == ["192.0.2.1", "fe80::1"]
    assert service["families"] == ["IPv4"]


def test_query_teaches_nothing():
    table = ServiceTable()
    table.update("eth0", query(Question((b"_http", b"_tcp", b"local"), TYPE_PTR), known=[ptr(HTTP, "Web")]), "IPv4", NOW)
    assert table.snapshot(NOW) == []


def test_same_service_on_two_interfaces_is_separate():
    table = full_table()
    table.update("eth1", response([ptr(HTTP, "Web")]), "IPv4", NOW)
    assert [s["iface"] for s in table.snapshot(NOW)] == ["eth0", "eth1"]


def test_names_are_case_insensitive():
    table = full_table()
    table.update("eth0", response([ptr(HTTP, "WEB")]), "IPv4", NOW)
    assert len(table.snapshot(NOW)) == 1


def test_host_index():
    table = full_table()
    assert table.instances_for_host("eth0", n("HOST.local")) == [(HTTP, "Web")]
    assert table.instances_for_host("eth1", n("host.local")) == []
    assert table.instances_for_host("eth0", n("other.local")) == []


def test_host_index_follows_srv_change():
    table = full_table()
    table.update("eth0", response([srv(HTTP, "Web", "new.local")]), "IPv4", NOW)
    assert table.instances_for_host("eth0", n("host.local")) == []
    assert table.instances_for_host("eth0", n("new.local")) == [(HTTP, "Web")]


def test_ptr_goodbye_removes_service_and_host_index():
    table = full_table()
    table.update("eth0", response([ptr(HTTP, "Web", ttl=0)]), "IPv4", NOW)
    assert table.snapshot(NOW) == []
    assert table.instances_for_host("eth0", n("host.local")) == []


def test_srv_goodbye_removes_service():
    table = full_table()
    table.update("eth0", response([srv(HTTP, "Web", "host.local", ttl=0)]), "IPv4", NOW)
    assert table.snapshot(NOW) == []


def test_subtype_goodbye_keeps_service():
    from mdns_relay.dns import Record
    from helpers import instance_name

    table = full_table()
    record = Record(n("_x._sub._http._tcp.local"), TYPE_PTR, 0, instance_name("Web", HTTP))
    table.update("eth0", response([record]), "IPv4", NOW)
    assert len(table.snapshot(NOW)) == 1


def test_expiry():
    table = ServiceTable()
    table.update("eth0", response([ptr(HTTP, "Web", ttl=100)]), "IPv4", NOW)
    table.prune(NOW + 99)
    assert len(table.snapshot(NOW + 99)) == 1
    table.prune(NOW + 100)
    assert table.snapshot(NOW + 100) == []


def test_address_expiry_and_goodbye():
    table = full_table()
    table.update("eth0", response([a("host.local", "192.0.2.1", ttl=0)]), "IPv4", NOW)
    assert table.snapshot(NOW)[0]["addresses"] == ["fe80::1"]
    table.prune(NOW + 121)
    assert table.snapshot(NOW + 121)[0]["addresses"] == []


def test_service_cap():
    table = ServiceTable(max_services=3)
    for index in range(10):
        table.update("eth0", response([ptr(HTTP, f"S{index}")]), "IPv4", NOW)
    assert len(table.snapshot(NOW)) == 3
    assert table.refused == 7


def test_host_cap():
    table = ServiceTable(max_hosts=2)
    for index in range(5):
        table.update("eth0", response([a(f"h{index}.local", "192.0.2.1")]), "IPv4", NOW)
    assert len(table._hosts) == 2


def test_address_cap():
    table = ServiceTable()
    for index in range(MAX_ADDRESSES_PER_HOST + 5):
        table.update("eth0", response([a("h.local", f"192.0.2.{index}")]), "IPv4", NOW)
    assert len(table._hosts[("eth0", n("h.local"))]) == MAX_ADDRESSES_PER_HOST


def test_txt_limits():
    data = b"".join(bytes([3]) + b"a=1" for _ in range(MAX_TXT_ITEMS + 5))
    assert len(parse_txt(data)) == MAX_TXT_ITEMS
    assert parse_txt(b"\x00") == []
    assert parse_txt(b"\x05ab") == ["ab"]  # Declared length runs past the end


def test_forget_interface():
    table = full_table()
    table.update("eth1", response([ptr(HTTP, "Other"), meta_ptr(HTTP)]), "IPv4", NOW)
    table.forget_interface("eth0")
    assert [s["iface"] for s in table.snapshot(NOW)] == ["eth1"]
    assert table.instances_for_host("eth0", n("host.local")) == []
    assert table.service_types("eth0") == set()


def test_service_types_and_incomplete():
    table = ServiceTable()
    table.update(
        "eth0",
        response([meta_ptr("_ipp._tcp"), ptr(HTTP, "NoSrv"), srv(HTTP, "NoAddr", "h.local")]),
        "IPv4",
        NOW,
    )
    assert table.service_types("eth0") == {"_ipp._tcp", HTTP}
    instances, hosts = table.incomplete("eth0")
    assert [name[0] for name in instances] == [b"NoSrv"]
    assert hosts == [n("h.local")]


def test_version_changes_on_content_but_not_on_refresh():
    table = full_table()
    version = table.version
    table.update("eth0", response([ptr(HTTP, "Web")]), "IPv4", NOW + 1)
    assert table.version == version
    table.update("eth0", response([txt(HTTP, "Web", "a=2")]), "IPv4", NOW + 1)
    assert table.version != version
