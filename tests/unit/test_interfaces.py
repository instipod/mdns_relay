import sys

import pytest

from mdns_relay.interfaces import list_interfaces, parse_ipv6_table


def test_ipv6_table_skips_unusable_addresses():
    lines = [
        "fe800000000000000000000000000001 02 40 20 80 eth0\n",  # Usable
        "fe800000000000000000000000000002 03 40 20 c0 eth1\n",  # Tentative
        "fe800000000000000000000000000003 04 40 20 88 eth2\n",  # DAD failed
        "not a valid line\n",
    ]
    assert parse_ipv6_table(lines) == {"eth0": ["fe80::1"]}


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux only")
def test_real_interface_listing_finds_loopback():
    loopback = next(info for info in list_interfaces() if info.name == "lo")
    assert loopback.loopback
    assert loopback.index > 0
