import pytest

from mdns_relay.dns import MalformedPacket
from mdns_relay.ssdp import (
    KIND_NOTIFY,
    KIND_RESPONSE,
    KIND_SEARCH,
    MAX_HEADERS,
    MAX_MESSAGE,
    build_search,
    locations_allowed,
    parse_message,
)

ALIVE = (
    b"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nCACHE-CONTROL: max-age=120\r\n"
    b"LOCATION: http://10.0.0.5:80/d.xml\r\nNT: upnp:rootdevice\r\nNTS: ssdp:alive\r\n"
    b"USN: uuid:a::upnp:rootdevice\r\n\r\n"
)
REPLY = (
    b"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=60\r\nLOCATION: http://10.0.0.5/d.xml\r\n"
    b"ST: upnp:rootdevice\r\nUSN: uuid:a\r\n\r\n"
)


def test_parse_notify():
    message = parse_message(ALIVE)
    assert message.kind == KIND_NOTIFY
    assert message.target == "upnp:rootdevice"
    assert message.max_age == 120


def test_parse_header_names_case_insensitive_and_bare_newlines():
    message = parse_message(ALIVE.replace(b"\r\n", b"\n").replace(b"NT:", b"nt:"))
    assert message.target == "upnp:rootdevice"


def test_parse_search_and_response():
    search = parse_message(build_search("239.255.255.250", 1900))
    assert (search.kind, search.target, search.mx) == (KIND_SEARCH, "ssdp:all", 2)
    assert parse_message(REPLY).kind == KIND_RESPONSE


def test_build_search_brackets_ipv6():
    assert b"HOST: [FF02::C]:1900\r\n" in build_search("ff02::c", 1900)


def test_byebye_needs_no_location():
    data = b"NOTIFY * HTTP/1.1\r\nNT: a\r\nNTS: ssdp:byebye\r\nUSN: uuid:a\r\n\r\n"
    assert parse_message(data).is_byebye


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"GET / HTTP/1.1\r\n\r\n",
        b"HTTP/1.1 404 Not Found\r\nST: a\r\nUSN: b\r\nLOCATION: http://1.1.1.1/\r\n\r\n",
        ALIVE.replace(b"NTS: ssdp:alive\r\n", b""),
        ALIVE.replace(b"NTS: ssdp:alive", b"NTS: ssdp:other"),
        ALIVE.replace(b"LOCATION: http://10.0.0.5:80/d.xml\r\n", b""),
        ALIVE.replace(b"NT: upnp", b"NT: bad\x01upnp"),
        ALIVE.replace(b"NT: upnp:rootdevice\r\n", b"NT: a\r\nNT: b\r\n"),
        b'M-SEARCH * HTTP/1.1\r\nMAN: "x"\r\nST: a\r\n\r\n',
        b'M-SEARCH * HTTP/1.1\r\nMAN: "ssdp:discover"\r\nMX: x\r\nST: a\r\n\r\n',
        b"NOTIFY * HTTP/1.1\r\nno colon line\r\n\r\n",
    ],
)
def test_malformed(data):
    with pytest.raises(MalformedPacket):
        parse_message(data)


def test_limits():
    with pytest.raises(MalformedPacket):
        parse_message(b"x" * (MAX_MESSAGE + 1))
    headers = b"".join(b"X-%d: 1\r\n" % i for i in range(MAX_HEADERS + 1))
    with pytest.raises(MalformedPacket):
        parse_message(b"NOTIFY * HTTP/1.1\r\n" + headers + b"\r\n")


@pytest.mark.parametrize(
    ("url", "source", "allowed"),
    [
        ("http://10.0.0.5/d.xml", "10.0.0.5", True),
        ("https://10.0.0.5:8443/d.xml", "10.0.0.5", True),
        ("http://[fd00::5]:80/d.xml", "fd00::5", True),
        ("http://10.0.0.6/d.xml", "10.0.0.5", False),
        ("http://device.local/d.xml", "10.0.0.5", False),
        ("http://169.254.1.1/d.xml", "169.254.1.1", False),
        ("http://[fe80::1]/d.xml", "fe80::1%eth0", False),
        ("ftp://10.0.0.5/d.xml", "10.0.0.5", False),
        ("http://10.0.0.5:99999/d.xml", "10.0.0.5", False),
        ("http://[bad/d.xml", "10.0.0.5", False),
        ("http://10.0.0.5/" + "a" * 600, "10.0.0.5", False),
    ],
)
def test_location_validation(url, source, allowed):
    data = ALIVE.replace(b"http://10.0.0.5:80/d.xml", url.encode())
    assert locations_allowed(parse_message(data), source) is allowed


def test_alternate_locations_are_checked():
    data = ALIVE.replace(b"NTS:", b"AL: <http://10.0.0.5/a><http://10.0.0.9/b>\r\nNTS:")
    assert not locations_allowed(parse_message(data), "10.0.0.5")
    data = ALIVE.replace(b"NTS:", b"SECURELOCATION.UPNP.ORG: https://10.0.0.9/\r\nNTS:")
    assert not locations_allowed(parse_message(data), "10.0.0.5")
