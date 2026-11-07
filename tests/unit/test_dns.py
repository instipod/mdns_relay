import random
import struct

import pytest
from helpers import a, aaaa, meta_ptr, n, ptr, query, response, srv, txt

from mdns_relay.dns import (
    TYPE_NSEC,
    TYPE_PTR,
    MalformedPacket,
    NsecData,
    Question,
    Record,
    encode_message,
    parse_message,
    parse_service_name,
)


def header(qd=0, an=0, ns=0, ar=0, flags=0):
    return struct.pack("!HHHHHH", 0, flags, qd, an, ns, ar)


def test_response_round_trip():
    message = response(
        [ptr("_http._tcp", "Web Server"), meta_ptr("_http._tcp")],
        [
            srv("_http._tcp", "Web Server", "host.local", 8080),
            txt("_http._tcp", "Web Server", "path=/", "v=1"),
            a("host.local", "192.0.2.1"),
            aaaa("host.local", "2001:db8::1"),
            Record(
                n("host.local"), TYPE_NSEC, 120, NsecData(n("host.local"), b"\x00\x01\x40"),
                cache_flush=True,
            ),
        ],
    )
    parsed = parse_message(encode_message(message))
    assert parsed.answers == message.answers
    assert parsed.additionals == message.additionals
    assert parsed.is_response


def test_query_round_trip_preserves_unicast_bit():
    message = query(Question(n("_http._tcp.local"), TYPE_PTR, unicast=True))
    assert parse_message(encode_message(message)).questions == message.questions


def test_cache_flush_bit_is_preserved():
    record = Record(n("host.local"), 1, 120, b"\xc0\x00\x02\x01", cache_flush=True)
    parsed = parse_message(encode_message(response([record])))
    assert parsed.answers[0].cache_flush
    assert parsed.answers[0].rclass == 1


def test_encoder_compresses_repeated_names():
    records = [ptr("_http._tcp", f"Instance {i}") for i in range(10)]
    data = encode_message(response(records))
    assert data.count(b"_http") == 1
    assert parse_message(data).answers == records


def test_label_containing_dot_is_one_label():
    message = response([ptr("_http._tcp", "Dr. Who's Printer")])
    parsed = parse_message(encode_message(message))
    assert parsed.answers[0].rdata[0] == b"Dr. Who's Printer"


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"\0" * 11,
        header(qd=1),  # Question missing
        header(qd=1) + b"\x05abc",  # Label past the end
        header(qd=1) + b"\x00\x00",  # Truncated question
        header(qd=1) + b"\xc0",  # Truncated pointer
        header(qd=1) + b"\xc0\x0c\x00\x01\x00\x01",  # Pointer to itself
        header(qd=1) + b"\xc0\xff\x00\x01\x00\x01",  # Pointer forwards
        header(qd=2) + b"\x01a\xc0\x0e\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01",  # Loop
        header(qd=1) + b"\x80a\x00\x00\x01\x00\x01",  # Reserved label type
        header(an=1) + b"\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\x09\x01",  # rdata too long
        header(an=1) + b"\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\x02\x01\x02",  # Bad A length
        header(an=1) + b"\x00\x00\x1c\x00\x01\x00\x00\x00\x00\x00\x02\x01\x02",  # Bad AAAA
        header(an=1) + b"\x00\x00\x21\x00\x01\x00\x00\x00\x00\x00\x02\x01\x02",  # Short SRV
        # PTR whose name extends past its rdata length
        header(an=1) + b"\x00\x00\x0c\x00\x01\x00\x00\x00\x00\x00\x01\x01a\x00",
    ],
)
def test_malformed_packets_are_rejected(data):
    with pytest.raises(MalformedPacket):
        parse_message(data)


def test_overlong_name_is_rejected():
    labels = (b"\x3f" + b"a" * 63) * 5 + b"\0"
    with pytest.raises(MalformedPacket):
        parse_message(header(qd=1) + labels + b"\x00\x01\x00\x01")


def test_random_bytes_never_cause_other_exceptions():
    generator = random.Random(1234)
    valid = encode_message(
        response([ptr("_http._tcp", "A")], [srv("_http._tcp", "A", "h.local")])
    )
    for _ in range(5000):
        data = bytearray(valid)
        for _ in range(generator.randint(1, 8)):
            data[generator.randrange(len(data))] = generator.randrange(256)
        try:
            parse_message(bytes(data))
        except MalformedPacket:
            pass
    for _ in range(2000):
        data = bytes(generator.randrange(256) for _ in range(generator.randint(0, 200)))
        try:
            parse_message(data)
        except MalformedPacket:
            pass


@pytest.mark.parametrize(
    "text,kind,service_type,instance",
    [
        ("_services._dns-sd._udp.local", "meta", None, None),
        ("_http._tcp.local", "type", "_http._tcp", None),
        ("_HTTP._TCP.LOCAL", "type", "_http._tcp", None),
        ("_printer._sub._http._tcp.local", "subtype", "_http._tcp", None),
        ("Web._http._tcp.local", "instance", "_http._tcp", "Web"),
    ],
)
def test_service_name_classification(text, kind, service_type, instance):
    parsed = parse_service_name(n(text))
    assert (parsed.kind, parsed.service_type, parsed.instance) == (kind, service_type, instance)


@pytest.mark.parametrize(
    "text", ["host.local", "a.b.local", "_http._tcp.example.com", "local", "x._http._sctp.local"]
)
def test_other_names_are_not_service_names(text):
    assert parse_service_name(n(text)) is None
