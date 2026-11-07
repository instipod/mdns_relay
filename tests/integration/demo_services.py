"""Announces fictional services on one interface, for the demo in demo.sh."""

from __future__ import annotations

import socket
import struct
import sys
import time

from mdns_relay.dns import (
    FLAG_QR,
    META_QUERY_NAME,
    TYPE_A,
    TYPE_PTR,
    TYPE_SRV,
    TYPE_TXT,
    Message,
    Record,
    SrvData,
    encode_message,
    name_from_text,
)
from mdns_relay.transport import MDNS_IPV4_GROUP, MDNS_PORT

SERVICES = {
    "lan": [
        ("Office Printer", "_ipp._tcp", "office-printer", 631, ["rp=ipp/print", "ty=Demo Printer"], "10.10.1.20"),
        ("Team File Share", "_smb._tcp", "fileshare", 445, [], "10.10.1.21"),
    ],
    "iot": [
        ("Living Room Speaker", "_airplay._tcp", "speaker", 7000, ["model=Demo Speaker"], "10.10.2.30"),
        ("Kitchen Speaker", "_airplay._tcp", "kitchen", 7000, ["model=Demo Speaker"], "10.10.2.31"),
        ("Thermostat", "_hap._tcp", "thermostat", 8080, ["md=Demo Thermostat"], "10.10.2.32"),
    ],
}


def build_announcement(service) -> Message:
    instance, service_type, host, port, txt, address = service
    type_name = (*name_from_text(service_type), b"local")
    instance_name = (instance.encode(), *type_name)
    host_name = (host.encode(), b"local")
    txt_data = b"".join(bytes([len(i)]) + i.encode() for i in txt) or b"\0"
    return Message(
        flags=FLAG_QR | 0x0400,
        answers=[
            Record(type_name, TYPE_PTR, 4500, instance_name),
            Record(META_QUERY_NAME, TYPE_PTR, 4500, type_name),
        ],
        additionals=[
            Record(instance_name, TYPE_SRV, 120, SrvData(0, 0, port, host_name)),
            Record(instance_name, TYPE_TXT, 4500, txt_data),
            Record(host_name, TYPE_A, 120, socket.inet_aton(address)),
        ],
    )


def main() -> None:
    iface, segment = sys.argv[1], sys.argv[2]
    index = socket.if_nametoindex(iface)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    sock.setsockopt(
        socket.IPPROTO_IP,
        socket.IP_MULTICAST_IF,
        struct.pack("=4s4si", b"\0\0\0\0", b"\0\0\0\0", index),
    )
    sock.bind(("0.0.0.0", MDNS_PORT))
    while True:
        for service in SERVICES[segment]:
            sock.sendto(encode_message(build_announcement(service)), (MDNS_IPV4_GROUP, MDNS_PORT))
        time.sleep(10)


if __name__ == "__main__":
    main()
