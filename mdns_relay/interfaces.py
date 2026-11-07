"""Linux network interface discovery using only the standard library."""

from __future__ import annotations

import fcntl
import ipaddress
import socket
import struct
from dataclasses import dataclass, field
from typing import Iterable

_SIOCGIFFLAGS = 0x8913
_SIOCGIFADDR = 0x8915
_IFF_UP = 0x1
_IFF_LOOPBACK = 0x8
_IFF_MULTICAST = 0x1000
_IFREQ_NAME = "16s"
_IFA_UNUSABLE = 0x08 | 0x40  # IFA_F_DADFAILED, IFA_F_TENTATIVE


@dataclass(frozen=True, slots=True)
class InterfaceInfo:
    name: str
    index: int
    up: bool
    loopback: bool
    multicast: bool
    ipv4: tuple[str, ...] = field(default=())
    ipv6: tuple[str, ...] = field(default=())

    def has_family(self, family: int) -> bool:
        return bool(self.ipv4 if family == socket.AF_INET else self.ipv6)


def _read_flags(sock: socket.socket, name: bytes) -> int:
    request = struct.pack(f"{_IFREQ_NAME}h14x", name, 0)
    result = fcntl.ioctl(sock.fileno(), _SIOCGIFFLAGS, request)
    return struct.unpack_from("h", result, 16)[0] & 0xFFFF


def _read_ipv4(sock: socket.socket, name: bytes) -> tuple[str, ...]:
    request = struct.pack(f"{_IFREQ_NAME}16x", name)
    try:
        result = fcntl.ioctl(sock.fileno(), _SIOCGIFADDR, request)
    except OSError:
        return ()  # The interface has no IPv4 address.
    return (socket.inet_ntoa(result[20:24]),)


def parse_ipv6_table(lines: Iterable[str]) -> dict[str, list[str]]:
    """Parse /proc/net/if_inet6, leaving out addresses that can't be used yet."""
    table: dict[str, list[str]] = {}
    for line in lines:
        parts = line.split()
        if len(parts) != 6 or int(parts[4], 16) & _IFA_UNUSABLE:
            continue
        address = str(ipaddress.IPv6Address(bytes.fromhex(parts[0])))
        table.setdefault(parts[5], []).append(address)
    return table


def _read_ipv6_table() -> dict[str, list[str]]:
    try:
        with open("/proc/net/if_inet6", encoding="ascii") as handle:
            return parse_ipv6_table(handle)
    except OSError:
        return {}  # IPv6 is disabled on this system.


def list_interfaces() -> list[InterfaceInfo]:
    ipv6_table = _read_ipv6_table()
    results = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for index, name in socket.if_nameindex():
            encoded = name.encode()
            try:
                flags = _read_flags(sock, encoded)
            except OSError:
                continue  # The interface disappeared during the scan.
            results.append(
                InterfaceInfo(
                    name=name,
                    index=index,
                    up=bool(flags & _IFF_UP),
                    loopback=bool(flags & _IFF_LOOPBACK),
                    multicast=bool(flags & _IFF_MULTICAST),
                    ipv4=_read_ipv4(sock, encoded),
                    ipv6=tuple(ipv6_table.get(name, ())),
                )
            )
    return results
