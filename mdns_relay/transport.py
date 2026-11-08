"""Linux multicast UDP transport: one socket per IP family."""

from __future__ import annotations

import asyncio
import logging
import socket
import struct
from dataclasses import dataclass
from typing import Callable

log = logging.getLogger(__name__)

MDNS_PORT = 5353
MDNS_IPV4_GROUP = "224.0.0.251"
MDNS_IPV6_GROUP = "ff02::fb"
HOP_LIMIT = 255
SSDP_PORT = 1900
SSDP_IPV4_GROUP = "239.255.255.250"
SSDP_IPV6_GROUP = "ff02::c"
SSDP_HOP_LIMIT = 2
MAX_PACKET = 9000
_MAX_READS_PER_WAKEUP = 64

# Linux values, for Python builds that don't export these names.
_IP_PKTINFO = getattr(socket, "IP_PKTINFO", 8)
_IP_MULTICAST_ALL = 49
_IPV6_MULTICAST_ALL = 29

_ADDRESS_SIZE = {socket.AF_INET: 4, socket.AF_INET6: 16}
GROUPS = {socket.AF_INET: MDNS_IPV4_GROUP, socket.AF_INET6: MDNS_IPV6_GROUP}
SSDP_GROUPS = {socket.AF_INET: SSDP_IPV4_GROUP, socket.AF_INET6: SSDP_IPV6_GROUP}
FAMILY_NAMES = {socket.AF_INET: "IPv4", socket.AF_INET6: "IPv6"}


@dataclass(frozen=True, slots=True)
class MulticastConfig:
    port: int
    groups: dict[int, str]
    hop_limit: int


MDNS = MulticastConfig(MDNS_PORT, GROUPS, HOP_LIMIT)
SSDP = MulticastConfig(SSDP_PORT, SSDP_GROUPS, SSDP_HOP_LIMIT)


@dataclass(frozen=True, slots=True)
class ReceivedPacket:
    family: int
    ifindex: int
    source: str
    source_port: int
    destination: str
    data: bytes


def _send_ipv4(sock: socket.socket, ifindex: int, data: bytes, address: tuple) -> None:
    # in_pktinfo: the kernel takes the outgoing interface from ipi_ifindex
    # and selects a source address belonging to that interface.
    pktinfo = struct.pack("=I4s4s", ifindex, b"\0\0\0\0", b"\0\0\0\0")
    sock.sendmsg([data], [(socket.IPPROTO_IP, _IP_PKTINFO, pktinfo)], 0, address)


def _send(
    sock: socket.socket, family: int, ifindex: int, data: bytes, host: str, port: int
) -> None:
    if family == socket.AF_INET:
        _send_ipv4(sock, ifindex, data, (host, port))
    else:
        sock.sendto(data, (host, port, 0, ifindex))


def _parse_pktinfo(family: int, ancillary: list) -> tuple[int, str] | None:
    for level, kind, payload in ancillary:
        if (
            family == socket.AF_INET
            and level == socket.IPPROTO_IP
            and kind == _IP_PKTINFO
            and len(payload) >= 12
        ):
            ifindex, _, destination = struct.unpack_from("=I4s4s", payload)
            return ifindex, socket.inet_ntoa(destination)
        if (
            family == socket.AF_INET6
            and level == socket.IPPROTO_IPV6
            and kind == socket.IPV6_PKTINFO
            and len(payload) >= 20
        ):
            destination, ifindex = struct.unpack_from("=16sI", payload)
            return ifindex, socket.inet_ntop(socket.AF_INET6, destination)
    return None


def _drain(sock: socket.socket, family: int, on_packet: Callable[[ReceivedPacket], None]) -> None:
    control_size = socket.CMSG_SPACE(32)
    for _ in range(_MAX_READS_PER_WAKEUP):
        try:
            data, ancillary, flags, address = sock.recvmsg(MAX_PACKET, control_size)
        except (BlockingIOError, InterruptedError):
            return
        except OSError as exc:
            log.warning("receive failed on %s: %s", FAMILY_NAMES[family], exc)
            return
        if flags & socket.MSG_TRUNC:
            continue
        info = _parse_pktinfo(family, ancillary)
        if info is None:
            continue
        ifindex, destination = info
        on_packet(ReceivedPacket(family, ifindex, address[0], address[1], destination, data))


class MulticastTransport:
    def __init__(
        self,
        family: int,
        on_packet: Callable[[ReceivedPacket], None],
        config: MulticastConfig = MDNS,
    ) -> None:
        self.family = family
        self.on_packet = on_packet
        self.config = config
        self._loop: asyncio.AbstractEventLoop | None = None
        self.sock = self._create_socket()

    def _create_socket(self) -> socket.socket:
        sock = socket.socket(self.family, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        try:
            sock.setblocking(False)
            # Shared with Avahi, systemd-resolved or a UPnP daemon if they are running.
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            if self.family == socket.AF_INET:
                sock.setsockopt(socket.IPPROTO_IP, _IP_PKTINFO, 1)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, self.config.hop_limit)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
                # Receive only from groups this socket joined. Otherwise another
                # program's join would deliver packets from inactive interfaces.
                sock.setsockopt(socket.IPPROTO_IP, _IP_MULTICAST_ALL, 0)
                sock.bind(("0.0.0.0", self.config.port))
            else:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVPKTINFO, 1)
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, self.config.hop_limit)
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 0)
                try:
                    sock.setsockopt(socket.IPPROTO_IPV6, _IPV6_MULTICAST_ALL, 0)
                except OSError:
                    pass  # Older kernels. The relay still checks the interface.
                sock.bind(("::", self.config.port))
        except BaseException:
            sock.close()
            raise
        return sock

    def start(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop
        loop.add_reader(self.sock.fileno(), self._on_readable)

    def close(self) -> None:
        if self._loop is not None:
            self._loop.remove_reader(self.sock.fileno())
        self.sock.close()

    def _membership(self, ifindex: int) -> bytes:
        group = socket.inet_pton(self.family, self.config.groups[self.family])
        if self.family == socket.AF_INET:
            return struct.pack("=4s4si", group, b"\0\0\0\0", ifindex)
        return struct.pack("=16sI", group, ifindex)

    def join(self, ifindex: int) -> None:
        request = self._membership(ifindex)
        if self.family == socket.AF_INET:
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, request)
        else:
            self.sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, request)

    def leave(self, ifindex: int) -> None:
        request = self._membership(ifindex)
        try:
            if self.family == socket.AF_INET:
                self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_DROP_MEMBERSHIP, request)
            else:
                self.sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_LEAVE_GROUP, request)
        except OSError:
            pass  # The interface has already gone.

    def send(self, ifindex: int, data: bytes) -> None:
        _send(
            self.sock, self.family, ifindex, data,
            self.config.groups[self.family], self.config.port,
        )

    def send_unicast(self, ifindex: int, data: bytes, host: str, port: int) -> None:
        _send(self.sock, self.family, ifindex, data, host, port)

    def _on_readable(self) -> None:
        _drain(self.sock, self.family, self.on_packet)


class SearchSocket:
    """A short-lived socket that sends one client's search and receives the replies."""

    def __init__(
        self,
        family: int,
        ifindex: int,
        config: MulticastConfig,
        on_packet: Callable[[ReceivedPacket], None],
    ) -> None:
        self.family = family
        self.ifindex = ifindex
        self.config = config
        self.on_packet = on_packet
        self._loop: asyncio.AbstractEventLoop | None = None
        self.sock = socket.socket(family, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        try:
            self.sock.setblocking(False)
            if family == socket.AF_INET:
                self.sock.setsockopt(socket.IPPROTO_IP, _IP_PKTINFO, 1)
                self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, config.hop_limit)
                self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
                self.sock.bind(("0.0.0.0", 0))
            else:
                self.sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                self.sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVPKTINFO, 1)
                self.sock.setsockopt(
                    socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, config.hop_limit
                )
                self.sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 0)
                self.sock.bind(("::", 0))
        except BaseException:
            self.sock.close()
            raise

    def start(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop
        loop.add_reader(self.sock.fileno(), self._on_readable)

    def close(self) -> None:
        if self._loop is not None:
            self._loop.remove_reader(self.sock.fileno())
        self.sock.close()

    def send(self, data: bytes) -> None:
        _send(
            self.sock, self.family, self.ifindex, data,
            self.config.groups[self.family], self.config.port,
        )

    def _on_readable(self) -> None:
        _drain(self.sock, self.family, self.on_packet)
