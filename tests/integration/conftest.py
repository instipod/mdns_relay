"""Real packets across network namespaces. Requires root on Linux (a privileged container).

Two broadcast segments, each a bridge in its own namespace:

    client --- [client segment] --- relay --- [provider segment] --- provider
                                  \\- relay2 -/    (only in the two-relay test)
"""

from __future__ import annotations

import json
import os
import select
import shutil
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from pathlib import Path

import pytest

from mdns_relay.dns import MalformedPacket, encode_message, parse_message
from mdns_relay.transport import MDNS_IPV4_GROUP, MDNS_IPV6_GROUP, MDNS_PORT

NAMESPACES = ["segment", "client", "provider", "relay", "relay2"]
HTTP_PORT = 8080


def run(*args: str) -> None:
    subprocess.run(args, check=True, capture_output=True, text=True)


def in_ns(ns: str, *args: str) -> None:
    run("ip", "netns", "exec", ns, *args)


@contextmanager
def netns(name: str):
    """Run the block in a network namespace. Sockets created there remain in it."""
    original = os.open("/proc/self/ns/net", os.O_RDONLY)
    target = os.open(f"/var/run/netns/{name}", os.O_RDONLY)
    try:
        os.setns(target, os.CLONE_NEWNET)
        yield
    finally:
        os.setns(original, os.CLONE_NEWNET)
        os.close(original)
        os.close(target)


def _attach(ns: str, name: str, bridge: str, peer: str, ipv4: str, ipv6: str) -> None:
    run("ip", "link", "add", name, "type", "veth", "peer", "name", peer)
    run("ip", "link", "set", name, "netns", ns)
    run("ip", "link", "set", peer, "netns", "segment")
    in_ns("segment", "ip", "link", "set", peer, "master", bridge)
    in_ns("segment", "ip", "link", "set", peer, "up")
    in_ns(ns, "ip", "addr", "add", ipv4, "dev", name)
    in_ns(ns, "ip", "-6", "addr", "add", ipv6, "dev", name, "nodad")
    in_ns(ns, "ip", "link", "set", name, "up")


def _prepare_ipv6(ns: str) -> None:
    for setting in (
        "net.ipv6.conf.all.disable_ipv6=0",
        "net.ipv6.conf.default.disable_ipv6=0",
        "net.ipv6.conf.all.accept_dad=0",
        "net.ipv6.conf.default.accept_dad=0",
    ):
        in_ns(ns, "sysctl", "-qw", setting)


class Endpoint:
    """A simulated device on one segment, with sockets for both IP families."""

    def __init__(self, ns: str, iface: str) -> None:
        self.ns = ns
        self.iface = iface
        with netns(ns):
            self.index = socket.if_nametoindex(iface)
            self.socks = {
                socket.AF_INET: self._open_ipv4(),
                socket.AF_INET6: self._open_ipv6(),
            }

    def _base(self, family: int) -> socket.socket:
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.setblocking(False)
        return sock

    def _open_ipv4(self) -> socket.socket:
        sock = self._base(socket.AF_INET)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
        sock.bind(("0.0.0.0", MDNS_PORT))
        group = socket.inet_aton(MDNS_IPV4_GROUP)
        mreqn = struct.pack("=4s4si", group, b"\0\0\0\0", self.index)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreqn)
        # ip_mreqn selects the outgoing interface by index.
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, mreqn)
        return sock

    def _open_ipv6(self) -> socket.socket:
        sock = self._base(socket.AF_INET6)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 0)
        sock.bind(("::", MDNS_PORT))
        group = socket.inet_pton(socket.AF_INET6, MDNS_IPV6_GROUP)
        sock.setsockopt(
            socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, struct.pack("=16sI", group, self.index)
        )
        return sock

    def send(self, message, family: int) -> None:
        self.send_raw(encode_message(message), family)

    def _address(self, family: int) -> tuple:
        if family == socket.AF_INET:
            return (MDNS_IPV4_GROUP, MDNS_PORT)
        return (MDNS_IPV6_GROUP, MDNS_PORT, 0, self.index)

    def send_raw(self, data: bytes, family: int) -> None:
        self.socks[family].sendto(data, self._address(family))

    def send_from_other_port(self, message, family: int) -> None:
        with netns(self.ns):
            sock = socket.socket(family, socket.SOCK_DGRAM)
        try:
            if family == socket.AF_INET:
                mreqn = struct.pack("=4s4si", b"\0\0\0\0", b"\0\0\0\0", self.index)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, mreqn)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
            else:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 0)
            sock.sendto(encode_message(message), self._address(family))
        finally:
            sock.close()

    def receive(self, family: int, seconds: float = 0.6) -> list:
        """Collect messages for the given time, returning them parsed."""
        sock = self.socks[family]
        deadline = time.monotonic() + seconds
        messages = []
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return messages
            ready, _, _ = select.select([sock], [], [], remaining)
            if ready:
                data = sock.recv(9000)
                try:
                    messages.append(parse_message(data))
                except MalformedPacket:
                    pass

    def wait_for(self, family: int, predicate, seconds: float = 3.0):
        """Return the first message satisfying the predicate, or None."""
        sock = self.socks[family]
        deadline = time.monotonic() + seconds
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            ready, _, _ = select.select([sock], [], [], remaining)
            if ready:
                message = parse_message(sock.recv(9000))
                if predicate(message):
                    return message

    def drain(self) -> None:
        for sock in self.socks.values():
            while True:
                ready, _, _ = select.select([sock], [], [], 0)
                if not ready:
                    break
                sock.recv(9000)

    def close(self) -> None:
        for sock in self.socks.values():
            sock.close()


class RelayProcess:
    def __init__(self, ns: str, interfaces: list[str], rules_file: Path, *extra: str) -> None:
        self.ns = ns
        self.interfaces = interfaces
        self.rules_file = rules_file
        self.extra = extra
        self.process: subprocess.Popen | None = None

    def start(self) -> None:
        command = [
            "ip", "netns", "exec", self.ns,
            sys.executable, "-m", "mdns_relay",
            "--rules-file", str(self.rules_file),
            "--http-port", str(HTTP_PORT),
            "--no-browse",
            *self.extra,
        ]
        for name in self.interfaces:
            command += ["--interface", name]
        self.process = subprocess.Popen(command)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(f"relay in {self.ns} exited with {self.process.returncode}")
            try:
                self.api("GET", "/api/status")
                return
            except OSError:
                time.sleep(0.1)
        raise RuntimeError(f"relay in {self.ns} did not start")

    def stop(self) -> None:
        if self.process and self.process.poll() is None:
            self.process.terminate()
            self.process.wait(timeout=10)
        self.process = None

    def request(self, method: str, path: str, body=None, headers=None):
        """Return (status, decoded JSON or None) from the relay's API."""
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(
            f"http://127.0.0.1:{HTTP_PORT}{path}", data=data, method=method
        )
        if data is not None:
            request.add_header("Content-Type", "application/json")
        for key, value in (headers or {}).items():
            request.add_header(key, value)
        # The connection is created while in the namespace and used entirely within it.
        with netns(self.ns):
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            try:
                with opener.open(request, timeout=5) as response:
                    payload = response.read()
                    status = response.status
            except urllib.error.HTTPError as exc:
                payload = exc.read()
                status = exc.code
        return status, json.loads(payload) if payload else None

    def api(self, method: str, path: str, body=None):
        status, data = self.request(method, path, body)
        if status >= 400:
            raise AssertionError(f"{method} {path} returned {status}: {data}")
        return data

    def add_rule(self, service_type: str, provider: str, client: str, **fields) -> dict:
        return self.api(
            "POST",
            "/api/rules",
            {
                "service_type": service_type,
                "provider_iface": provider,
                "client_iface": client,
                **fields,
            },
        )

    def clear_rules(self) -> None:
        for rule in self.api("GET", "/api/rules")["rules"]:
            self.api("DELETE", f"/api/rules/{rule['id']}")

    def services(self) -> list[dict]:
        return self.api("GET", "/api/services")["services"]


@pytest.fixture(scope="session")
def topology():
    if os.geteuid() != 0 or not shutil.which("ip"):
        pytest.skip("integration tests need root and iproute2 (a privileged Linux container)")
    for ns in NAMESPACES:
        run("ip", "netns", "add", ns)
    try:
        for ns in NAMESPACES:
            _prepare_ipv6(ns)
            in_ns(ns, "ip", "link", "set", "lo", "up")
        for bridge in ("br-client", "br-provider"):
            in_ns("segment", "ip", "link", "add", bridge, "type", "bridge", "mcast_snooping", "0")
            in_ns("segment", "ip", "link", "set", bridge, "up")
        _attach("client", "c0", "br-client", "s-c0", "10.0.1.2/24", "fd01::2/64")
        _attach("relay", "r-client", "br-client", "s-rc", "10.0.1.1/24", "fd01::1/64")
        _attach("relay", "r-provider", "br-provider", "s-rp", "10.0.2.1/24", "fd02::1/64")
        _attach("provider", "p0", "br-provider", "s-p0", "10.0.2.2/24", "fd02::2/64")
        _attach("relay2", "r2-client", "br-client", "s-r2c", "10.0.1.3/24", "fd01::3/64")
        _attach("relay2", "r2-provider", "br-provider", "s-r2p", "10.0.2.3/24", "fd02::3/64")
        yield
    finally:
        for ns in NAMESPACES:
            subprocess.run(["ip", "netns", "del", ns], capture_output=True)


@pytest.fixture(scope="session")
def client(topology):
    endpoint = Endpoint("client", "c0")
    yield endpoint
    endpoint.close()


@pytest.fixture(scope="session")
def provider(topology):
    endpoint = Endpoint("provider", "p0")
    yield endpoint
    endpoint.close()


@pytest.fixture(scope="session")
def relay(topology, tmp_path_factory):
    process = RelayProcess(
        "relay", ["r-client", "r-provider"], tmp_path_factory.mktemp("relay") / "rules.json"
    )
    process.start()
    yield process
    process.stop()


@pytest.fixture(autouse=True)
def clean_state(request):
    """Give each test no rules and empty sockets."""
    if "relay" in request.fixturenames:
        request.getfixturevalue("relay").clear_rules()
    for name in ("client", "provider"):
        if name in request.fixturenames:
            request.getfixturevalue(name).drain()


@pytest.fixture(params=[socket.AF_INET, socket.AF_INET6], ids=["ipv4", "ipv6"])
def family(request):
    return request.param
