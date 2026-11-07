"""Packet flow, loop protection, counters and active browsing."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import socket
import time
from collections import Counter, OrderedDict, deque
from typing import Callable, Iterable, Protocol

from . import policy
from .dns import (
    TYPE_A,
    TYPE_AAAA,
    TYPE_PTR,
    TYPE_SRV,
    TYPE_TXT,
    META_QUERY_NAME,
    MalformedPacket,
    Message,
    Question,
    encode_message,
    name_from_text,
    name_text,
    parse_message,
)
from .interfaces import InterfaceInfo, list_interfaces
from .rules import RuleStore
from .services import ServiceTable
from .transport import FAMILY_NAMES, GROUPS, MDNS_PORT, ReceivedPacket

log = logging.getLogger(__name__)

ECHO_WINDOW = 1.0
MAX_ACTIVITY = 500
RESCAN_INTERVAL = 5.0
PRUNE_INTERVAL = 10.0
BROWSE_MAX_INTERVAL = 60.0
MAX_QUESTIONS_PER_PACKET = 20

ACTION_RELAYED = "relayed"
ACTION_DROPPED = "dropped"


class Transport(Protocol):
    def join(self, ifindex: int) -> None: ...
    def leave(self, ifindex: int) -> None: ...
    def send(self, ifindex: int, data: bytes) -> None: ...


class RecentPackets:
    """Remembers keys for a fixed time window, using bounded memory."""

    def __init__(self, window: float, clock: Callable[[], float], max_entries: int = 8192) -> None:
        self.window = window
        self.clock = clock
        self.max_entries = max_entries
        self._entries: OrderedDict[tuple, float] = OrderedDict()

    def _purge(self, now: float) -> None:
        while self._entries:
            key, expires = next(iter(self._entries.items()))
            if expires > now and len(self._entries) <= self.max_entries:
                return
            del self._entries[key]

    def add(self, key: tuple) -> None:
        now = self.clock()
        self._entries[key] = now + self.window
        self._entries.move_to_end(key)
        self._purge(now)

    def __contains__(self, key: tuple) -> bool:
        expires = self._entries.get(key)
        return expires is not None and expires > self.clock()


def _digest(data: bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=16).digest()


def _summarize(message: Message) -> str:
    names = [name_text(q.name) for q in message.questions]
    names += [name_text(r.name) for r in message.answers]
    unique = list(dict.fromkeys(names))
    text = ", ".join(unique[:3])
    if len(unique) > 3:
        text += f" and {len(unique) - 3} more"
    return text or "(empty)"


class Relay:
    def __init__(
        self,
        store: RuleStore,
        *,
        table: ServiceTable | None = None,
        pinned_interfaces: Iterable[str] | None = None,
        browse: bool = True,
        interface_lister: Callable[[], list[InterfaceInfo]] = list_interfaces,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.store = store
        self.table = table or ServiceTable()
        self.pinned = frozenset(pinned_interfaces) if pinned_interfaces else None
        self.browse = browse
        self.clock = clock
        self.started = clock()
        self.transports: dict[int, Transport] = {}
        self.interfaces: dict[str, InterfaceInfo] = {}
        self.counters: Counter = Counter()
        self.interface_counters: dict[str, Counter] = {}
        self.activity: deque[dict] = deque(maxlen=MAX_ACTIVITY)
        self._activity_version = 0
        self._list_interfaces = interface_lister
        self._active: dict[str, InterfaceInfo] = {}
        self._by_index: dict[int, InterfaceInfo] = {}
        self._joined: set[tuple[int, int]] = set()
        self._sent = RecentPackets(ECHO_WINDOW, clock)
        self._browse_wake = asyncio.Event()

    @property
    def state_version(self) -> tuple:
        return (self.table.version, self.store.version, self._activity_version)

    def add_transport(self, family: int, transport: Transport) -> None:
        self.transports[family] = transport

    def is_enabled(self, info: InterfaceInfo) -> bool:
        if not info.up or info.loopback or not info.multicast:
            return False
        if self.pinned is not None:
            return info.name in self.pinned
        return info.name not in self.store.disabled_interfaces

    def active_names(self) -> list[str]:
        return sorted(self._active)

    def sync_interfaces(self) -> None:
        """Match multicast memberships to the current interfaces and settings."""
        infos = {info.name: info for info in self._list_interfaces()}
        active = {name: info for name, info in infos.items() if self.is_enabled(info)}
        wanted = {
            (family, info.index)
            for info in active.values()
            for family in self.transports
            if info.has_family(family)
        }
        for family, index in self._joined - wanted:
            self.transports[family].leave(index)
            self._joined.discard((family, index))
        joined_new = False
        for family, index in wanted - self._joined:
            try:
                self.transports[family].join(index)
            except OSError as exc:
                log.warning(
                    "cannot join %s multicast on interface %d: %s",
                    FAMILY_NAMES[family], index, exc,
                )
                continue
            self._joined.add((family, index))
            joined_new = True

        for name in self._active.keys() - active.keys():
            self.table.forget_interface(name)
        self.interfaces = infos
        self._active = active
        self._by_index = {info.index: info for info in active.values()}
        for name in active:
            self.interface_counters.setdefault(name, Counter())
        if joined_new:
            self._browse_wake.set()

    def _record_activity(
        self,
        packet: ReceivedPacket,
        source: str,
        message: Message | None,
        action: str,
        reason: str | None,
        destination: str | None = None,
    ) -> None:
        kind = None
        summary = ""
        if message is not None:
            kind = "response" if message.is_response else "query"
            summary = _summarize(message)
        self.activity.append(
            {
                "time": self.clock(),
                "family": FAMILY_NAMES[packet.family],
                "source": source,
                "source_address": packet.source,
                "destination": destination,
                "kind": kind,
                "action": action,
                "reason": reason,
                "summary": summary,
            }
        )
        self._activity_version += 1

    def _drop(
        self,
        packet: ReceivedPacket,
        iface: str,
        reason: str,
        message: Message | None = None,
        destination: str | None = None,
    ) -> None:
        self.counters[f"drop_{reason}"] += 1
        self.interface_counters[iface]["dropped"] += 1
        self._record_activity(packet, iface, message, ACTION_DROPPED, reason, destination)

    def handle_packet(self, packet: ReceivedPacket) -> None:
        """Process one received packet. Failure always results in no relay."""
        info = self._by_index.get(packet.ifindex)
        if info is None:
            self.counters["ignored_inactive_interface"] += 1
            return
        iface = info.name
        self.counters["received"] += 1
        self.interface_counters[iface]["received"] += 1
        try:
            self._process(packet, iface)
        except Exception:
            log.exception("error handling packet from %s", packet.source)
            self._drop(packet, iface, "internal_error")

    def _process(self, packet: ReceivedPacket, iface: str) -> None:
        if packet.destination != GROUPS[packet.family]:
            self._drop(packet, iface, "unicast")
            return
        if (packet.family, iface, _digest(packet.data)) in self._sent:
            self.counters["drop_echo"] += 1
            return
        try:
            message = parse_message(packet.data)
        except MalformedPacket:
            self._drop(packet, iface, "malformed")
            return
        if not message.is_standard:
            self._drop(packet, iface, "malformed", message)
            return
        if packet.source_port != MDNS_PORT:
            self._drop(packet, iface, "legacy_source_port", message)
            return

        self.table.update(iface, message, FAMILY_NAMES[packet.family], self.clock())

        rules = self.store.rules
        for destination in self._active:
            if destination != iface:
                self._relay_to(packet, iface, destination, message, rules)

    def _relay_to(self, packet, source, destination, message, rules) -> None:
        if (packet.family, self._active[destination].index) not in self._joined:
            return
        decision = policy.filter_packet(message, source, destination, rules, self.table)
        for reason, count in decision.dropped.items():
            self.counters[f"records_dropped_{reason}"] += count
        if decision.message is None:
            self._drop(packet, source, decision.reason, message, destination)
            return
        data = encode_message(decision.message)
        key = (packet.family, destination, _digest(data))
        if key in self._sent:
            # A second relay or a retransmission produced what was just sent.
            self.counters["drop_duplicate"] += 1
            return
        if self._transmit(packet.family, destination, data):
            self.counters["relayed"] += 1
            self._record_activity(
                packet, source, decision.message, ACTION_RELAYED, None, destination
            )
        else:
            self._drop(packet, source, "send_failed", message, destination)

    def _transmit(self, family: int, iface: str, data: bytes) -> bool:
        info = self._active[iface]
        self._sent.add((family, iface, _digest(data)))
        try:
            self.transports[family].send(info.index, data)
        except OSError as exc:
            log.warning("send failed on %s (%s): %s", iface, FAMILY_NAMES[family], exc)
            self.counters["send_errors"] += 1
            return False
        self.interface_counters[iface]["sent"] += 1
        return True

    def build_browse_messages(self, iface: str) -> list[Message]:
        """Build this app's own discovery queries for one interface."""
        questions = [Question(META_QUERY_NAME, TYPE_PTR)]
        for service_type in sorted(self.table.service_types(iface)):
            questions.append(Question((*name_from_text(service_type), b"local"), TYPE_PTR))
        instances, hosts = self.table.incomplete(iface)
        for name in instances:
            questions.append(Question(name, TYPE_SRV))
            questions.append(Question(name, TYPE_TXT))
        for host in hosts:
            questions.append(Question(host, TYPE_A))
            questions.append(Question(host, TYPE_AAAA))
        return [
            Message(questions=questions[start : start + MAX_QUESTIONS_PER_PACKET])
            for start in range(0, len(questions), MAX_QUESTIONS_PER_PACKET)
        ]

    def browse_once(self) -> None:
        for name, info in self._active.items():
            messages = self.build_browse_messages(name)
            for family in self.transports:
                if (family, info.index) not in self._joined:
                    continue
                for message in messages:
                    if self._transmit(family, name, encode_message(message)):
                        self.counters["browse_queries_sent"] += 1

    async def _rescan_loop(self) -> None:
        while True:
            await asyncio.sleep(RESCAN_INTERVAL)
            try:
                self.sync_interfaces()
            except OSError as exc:
                log.warning("interface scan failed: %s", exc)

    async def _prune_loop(self) -> None:
        while True:
            await asyncio.sleep(PRUNE_INTERVAL)
            self.table.prune(self.clock())

    async def _browse_loop(self) -> None:
        delay = 1.0
        while True:
            try:
                await asyncio.wait_for(self._browse_wake.wait(), delay)
                self._browse_wake.clear()
                delay = 1.0
                continue
            except TimeoutError:
                pass
            self.browse_once()
            delay = min(delay * 2, BROWSE_MAX_INTERVAL)

    async def run(self) -> None:
        tasks = [self._rescan_loop(), self._prune_loop()]
        if self.browse:
            tasks.append(self._browse_loop())
        await asyncio.gather(*tasks)

    def rule_status(self, rule) -> list[str]:
        """Return the rule's problems, which are empty when it can relay."""
        problems = []
        for label, name in (("Provider", rule.provider_iface), ("Client", rule.client_iface)):
            if name not in self.interfaces:
                problems.append(f"{label} interface {name} does not exist")
            elif name not in self._active:
                problems.append(f"{label} interface {name} is not active")
        return problems

    def relay_targets(self, service: dict) -> list[str]:
        """Return the client interfaces that an enabled rule exposes a service to."""
        targets = {
            rule.client_iface
            for rule in self.store.rules
            if rule.enabled
            and rule.provider_iface == service["iface"]
            and rule.matches_instance(service["service_type"], service["instance"])
        }
        return sorted(targets)
