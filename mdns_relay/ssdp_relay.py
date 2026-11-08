"""SSDP packet flow: relayed announcements and proxied searches.

M-SEARCH replies are unicast to whoever sent the search. Each relayed search is
therefore sent from its own socket, so that replies can be matched to the client
and passed through the rules before being forwarded.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, Protocol

from . import policy
from .dns import MalformedPacket
from .rules import PROTOCOL_SSDP
from .services import DeviceTable
from .ssdp import (
    KIND_NOTIFY,
    KIND_RESPONSE,
    KIND_SEARCH,
    SsdpMessage,
    build_search,
    locations_allowed,
    parse_message,
)
from .transport import FAMILY_NAMES, SSDP, ReceivedPacket

if TYPE_CHECKING:
    from .relay import Relay

log = logging.getLogger(__name__)

MAX_SEARCHES = 256
MAX_SEARCHES_PER_CLIENT = 16
MAX_WAIT = 5
EXPIRE_INTERVAL = 1.0
BROWSE_MX = 2


class SearchHandle(Protocol):
    def send(self, data: bytes) -> None: ...
    def close(self) -> None: ...


OpenSearch = Callable[[int, int, Callable[[ReceivedPacket], None]], SearchHandle]


@dataclass(slots=True)
class PendingSearch:
    family: int
    provider: str
    client: str | None  # None for this app's own discovery searches.
    client_address: str | None
    client_port: int
    socket: SearchHandle
    expires: float


class SsdpRelay:
    def __init__(
        self,
        relay: Relay,
        open_search: OpenSearch,
        table: DeviceTable | None = None,
        max_searches: int = MAX_SEARCHES,
        max_per_client: int = MAX_SEARCHES_PER_CLIENT,
    ) -> None:
        self.relay = relay
        self.table = table or DeviceTable()
        self.max_searches = max_searches
        self.max_per_client = max_per_client
        self._open_search = open_search
        self._pending: dict[tuple, PendingSearch] = {}

    @property
    def pending_count(self) -> int:
        return len(self._pending)

    def _drop(self, packet, iface, reason, message=None, destination=None) -> None:
        self.relay._drop(packet, iface, reason, message, destination, protocol=PROTOCOL_SSDP)

    def _record_relayed(self, packet, source, message, destination) -> None:
        self.relay.counters["relayed"] += 1
        self.relay._record_activity(
            packet, source, message, "relayed", None, destination, protocol=PROTOCOL_SSDP
        )

    def handle_packet(self, packet: ReceivedPacket) -> None:
        """Process one multicast packet. Failure always results in no relay."""
        relay = self.relay
        info = relay._by_index.get(packet.ifindex)
        if info is None:
            relay.counters["ignored_inactive_interface"] += 1
            return
        iface = info.name
        relay.counters["received"] += 1
        relay.interface_counters[iface]["received"] += 1
        try:
            self._process(packet, iface)
        except Exception:
            log.exception("error handling SSDP packet from %s", packet.source)
            self._drop(packet, iface, "internal_error")

    def _parse(self, packet: ReceivedPacket, iface: str) -> SsdpMessage | None:
        try:
            return parse_message(packet.data)
        except MalformedPacket:
            self._drop(packet, iface, "malformed")
            return None

    def _process(self, packet: ReceivedPacket, iface: str) -> None:
        relay = self.relay
        if packet.destination != SSDP.groups[packet.family]:
            self._drop(packet, iface, "unicast")
            return
        if (packet.family, iface, relay.digest(packet.data)) in relay._sent:
            relay.counters["drop_echo"] += 1
            return
        message = self._parse(packet, iface)
        if message is None:
            return
        if message.kind == KIND_RESPONSE:
            self._drop(packet, iface, "malformed", message)
            return
        if message.kind == KIND_NOTIFY:
            if not locations_allowed(message, packet.source):
                self._drop(packet, iface, "bad_location", message)
                return
            self.table.update(
                iface, message, FAMILY_NAMES[packet.family], packet.source, relay.clock()
            )
        rules = relay.store.rules
        for destination in relay._active:
            if destination == iface:
                continue
            if (packet.family, relay._active[destination].index) not in relay.ssdp_joined:
                continue
            decision = policy.filter_ssdp(message, iface, destination, rules)
            if decision.message is None:
                self._drop(packet, iface, decision.reason, message, destination)
            elif message.kind == KIND_SEARCH:
                self._relay_search(packet, iface, destination, message)
            else:
                self._relay_notify(packet, iface, destination, message)

    def _relay_notify(self, packet, source, destination, message) -> None:
        relay = self.relay
        if (packet.family, destination, relay.digest(packet.data)) in relay._sent:
            relay.counters["drop_duplicate"] += 1
            return
        if relay._transmit(packet.family, destination, packet.data, relay.ssdp_transports):
            self._record_relayed(packet, source, message, destination)
        else:
            self._drop(packet, source, "send_failed", message, destination)

    def _relay_search(self, packet, source, destination, message) -> None:
        # Identical searches are normal, from different clients and from one
        # client's retransmissions, so they are not treated as duplicates. The
        # per-client limit is what bounds a search looping between two relays.
        relay = self.relay
        key = (packet.family, packet.source, packet.source_port, source, destination)
        wait = min(message.mx, MAX_WAIT) + 1
        entry = self._pending.get(key) or self._open(
            key, packet.family, destination, source, packet.source, packet.source_port
        )
        if entry is None:
            self._drop(packet, source, "search_limit", message, destination)
            return
        entry.expires = max(entry.expires, relay.clock() + wait)
        try:
            entry.socket.send(packet.data)
        except OSError as exc:
            log.warning("SSDP search failed on %s: %s", destination, exc)
            relay.counters["send_errors"] += 1
            self._drop(packet, source, "send_failed", message, destination)
            return
        relay.interface_counters[destination]["sent"] += 1
        self._record_relayed(packet, source, message, destination)

    def _open(
        self,
        key: tuple,
        family: int,
        provider: str,
        client: str | None,
        client_address: str | None,
        client_port: int,
    ) -> PendingSearch | None:
        self.expire()
        if len(self._pending) >= self.max_searches:
            return None
        if client_address is not None and self.max_per_client <= sum(
            1
            for entry in self._pending.values()
            if entry.family == family and entry.client_address == client_address
        ):
            return None
        try:
            handle = self._open_search(
                family,
                self.relay._active[provider].index,
                lambda packet: self.handle_reply(key, packet),
            )
        except OSError as exc:
            log.warning("cannot open SSDP search socket: %s", exc)
            return None
        entry = PendingSearch(
            family, provider, client, client_address, client_port, handle, self.relay.clock()
        )
        self._pending[key] = entry
        return entry

    def handle_reply(self, key: tuple, packet: ReceivedPacket) -> None:
        """Process a unicast reply to a relayed search."""
        relay = self.relay
        entry = self._pending.get(key)
        if entry is None or entry.expires <= relay.clock():
            relay.counters["ssdp_reply_unmatched"] += 1
            return
        relay.counters["received"] += 1
        relay.interface_counters[entry.provider]["received"] += 1
        try:
            self._process_reply(entry, packet)
        except Exception:
            log.exception("error handling SSDP reply from %s", packet.source)
            self._drop(packet, entry.provider, "internal_error")

    def _process_reply(self, entry: PendingSearch, packet: ReceivedPacket) -> None:
        relay = self.relay
        provider = entry.provider
        info = relay._by_index.get(packet.ifindex)
        if info is None or info.name != provider:
            self._drop(packet, provider, "wrong_interface")
            return
        message = self._parse(packet, provider)
        if message is None:
            return
        if message.kind != KIND_RESPONSE:
            self._drop(packet, provider, "malformed", message)
            return
        if not locations_allowed(message, packet.source):
            self._drop(packet, provider, "bad_location", message)
            return
        self.table.update(
            provider, message, FAMILY_NAMES[packet.family], packet.source, relay.clock()
        )
        if entry.client is None:
            return
        decision = policy.filter_ssdp(message, provider, entry.client, relay.store.rules)
        if decision.message is None:
            self._drop(packet, provider, decision.reason, message, entry.client)
            return
        client_info = relay._active.get(entry.client)
        transport = relay.ssdp_transports.get(entry.family)
        if client_info is None or transport is None:
            self._drop(packet, provider, "send_failed", message, entry.client)
            return
        try:
            transport.send_unicast(
                client_info.index, packet.data, entry.client_address, entry.client_port
            )
        except OSError as exc:
            log.warning("SSDP reply to %s failed: %s", entry.client_address, exc)
            relay.counters["send_errors"] += 1
            self._drop(packet, provider, "send_failed", message, entry.client)
            return
        relay.interface_counters[entry.client]["sent"] += 1
        self._record_relayed(packet, provider, message, entry.client)

    def _close(self, key: tuple) -> None:
        self._pending.pop(key).socket.close()

    def expire(self) -> None:
        now = self.relay.clock()
        for key, entry in list(self._pending.items()):
            if entry.expires <= now:
                self._close(key)

    def sync_interfaces(self) -> None:
        """Close searches that depend on an interface that is no longer active."""
        active = self.relay._active
        for key, entry in list(self._pending.items()):
            if entry.provider not in active or (
                entry.client is not None and entry.client not in active
            ):
                self._close(key)

    def close(self) -> None:
        for key in list(self._pending):
            self._close(key)

    def browse_once(self) -> None:
        relay = self.relay
        for name, info in relay._active.items():
            for family in relay.ssdp_transports:
                if (family, info.index) not in relay.ssdp_joined:
                    continue
                key = (family, None, 0, None, name)
                entry = self._pending.get(key) or self._open(key, family, name, None, None, 0)
                if entry is None:
                    continue
                entry.expires = max(entry.expires, relay.clock() + BROWSE_MX + 1)
                data = build_search(SSDP.groups[family], SSDP.port, mx=BROWSE_MX)
                try:
                    entry.socket.send(data)
                except OSError as exc:
                    log.warning("SSDP search failed on %s: %s", name, exc)
                    relay.counters["send_errors"] += 1
                    continue
                relay.interface_counters[name]["sent"] += 1
                relay.counters["browse_queries_sent"] += 1

    async def run(self) -> None:
        while True:
            await asyncio.sleep(EXPIRE_INTERVAL)
            self.expire()
