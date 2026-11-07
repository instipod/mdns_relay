"""Table of services and hosts learned from mDNS responses, per interface.

Every entry comes from untrusted network traffic, so all sizes are capped. Once
a cap is reached new entries are refused until existing ones expire.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field

from .dns import (
    TYPE_A,
    TYPE_AAAA,
    TYPE_PTR,
    TYPE_SRV,
    TYPE_TXT,
    Message,
    Name,
    Record,
    SrvData,
    label_text,
    name_key,
    name_text,
    parse_service_name,
)

MAX_SERVICES = 4096
MAX_HOSTS = 4096
MAX_TYPES = 1024
MAX_ADDRESSES_PER_HOST = 16
MAX_TXT_ITEMS = 64
MAX_TXT_CHARS = 2048


def parse_txt(rdata: bytes) -> list[str]:
    items: list[str] = []
    chars = 0
    position = 0
    while position < len(rdata) and len(items) < MAX_TXT_ITEMS:
        length = rdata[position]
        item = rdata[position + 1 : position + 1 + length]
        position += 1 + length
        if not item:
            continue
        text = label_text(item)
        chars += len(text)
        if chars > MAX_TXT_CHARS:
            break
        items.append(text)
    return items


@dataclass(slots=True)
class ServiceEntry:
    iface: str
    service_type: str
    instance: str
    name: Name
    first_seen: float
    last_seen: float
    expires: float
    host: Name | None = None
    port: int | None = None
    txt: list[str] = field(default_factory=list)
    families: set[str] = field(default_factory=set)


class ServiceTable:
    def __init__(
        self,
        max_services: int = MAX_SERVICES,
        max_hosts: int = MAX_HOSTS,
    ) -> None:
        self.max_services = max_services
        self.max_hosts = max_hosts
        self.version = 0
        self.refused = 0
        self._services: dict[tuple[str, Name], ServiceEntry] = {}
        self._hosts: dict[tuple[str, Name], dict[str, float]] = {}
        self._host_refs: dict[tuple[str, Name], set[Name]] = {}
        self._types: dict[tuple[str, str], float] = {}

    def update(self, iface: str, message: Message, family: str, now: float) -> None:
        """Learn from a response. Queries are ignored because they prove nothing."""
        if not message.is_response:
            return
        for record in (*message.answers, *message.additionals):
            if record.rtype == TYPE_PTR:
                self._learn_ptr(iface, record, family, now)
            elif record.rtype == TYPE_SRV:
                self._learn_srv(iface, record, family, now)
            elif record.rtype == TYPE_TXT:
                self._learn_txt(iface, record, family, now)
            elif record.rtype in (TYPE_A, TYPE_AAAA):
                self._learn_address(iface, record, now)

    def _entry(
        self, iface: str, name: Name, service_type: str, instance: str, family: str, now: float
    ) -> ServiceEntry | None:
        key = (iface, name_key(name))
        entry = self._services.get(key)
        if entry is None:
            if len(self._services) >= self.max_services:
                self.refused += 1
                return None
            entry = ServiceEntry(iface, service_type, instance, name, now, now, now)
            self._services[key] = entry
            self.version += 1
        entry.last_seen = now
        if family not in entry.families:
            entry.families.add(family)
            self.version += 1
        return entry

    def _remove(self, iface: str, key: Name) -> None:
        entry = self._services.pop((iface, key), None)
        if entry is None:
            return
        self._unlink_host(entry)
        self.version += 1

    def _unlink_host(self, entry: ServiceEntry) -> None:
        if entry.host is None:
            return
        host_key = (entry.iface, name_key(entry.host))
        refs = self._host_refs.get(host_key)
        if refs:
            refs.discard(name_key(entry.name))
            if not refs:
                del self._host_refs[host_key]

    def _learn_ptr(self, iface: str, record: Record, family: str, now: float) -> None:
        owner = parse_service_name(record.name)
        if owner is None or not isinstance(record.rdata, tuple):
            return
        target = parse_service_name(record.rdata)
        if target is None:
            return
        if owner.kind == "meta" and target.kind == "type":
            type_key = (iface, target.service_type)
            if record.ttl == 0:
                if self._types.pop(type_key, None) is not None:
                    self.version += 1
            elif type_key in self._types or len(self._types) < MAX_TYPES:
                self._types[type_key] = now + record.ttl
            return
        if (
            owner.kind not in ("type", "subtype")
            or target.kind != "instance"
            or owner.service_type != target.service_type
        ):
            return
        if record.ttl == 0:
            # A subtype goodbye withdraws only the subtype, not the service.
            if owner.kind == "type":
                self._remove(iface, name_key(record.rdata))
            return
        entry = self._entry(
            iface, record.rdata, target.service_type, target.instance, family, now
        )
        if entry:
            entry.expires = max(entry.expires, now + record.ttl)

    def _learn_srv(self, iface: str, record: Record, family: str, now: float) -> None:
        owner = parse_service_name(record.name)
        if owner is None or owner.kind != "instance" or not isinstance(record.rdata, SrvData):
            return
        if record.ttl == 0:
            self._remove(iface, name_key(record.name))
            return
        entry = self._entry(iface, record.name, owner.service_type, owner.instance, family, now)
        if entry is None:
            return
        entry.expires = max(entry.expires, now + record.ttl)
        srv = record.rdata
        if entry.host != srv.target or entry.port != srv.port:
            self._unlink_host(entry)
            entry.host = srv.target
            entry.port = srv.port
            self._host_refs.setdefault((iface, name_key(srv.target)), set()).add(
                name_key(record.name)
            )
            self.version += 1

    def _learn_txt(self, iface: str, record: Record, family: str, now: float) -> None:
        owner = parse_service_name(record.name)
        if owner is None or owner.kind != "instance" or record.ttl == 0:
            return
        entry = self._entry(iface, record.name, owner.service_type, owner.instance, family, now)
        if entry is None:
            return
        entry.expires = max(entry.expires, now + record.ttl)
        txt = parse_txt(record.rdata)
        if txt != entry.txt:
            entry.txt = txt
            self.version += 1

    def _learn_address(self, iface: str, record: Record, now: float) -> None:
        family = socket.AF_INET if record.rtype == TYPE_A else socket.AF_INET6
        address = socket.inet_ntop(family, record.rdata)
        key = (iface, name_key(record.name))
        addresses = self._hosts.get(key)
        if record.ttl == 0:
            if addresses and addresses.pop(address, None) is not None:
                self.version += 1
                if not addresses:
                    del self._hosts[key]
            return
        if addresses is None:
            if len(self._hosts) >= self.max_hosts:
                self.refused += 1
                return
            addresses = self._hosts[key] = {}
        if address not in addresses:
            if len(addresses) >= MAX_ADDRESSES_PER_HOST:
                self.refused += 1
                return
            self.version += 1
        addresses[address] = now + record.ttl

    def prune(self, now: float) -> None:
        for (iface, key), entry in list(self._services.items()):
            if entry.expires <= now:
                self._remove(iface, key)
        for key, addresses in list(self._hosts.items()):
            for address, expires in list(addresses.items()):
                if expires <= now:
                    del addresses[address]
                    self.version += 1
            if not addresses:
                del self._hosts[key]
        for key, expires in list(self._types.items()):
            if expires <= now:
                del self._types[key]
                self.version += 1

    def forget_interface(self, iface: str) -> None:
        for owner, key in [k for k in self._services if k[0] == iface]:
            self._remove(owner, key)
        for table in (self._hosts, self._types):
            for key in [k for k in table if k[0] == iface]:
                del table[key]
                self.version += 1

    def instances_for_host(self, iface: str, host: Name) -> list[tuple[str, str]]:
        results = []
        for key in self._host_refs.get((iface, name_key(host)), ()):
            entry = self._services.get((iface, key))
            if entry:
                results.append((entry.service_type, entry.instance))
        return results

    def service_types(self, iface: str) -> set[str]:
        types = {t for owner, t in self._types if owner == iface}
        types.update(e.service_type for e in self._services.values() if e.iface == iface)
        return types

    def incomplete(self, iface: str) -> tuple[list[Name], list[Name]]:
        """Return instances missing SRV data, and hosts with no known addresses."""
        instances = []
        hosts = []
        for entry in self._services.values():
            if entry.iface != iface:
                continue
            if entry.host is None:
                instances.append(entry.name)
            elif (iface, name_key(entry.host)) not in self._hosts:
                hosts.append(entry.host)
        return instances, hosts

    def snapshot(self, now: float) -> list[dict]:
        results = []
        for entry in self._services.values():
            addresses: list[str] = []
            if entry.host is not None:
                addresses = sorted(self._hosts.get((entry.iface, name_key(entry.host)), ()))
            results.append(
                {
                    "iface": entry.iface,
                    "service_type": entry.service_type,
                    "instance": entry.instance,
                    "name": name_text(entry.name),
                    "host": name_text(entry.host) if entry.host is not None else None,
                    "port": entry.port,
                    "addresses": addresses,
                    "txt": entry.txt,
                    "families": sorted(entry.families),
                    "first_seen": entry.first_seen,
                    "last_seen": entry.last_seen,
                    "expires_in": max(0, round(entry.expires - now)),
                }
            )
        results.sort(key=lambda s: (s["service_type"], s["instance"].lower(), s["iface"]))
        return results
