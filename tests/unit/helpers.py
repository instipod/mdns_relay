"""Builders for mDNS messages used across the unit tests."""

from __future__ import annotations

import socket

from mdns_relay.dns import (
    FLAG_QR,
    META_QUERY_NAME,
    TYPE_A,
    TYPE_AAAA,
    TYPE_PTR,
    TYPE_SRV,
    TYPE_TXT,
    Message,
    Question,
    Record,
    SrvData,
    name_from_text,
)
from mdns_relay.rules import build_rule

RESPONSE_FLAGS = FLAG_QR | 0x0400


def n(text: str):
    return name_from_text(text)


def instance_name(instance: str, service_type: str):
    return (instance.encode(), *n(service_type), b"local")


def type_name(service_type: str):
    return (*n(service_type), b"local")


def ptr(service_type: str, instance: str, ttl: int = 4500) -> Record:
    return Record(type_name(service_type), TYPE_PTR, ttl, instance_name(instance, service_type))


def meta_ptr(service_type: str, ttl: int = 4500) -> Record:
    return Record(META_QUERY_NAME, TYPE_PTR, ttl, type_name(service_type))


def srv(service_type: str, instance: str, host: str, port: int = 80, ttl: int = 120) -> Record:
    return Record(
        instance_name(instance, service_type), TYPE_SRV, ttl, SrvData(0, 0, port, n(host))
    )


def txt(service_type: str, instance: str, *items: str, ttl: int = 4500) -> Record:
    data = b"".join(bytes([len(i.encode())]) + i.encode() for i in items) or b"\0"
    return Record(instance_name(instance, service_type), TYPE_TXT, ttl, data)


def a(host: str, address: str, ttl: int = 120) -> Record:
    return Record(n(host), TYPE_A, ttl, socket.inet_pton(socket.AF_INET, address))


def aaaa(host: str, address: str, ttl: int = 120) -> Record:
    return Record(n(host), TYPE_AAAA, ttl, socket.inet_pton(socket.AF_INET6, address))


def response(answers, additionals=()) -> Message:
    return Message(flags=RESPONSE_FLAGS, answers=list(answers), additionals=list(additionals))


def query(*questions: Question, known=()) -> Message:
    return Message(questions=list(questions), answers=list(known))


def rule(service_type="_http._tcp", provider="prov", client="cli", **fields):
    return build_rule(
        {"service_type": service_type, "provider_iface": provider, "client_iface": client, **fields}
    )


class NoHosts:
    def instances_for_host(self, iface, host):
        return []


class StaticHosts:
    def __init__(self, entries):
        self.entries = entries

    def instances_for_host(self, iface, host):
        return self.entries.get((iface, host), [])
