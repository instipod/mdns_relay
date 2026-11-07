"""The default-deny relay policy.

Each decision covers one packet going from one interface to another. A question
or record is relayed only if a rule explicitly permits it. Everything else is
removed, and if nothing permitted remains, nothing is sent. This module does no
I/O so that the policy can be tested exhaustively.
"""

from __future__ import annotations

import ipaddress
from collections import Counter
from dataclasses import dataclass, field, replace
from typing import Iterable, Protocol, Sequence

from .dns import (
    CLASS_IN,
    TYPE_A,
    TYPE_AAAA,
    TYPE_ANY,
    TYPE_NSEC,
    TYPE_PTR,
    TYPE_SRV,
    TYPE_TXT,
    Message,
    Name,
    Question,
    Record,
    SrvData,
    is_local,
    name_key,
    parse_service_name,
)
from .rules import Rule

REASON_NO_RULE = "no_rule"
REASON_PROBE = "probe"
REASON_NOTHING_PERMITTED = "nothing_permitted"

DROP_NOT_PERMITTED = "not_permitted"
DROP_NON_LOCAL = "non_local"
DROP_LINK_LOCAL = "link_local"


class HostIndex(Protocol):
    def instances_for_host(self, iface: str, host: Name) -> Iterable[tuple[str, str]]:
        """Return (service_type, instance) pairs whose SRV targets this host."""


@dataclass(slots=True)
class Decision:
    message: Message | None
    reason: str | None = None
    dropped: Counter = field(default_factory=Counter)
    rule_ids: set[str] = field(default_factory=set)


def _is_link_local(record: Record) -> bool:
    try:
        return ipaddress.ip_address(record.rdata).is_link_local
    except ValueError:
        return True


class _Scope:
    """The rules that apply to one client/provider pair, and how to check them."""

    def __init__(
        self,
        rules: Sequence[Rule],
        provider: str,
        hosts: HostIndex,
        packet_srv: dict[Name, list[tuple[str, str]]] | None = None,
    ) -> None:
        self.rules = rules
        self.provider = provider
        self.hosts = hosts
        self.packet_srv = packet_srv or {}

    def _type_rule(self, service_type: str | None) -> Rule | None:
        if service_type is None:
            return None
        return next((r for r in self.rules if r.matches_type(service_type)), None)

    def _instance_rule(self, service_type: str | None, instance: str | None) -> Rule | None:
        if service_type is None or instance is None:
            return None
        return next((r for r in self.rules if r.matches_instance(service_type, instance)), None)

    def _host_rule(self, name: Name) -> Rule | None:
        key = name_key(name)
        for service_type, instance in self.packet_srv.get(key, ()):
            rule = self._instance_rule(service_type, instance)
            if rule:
                return rule
        for service_type, instance in self.hosts.instances_for_host(self.provider, key):
            rule = self._instance_rule(service_type, instance)
            if rule:
                return rule
        return None

    def question(self, question: Question) -> Rule | None:
        if question.qclass != CLASS_IN or not is_local(question.name):
            return None
        service = parse_service_name(question.name)
        if service is None:
            if question.qtype in (TYPE_A, TYPE_AAAA):
                return self._host_rule(question.name)
            return None
        if service.kind == "meta":
            return self.rules[0] if question.qtype == TYPE_PTR else None
        if service.kind in ("type", "subtype"):
            return self._type_rule(service.service_type) if question.qtype == TYPE_PTR else None
        if question.qtype in (TYPE_SRV, TYPE_TXT, TYPE_ANY):
            return self._instance_rule(service.service_type, service.instance)
        return None

    def record(self, record: Record) -> tuple[Rule | None, str]:
        if record.rclass != CLASS_IN:
            return None, DROP_NOT_PERMITTED
        if not is_local(record.name):
            return None, DROP_NON_LOCAL
        if record.rtype in (TYPE_A, TYPE_AAAA):
            if _is_link_local(record):
                return None, DROP_LINK_LOCAL
            return self._host_rule(record.name), DROP_NOT_PERMITTED

        owner = parse_service_name(record.name)
        if owner is None:
            return None, DROP_NOT_PERMITTED
        if record.rtype == TYPE_PTR:
            if not isinstance(record.rdata, tuple):
                return None, DROP_NOT_PERMITTED
            target = parse_service_name(record.rdata)
            if target is None:
                return None, DROP_NOT_PERMITTED
            if owner.kind == "meta" and target.kind == "type":
                return self._type_rule(target.service_type), DROP_NOT_PERMITTED
            if (
                owner.kind in ("type", "subtype")
                and target.kind == "instance"
                and owner.service_type == target.service_type
            ):
                return (
                    self._instance_rule(target.service_type, target.instance),
                    DROP_NOT_PERMITTED,
                )
            return None, DROP_NOT_PERMITTED
        if record.rtype in (TYPE_SRV, TYPE_TXT, TYPE_NSEC) and owner.kind == "instance":
            return self._instance_rule(owner.service_type, owner.instance), DROP_NOT_PERMITTED
        return None, DROP_NOT_PERMITTED


def _filter_records(
    records: Iterable[Record], scope: _Scope, decision: Decision
) -> list[Record]:
    kept = []
    for record in records:
        rule, reason = scope.record(record)
        if rule is None:
            decision.dropped[reason] += 1
        else:
            decision.rule_ids.add(rule.id)
            kept.append(record)
    return kept


def _packet_srv_index(message: Message) -> dict[Name, list[tuple[str, str]]]:
    index: dict[Name, list[tuple[str, str]]] = {}
    for record in (*message.answers, *message.additionals):
        if record.rtype == TYPE_SRV and isinstance(record.rdata, SrvData):
            owner = parse_service_name(record.name)
            if owner and owner.kind == "instance":
                index.setdefault(name_key(record.rdata.target), []).append(
                    (owner.service_type, owner.instance)
                )
    return index


def _filter_query(
    message: Message, rules: Sequence[Rule], provider: str, hosts: HostIndex
) -> Decision:
    decision = Decision(None)
    if message.authorities:
        decision.reason = REASON_PROBE
        return decision

    # SRV records in a query are not trusted to grant access to a host. Host
    # checks use only what has been learned from the provider's own responses.
    scope = _Scope(rules, provider, hosts)
    questions = []
    for question in message.questions:
        rule = scope.question(question)
        if rule is None:
            decision.dropped[DROP_NOT_PERMITTED] += 1
        else:
            decision.rule_ids.add(rule.id)
            questions.append(replace(question, unicast=False))
    answers = _filter_records(message.answers, scope, decision)

    # A packet of only known answers is valid when it continues a truncated
    # query. It is not valid when all of its questions were filtered out.
    keep_answers_alone = not message.questions and answers
    if questions or keep_answers_alone:
        decision.message = Message(
            id=message.id, flags=message.flags, questions=questions, answers=answers
        )
    else:
        decision.reason = REASON_NOTHING_PERMITTED
        decision.rule_ids.clear()
    return decision


def _filter_response(
    message: Message, rules: Sequence[Rule], provider: str, hosts: HostIndex
) -> Decision:
    decision = Decision(None)
    scope = _Scope(rules, provider, hosts, _packet_srv_index(message))
    answers = _filter_records(message.answers, scope, decision)
    additionals = _filter_records(message.additionals, scope, decision)
    if answers:
        decision.message = Message(
            id=message.id, flags=message.flags, answers=answers, additionals=additionals
        )
    else:
        decision.reason = REASON_NOTHING_PERMITTED
        decision.rule_ids.clear()
    return decision


def filter_packet(
    message: Message,
    source: str,
    destination: str,
    rules: Sequence[Rule],
    hosts: HostIndex,
) -> Decision:
    """Decide what, if anything, of a packet may go from source to destination."""
    if message.is_response:
        provider, client = source, destination
    else:
        client, provider = source, destination
    applicable = [
        rule
        for rule in rules
        if rule.enabled and rule.provider_iface == provider and rule.client_iface == client
    ]
    if not applicable:
        return Decision(None, reason=REASON_NO_RULE)
    if message.is_response:
        return _filter_response(message, applicable, provider, hosts)
    return _filter_query(message, applicable, provider, hosts)
