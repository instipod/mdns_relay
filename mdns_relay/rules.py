"""Relay rules and their on-disk store.

The store fails closed: a missing file means no rules, and a file that can't be
read or validated stops startup rather than being replaced. Changes are written
to disk first and only then become visible to the relay.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import uuid
from dataclasses import asdict, dataclass
from fnmatch import fnmatchcase
from pathlib import Path

ANY_TYPE = "*"

_SERVICE_TYPE_RE = re.compile(r"^_[a-z0-9][a-z0-9-]{0,62}\._(tcp|udp)$")
_INTERFACE_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,15}$")
_MAX_PATTERN = 255
_MAX_NOTE = 200
_FIELDS = {"enabled", "service_type", "instance_pattern", "provider_iface", "client_iface", "note"}


class RuleError(ValueError):
    """A rule failed validation."""


class RuleFileError(RuntimeError):
    """The rules file exists but can't be used."""


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    enabled: bool
    service_type: str
    instance_pattern: str
    provider_iface: str
    client_iface: str
    note: str = ""

    def matches_type(self, service_type: str) -> bool:
        return self.service_type == ANY_TYPE or self.service_type == service_type.lower()

    def matches_instance(self, service_type: str, instance: str) -> bool:
        return self.matches_type(service_type) and fnmatchcase(
            instance.lower(), self.instance_pattern.lower()
        )

    def to_dict(self) -> dict:
        return asdict(self)


def normalize_service_type(value: object) -> str:
    if not isinstance(value, str):
        raise RuleError("service_type must be a string")
    text = value.strip().lower().rstrip(".")
    if text == ANY_TYPE:
        return text
    if text.endswith(".local"):
        text = text[: -len(".local")]
    if not _SERVICE_TYPE_RE.match(text):
        raise RuleError("service_type must look like _name._tcp or _name._udp, or be *")
    return text


def _validate_interface(field_name: str, value: object) -> str:
    if not isinstance(value, str) or not _INTERFACE_RE.match(value):
        raise RuleError(f"{field_name} is not a valid interface name")
    return value


def build_rule(data: dict, rule_id: str | None = None) -> Rule:
    """Validate raw fields and return a Rule. Unknown fields are rejected."""
    unknown = set(data) - _FIELDS
    if unknown:
        raise RuleError(f"unknown fields: {', '.join(sorted(unknown))}")

    enabled = data.get("enabled", True)
    if not isinstance(enabled, bool):
        raise RuleError("enabled must be true or false")

    pattern = data.get("instance_pattern", "*")
    if (
        not isinstance(pattern, str)
        or not pattern
        or len(pattern) > _MAX_PATTERN
        or not pattern.isprintable()
    ):
        raise RuleError(f"instance_pattern must be 1-{_MAX_PATTERN} printable characters")

    note = data.get("note", "")
    if not isinstance(note, str) or len(note) > _MAX_NOTE:
        raise RuleError(f"note must be at most {_MAX_NOTE} characters")

    for required in ("service_type", "provider_iface", "client_iface"):
        if required not in data:
            raise RuleError(f"{required} is required")
    provider = _validate_interface("provider_iface", data["provider_iface"])
    client = _validate_interface("client_iface", data["client_iface"])
    if provider == client:
        raise RuleError("provider_iface and client_iface must be different")

    return Rule(
        id=rule_id or uuid.uuid4().hex,
        enabled=enabled,
        service_type=normalize_service_type(data["service_type"]),
        instance_pattern=pattern,
        provider_iface=provider,
        client_iface=client,
        note=note,
    )


def _same_match(a: Rule, b: Rule) -> bool:
    return (
        a.id != b.id
        and a.service_type == b.service_type
        and a.instance_pattern.lower() == b.instance_pattern.lower()
        and a.provider_iface == b.provider_iface
        and a.client_iface == b.client_iface
    )


class RuleStore:
    def __init__(self, path: str | os.PathLike) -> None:
        self.path = Path(path)
        self.rules: tuple[Rule, ...] = ()
        self.disabled_interfaces: frozenset[str] = frozenset()
        self.version = 0

    def load(self) -> None:
        try:
            raw = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return
        except (OSError, UnicodeDecodeError) as exc:
            raise RuleFileError(f"cannot read {self.path}: {exc}") from exc

        try:
            data = json.loads(raw)
            if not isinstance(data, dict) or data.get("version") != 1:
                raise RuleFileError("unsupported file format or version")
            items = data.get("rules", [])
            disabled = data.get("disabled_interfaces", [])
            if not isinstance(items, list) or not isinstance(disabled, list):
                raise RuleFileError("rules and disabled_interfaces must be lists")
            rules = []
            for item in items:
                if not isinstance(item, dict) or not isinstance(item.get("id"), str):
                    raise RuleFileError("each rule must be an object with an id")
                fields = {key: value for key, value in item.items() if key != "id"}
                rules.append(build_rule(fields, item["id"]))
            if len({rule.id for rule in rules}) != len(rules):
                raise RuleFileError("duplicate rule ids")
            names = [_validate_interface("disabled_interfaces", name) for name in disabled]
        except (ValueError, RuleFileError) as exc:
            raise RuleFileError(f"invalid rules file {self.path}: {exc}") from exc

        self.rules = tuple(rules)
        self.disabled_interfaces = frozenset(names)

    def _commit(self, rules: tuple[Rule, ...], disabled: frozenset[str]) -> None:
        payload = {
            "version": 1,
            "rules": [rule.to_dict() for rule in rules],
            "disabled_interfaces": sorted(disabled),
        }
        directory = self.path.parent if str(self.path.parent) else Path(".")
        fd, temp_name = tempfile.mkstemp(
            prefix=f".{self.path.name}.", suffix=".tmp", dir=directory
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, self.path)
        except BaseException:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass
            raise
        self.rules = rules
        self.disabled_interfaces = disabled
        self.version += 1

    def _check_duplicate(self, rule: Rule, rules: tuple[Rule, ...]) -> None:
        if any(_same_match(rule, other) for other in rules):
            raise RuleError("an identical rule already exists")

    def add(self, data: dict) -> Rule:
        rule = build_rule(data)
        self._check_duplicate(rule, self.rules)
        self._commit((*self.rules, rule), self.disabled_interfaces)
        return rule

    def get(self, rule_id: str) -> Rule | None:
        return next((rule for rule in self.rules if rule.id == rule_id), None)

    def update(self, rule_id: str, changes: dict) -> Rule | None:
        current = self.get(rule_id)
        if current is None:
            return None
        fields = {key: value for key, value in current.to_dict().items() if key != "id"}
        if "id" in changes:
            raise RuleError("id cannot be changed")
        fields.update(changes)
        rule = build_rule(fields, rule_id)
        self._check_duplicate(rule, self.rules)
        rules = tuple(rule if other.id == rule_id else other for other in self.rules)
        self._commit(rules, self.disabled_interfaces)
        return rule

    def delete(self, rule_id: str) -> bool:
        if self.get(rule_id) is None:
            return False
        rules = tuple(rule for rule in self.rules if rule.id != rule_id)
        self._commit(rules, self.disabled_interfaces)
        return True

    def set_interface_enabled(self, name: str, enabled: bool) -> None:
        _validate_interface("interface", name)
        disabled = (
            self.disabled_interfaces - {name} if enabled else self.disabled_interfaces | {name}
        )
        self._commit(self.rules, frozenset(disabled))
