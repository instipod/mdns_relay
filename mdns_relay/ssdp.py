"""SSDP (HTTP over UDP) parsing. Input is untrusted, so sizes are capped.

Anything unexpected raises MalformedPacket. Relayed packets keep their original
bytes, so a header that appears twice is refused where the relay and the
receiver could otherwise read different values from it.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from .dns import MalformedPacket

KIND_NOTIFY = "notify"
KIND_SEARCH = "query"
KIND_RESPONSE = "response"

TARGET_ALL = "ssdp:all"
NTS_ALIVE = "ssdp:alive"
NTS_UPDATE = "ssdp:update"
NTS_BYEBYE = "ssdp:byebye"

MAX_MESSAGE = 4096
MAX_HEADERS = 32
DEFAULT_MAX_AGE = 1800
DEFAULT_MX = 3
MAX_LOCATION = 512

_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
_RESPONSE_RE = re.compile(r"^HTTP/1\.[01] 200(?: .*)?$")
_MAX_AGE_RE = re.compile(r"max-age\s*=\s*(\d+)", re.IGNORECASE)
_AL_URL_RE = re.compile(r"<([^<>]*)>")
_LINE_END_RE = re.compile(r"\r?\n")
_SINGLE_VALUE = {
    "al", "cache-control", "host", "location", "man", "mx", "nt", "nts",
    "securelocation.upnp.org", "st", "usn",
}


@dataclass(frozen=True, slots=True)
class SsdpMessage:
    kind: str
    target: str
    usn: str = ""
    nts: str = ""
    mx: int = DEFAULT_MX
    max_age: int = DEFAULT_MAX_AGE
    location: str = ""
    alternate_locations: tuple[str, ...] = ()
    server: str = ""

    @property
    def is_byebye(self) -> bool:
        return self.nts == NTS_BYEBYE

    @property
    def summary(self) -> str:
        return f"{self.target} ({self.usn})" if self.usn else self.target


def _parse_headers(lines: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for count, line in enumerate(lines):
        if not line:
            break
        if count >= MAX_HEADERS:
            raise MalformedPacket("too many headers")
        name, separator, value = line.partition(":")
        if not separator or not _HEADER_NAME_RE.match(name):
            raise MalformedPacket("invalid header")
        key = name.lower()
        if key in headers and key in _SINGLE_VALUE:
            raise MalformedPacket(f"duplicate {key} header")
        headers[key] = value.strip()
    return headers


def _require(headers: dict[str, str], name: str) -> str:
    value = headers.get(name)
    if not value:
        raise MalformedPacket(f"missing {name} header")
    return value


def _location_fields(headers: dict[str, str]) -> dict:
    locations = _AL_URL_RE.findall(headers["al"]) if "al" in headers else []
    if "al" in headers and not locations:
        locations = [headers["al"]]
    if "securelocation.upnp.org" in headers:
        locations.append(headers["securelocation.upnp.org"])
    return {
        "location": headers.get("location", ""),
        "alternate_locations": tuple(locations),
        "server": headers.get("server", ""),
    }


def _max_age(headers: dict[str, str]) -> int:
    match = _MAX_AGE_RE.search(headers.get("cache-control", ""))
    return int(match.group(1)[:9]) if match else DEFAULT_MAX_AGE


def _parse_search(headers: dict[str, str]) -> SsdpMessage:
    if _require(headers, "man").strip('"') != "ssdp:discover":
        raise MalformedPacket("not a discovery search")
    mx = DEFAULT_MX
    if "mx" in headers:
        if not headers["mx"].isascii() or not headers["mx"].isdigit():
            raise MalformedPacket("invalid MX")
        mx = int(headers["mx"][:9])
    return SsdpMessage(KIND_SEARCH, _require(headers, "st"), mx=mx)


def _parse_notify(headers: dict[str, str]) -> SsdpMessage:
    nts = _require(headers, "nts")
    if nts not in (NTS_ALIVE, NTS_UPDATE, NTS_BYEBYE):
        raise MalformedPacket("unknown NTS")
    if nts != NTS_BYEBYE:
        _require(headers, "location")
    return SsdpMessage(
        KIND_NOTIFY,
        _require(headers, "nt"),
        usn=_require(headers, "usn"),
        nts=nts,
        max_age=_max_age(headers),
        **_location_fields(headers),
    )


def _parse_response(headers: dict[str, str]) -> SsdpMessage:
    _require(headers, "location")
    return SsdpMessage(
        KIND_RESPONSE,
        _require(headers, "st"),
        usn=_require(headers, "usn"),
        max_age=_max_age(headers),
        **_location_fields(headers),
    )


def parse_message(data: bytes) -> SsdpMessage:
    if len(data) > MAX_MESSAGE:
        raise MalformedPacket("message too large")
    text = data.decode("latin-1")
    head = re.split(r"\r?\n\r?\n", text, maxsplit=1)[0]
    if any(ord(c) < 32 and c not in "\t\r\n" or ord(c) == 127 for c in head):
        raise MalformedPacket("control character in headers")
    start, *lines = _LINE_END_RE.split(head)
    headers = _parse_headers(lines)
    if start == "NOTIFY * HTTP/1.1":
        return _parse_notify(headers)
    if start == "M-SEARCH * HTTP/1.1":
        return _parse_search(headers)
    if _RESPONSE_RE.match(start):
        return _parse_response(headers)
    raise MalformedPacket("not an SSDP message")


def _location_allowed(url: str, source: str) -> bool:
    if len(url) > MAX_LOCATION:
        return False
    try:
        parts = urlsplit(url)
        _ = parts.port  # Raises ValueError if out of range.
        if parts.scheme.lower() not in ("http", "https") or parts.hostname is None:
            return False
        address = ipaddress.ip_address(parts.hostname)
        origin = ipaddress.ip_address(source.partition("%")[0])
    except ValueError:
        return False
    return address == origin and not address.is_link_local


def locations_allowed(message: SsdpMessage, source: str) -> bool:
    """Check that every advertised URL points at the device that sent the packet."""
    urls = [*message.alternate_locations]
    if message.location:
        urls.append(message.location)
    return all(_location_allowed(url, source) for url in urls)


def build_search(host: str, port: int, target: str = TARGET_ALL, mx: int = 2) -> bytes:
    host_header = f"[{host.upper()}]:{port}" if ":" in host else f"{host}:{port}"
    return (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {host_header}\r\n"
        'MAN: "ssdp:discover"\r\n'
        f"MX: {mx}\r\n"
        f"ST: {target}\r\n"
        "\r\n"
    ).encode("ascii")
