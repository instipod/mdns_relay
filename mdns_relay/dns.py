"""mDNS wire-format parser and encoder.

Packets come from the network and are untrusted. Any structural problem raises
MalformedPacket, and compression pointers must point strictly backwards so that
a hostile packet cannot cause a loop.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

TYPE_A = 1
TYPE_PTR = 12
TYPE_TXT = 16
TYPE_AAAA = 28
TYPE_SRV = 33
TYPE_NSEC = 47
TYPE_ANY = 255

CLASS_IN = 1

FLAG_QR = 0x8000
OPCODE_MASK = 0x7800
RCODE_MASK = 0x000F
CLASS_TOP_BIT = 0x8000  # QU in questions, cache-flush in records

MAX_NAME_LENGTH = 255
MAX_LABEL_LENGTH = 63

META_QUERY_NAME = (b"_services", b"_dns-sd", b"_udp", b"local")

Name = tuple[bytes, ...]


class MalformedPacket(ValueError):
    """The packet is not a well-formed DNS message."""


@dataclass(frozen=True, slots=True)
class SrvData:
    priority: int
    weight: int
    port: int
    target: Name


@dataclass(frozen=True, slots=True)
class NsecData:
    next_name: Name
    bitmaps: bytes


@dataclass(frozen=True, slots=True)
class Question:
    name: Name
    qtype: int
    qclass: int = CLASS_IN
    unicast: bool = False


@dataclass(frozen=True, slots=True)
class Record:
    name: Name
    rtype: int
    ttl: int
    # Name for PTR, SrvData for SRV, NsecData for NSEC, otherwise raw bytes.
    rdata: Name | SrvData | NsecData | bytes
    rclass: int = CLASS_IN
    cache_flush: bool = False


@dataclass(slots=True)
class Message:
    id: int = 0
    flags: int = 0
    questions: list[Question] = field(default_factory=list)
    answers: list[Record] = field(default_factory=list)
    authorities: list[Record] = field(default_factory=list)
    additionals: list[Record] = field(default_factory=list)

    @property
    def is_response(self) -> bool:
        return bool(self.flags & FLAG_QR)

    @property
    def is_standard(self) -> bool:
        return not self.flags & (OPCODE_MASK | RCODE_MASK)


def _read_name(data: bytes, offset: int) -> tuple[Name, int]:
    """Read a possibly compressed name, returning it and the offset after it."""
    labels: list[bytes] = []
    total = 1
    position = offset
    limit = offset
    end: int | None = None
    size = len(data)
    while True:
        if position >= size:
            raise MalformedPacket("name runs past end of packet")
        length = data[position]
        if length == 0:
            if end is None:
                end = position + 1
            return tuple(labels), end
        kind = length & 0xC0
        if kind == 0xC0:
            if position + 1 >= size:
                raise MalformedPacket("truncated compression pointer")
            target = ((length & 0x3F) << 8) | data[position + 1]
            if target >= limit:
                raise MalformedPacket("compression pointer does not point backwards")
            if end is None:
                end = position + 2
            limit = target
            position = target
            continue
        if kind:
            raise MalformedPacket("unsupported label type")
        stop = position + 1 + length
        if stop > size:
            raise MalformedPacket("label runs past end of packet")
        total += length + 1
        if total > MAX_NAME_LENGTH:
            raise MalformedPacket("name too long")
        labels.append(data[position + 1 : stop])
        position = stop


def _read_rdata(data: bytes, rtype: int, start: int, end: int):
    if rtype == TYPE_PTR:
        target, stop = _read_name(data, start)
        if stop != end:
            raise MalformedPacket("PTR rdata length mismatch")
        return target
    if rtype == TYPE_SRV:
        if end - start < 7:
            raise MalformedPacket("SRV rdata too short")
        priority, weight, port = struct.unpack_from("!HHH", data, start)
        target, stop = _read_name(data, start + 6)
        if stop != end:
            raise MalformedPacket("SRV rdata length mismatch")
        return SrvData(priority, weight, port, target)
    if rtype == TYPE_NSEC:
        next_name, stop = _read_name(data, start)
        if stop > end:
            raise MalformedPacket("NSEC rdata length mismatch")
        return NsecData(next_name, data[stop:end])
    if rtype == TYPE_A and end - start != 4:
        raise MalformedPacket("bad A rdata length")
    if rtype == TYPE_AAAA and end - start != 16:
        raise MalformedPacket("bad AAAA rdata length")
    return data[start:end]


def _read_record(data: bytes, offset: int) -> tuple[Record, int]:
    name, offset = _read_name(data, offset)
    if offset + 10 > len(data):
        raise MalformedPacket("truncated record header")
    rtype, rclass, ttl, rdlength = struct.unpack_from("!HHIH", data, offset)
    start = offset + 10
    end = start + rdlength
    if end > len(data):
        raise MalformedPacket("rdata runs past end of packet")
    record = Record(
        name=name,
        rtype=rtype,
        ttl=ttl,
        rdata=_read_rdata(data, rtype, start, end),
        rclass=rclass & ~CLASS_TOP_BIT,
        cache_flush=bool(rclass & CLASS_TOP_BIT),
    )
    return record, end


def parse_message(data: bytes) -> Message:
    if len(data) < 12:
        raise MalformedPacket("packet shorter than DNS header")
    msg_id, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", data, 0)
    message = Message(id=msg_id, flags=flags)
    offset = 12
    for _ in range(qd):
        name, offset = _read_name(data, offset)
        if offset + 4 > len(data):
            raise MalformedPacket("truncated question")
        qtype, qclass = struct.unpack_from("!HH", data, offset)
        offset += 4
        message.questions.append(
            Question(name, qtype, qclass & ~CLASS_TOP_BIT, bool(qclass & CLASS_TOP_BIT))
        )
    for count, section in (
        (an, message.answers),
        (ns, message.authorities),
        (ar, message.additionals),
    ):
        for _ in range(count):
            record, offset = _read_record(data, offset)
            section.append(record)
    return message


class _Encoder:
    def __init__(self) -> None:
        self.buffer = bytearray()
        self._offsets: dict[Name, int] = {}

    def name(self, name: Name, compress: bool = True) -> None:
        for index in range(len(name)):
            suffix = name[index:]
            if compress and suffix in self._offsets:
                self.buffer += struct.pack("!H", 0xC000 | self._offsets[suffix])
                return
            if len(self.buffer) < 0x4000:
                self._offsets.setdefault(suffix, len(self.buffer))
            label = name[index]
            self.buffer.append(len(label))
            self.buffer += label
        self.buffer.append(0)

    def record(self, record: Record) -> None:
        self.name(record.name)
        rclass = record.rclass | (CLASS_TOP_BIT if record.cache_flush else 0)
        self.buffer += struct.pack("!HHI", record.rtype, rclass, record.ttl)
        length_at = len(self.buffer)
        self.buffer += b"\0\0"
        rdata = record.rdata
        if isinstance(rdata, SrvData):
            self.buffer += struct.pack("!HHH", rdata.priority, rdata.weight, rdata.port)
            self.name(rdata.target)
        elif isinstance(rdata, NsecData):
            # Written uncompressed because some stacks treat NSEC rdata as opaque.
            self.name(rdata.next_name, compress=False)
            self.buffer += rdata.bitmaps
        elif isinstance(rdata, tuple):
            self.name(rdata)
        else:
            self.buffer += rdata
        struct.pack_into("!H", self.buffer, length_at, len(self.buffer) - length_at - 2)


def encode_message(message: Message) -> bytes:
    encoder = _Encoder()
    encoder.buffer += struct.pack(
        "!HHHHHH",
        message.id,
        message.flags,
        len(message.questions),
        len(message.answers),
        len(message.authorities),
        len(message.additionals),
    )
    for question in message.questions:
        encoder.name(question.name)
        qclass = question.qclass | (CLASS_TOP_BIT if question.unicast else 0)
        encoder.buffer += struct.pack("!HH", question.qtype, qclass)
    for section in (message.answers, message.authorities, message.additionals):
        for record in section:
            encoder.record(record)
    return bytes(encoder.buffer)


def name_key(name: Name) -> Name:
    """Case-insensitive form of a name, for comparisons and dictionary keys."""
    return tuple(label.lower() for label in name)


def is_local(name: Name) -> bool:
    return bool(name) and name[-1].lower() == b"local"


def label_text(label: bytes) -> str:
    return label.decode("utf-8", errors="replace")


def name_text(name: Name) -> str:
    return ".".join(
        label_text(label).replace("\\", "\\\\").replace(".", "\\.") for label in name
    )


def name_from_text(text: str) -> Name:
    """Convert dotted text to a name. Dots inside labels are not supported."""
    return tuple(part.encode("utf-8") for part in text.strip(".").split(".") if part)


@dataclass(frozen=True, slots=True)
class ServiceName:
    kind: str  # "meta", "type", "subtype" or "instance"
    service_type: str | None = None
    instance: str | None = None


def _service_type(labels: Name) -> str | None:
    service, protocol = labels[0].lower(), labels[1].lower()
    if service.startswith(b"_") and len(service) > 1 and protocol in (b"_tcp", b"_udp"):
        return f"{label_text(service)}.{label_text(protocol)}"
    return None


def parse_service_name(name: Name) -> ServiceName | None:
    """Classify a DNS-SD name, or return None if it isn't one (such as a host)."""
    if not is_local(name):
        return None
    if name_key(name) == META_QUERY_NAME:
        return ServiceName("meta")
    if len(name) == 3:
        service_type = _service_type(name[0:2])
        return ServiceName("type", service_type) if service_type else None
    if len(name) == 4:
        service_type = _service_type(name[1:3])
        if service_type:
            return ServiceName("instance", service_type, label_text(name[0]))
        return None
    if len(name) == 5 and name[1].lower() == b"_sub":
        service_type = _service_type(name[2:4])
        return ServiceName("subtype", service_type) if service_type else None
    return None
