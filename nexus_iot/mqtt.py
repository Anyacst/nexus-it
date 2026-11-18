"""Passive MQTT 3.1.1 decoding from packet captures (standard library only).

The module has three layers:

* ``decode_packet`` decodes one complete MQTT control packet.
* ``MQTTStreamDecoder`` splits a byte stream into packets, holding partial packets until
  more bytes arrive.
* ``TCPStream`` reassembles one direction of a TCP connection by sequence number.

``mqtt_messages`` ties them together for a PCAP/PCAPNG file. None of the public functions
or methods raise on truncated or garbage input; problems are returned as findings or as an
``INVALID`` packet. Only plain-text MQTT over TCP is decoded (no TLS, no MQTT 5 properties).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from .capture import TCP_SYN, CaptureError, tcp_segments

DEFAULT_PORTS: frozenset[int] = frozenset({1883})

PACKET_TYPES: dict[int, str] = {
    1: "CONNECT", 2: "CONNACK", 3: "PUBLISH", 4: "PUBACK", 5: "PUBREC", 6: "PUBREL", 7: "PUBCOMP",
    8: "SUBSCRIBE", 9: "SUBACK", 10: "UNSUBSCRIBE", 11: "UNSUBACK", 12: "PINGREQ", 13: "PINGRESP",
    14: "DISCONNECT",
}

# MQTT 3.1.1 section 2.2.2: these packet types have fixed flag bits; PUBLISH flags vary.
_REQUIRED_FLAGS: dict[int, int] = {1: 0, 2: 0, 4: 0, 5: 0, 6: 2, 7: 0, 8: 2, 9: 0, 10: 2, 11: 0, 12: 0, 13: 0, 14: 0}

MAX_REMAINING_LENGTH = 268_435_455
MAX_PENDING_SEGMENTS = 1_000
MAX_PENDING_BYTES = 4 * 1024 * 1024
_SEQ_MOD = 1 << 32


class MQTTDecodeError(ValueError):
    """Malformed MQTT data. Raised only by private helpers; public APIs convert it."""


def encode_remaining_length(value: int) -> bytes:
    """Encode an MQTT remaining-length variable byte integer (helper for building packets)."""
    if not 0 <= value <= MAX_REMAINING_LENGTH:
        raise ValueError("remaining length must be between 0 and 268435455")
    out = bytearray()
    while True:
        byte = value % 128
        value //= 128
        out.append(byte | 0x80 if value else byte)
        if not value:
            return bytes(out)


def _read_remaining_length(data: bytes | bytearray, offset: int = 1) -> tuple[int, int] | None:
    """Return (value, encoded size) of the varint at offset, or None if more bytes are needed.

    Raises MQTTDecodeError when the encoding uses more than four bytes.
    """
    value = 0
    for i in range(4):
        if offset + i >= len(data):
            return None
        byte = data[offset + i]
        value += (byte & 0x7F) << (7 * i)
        if not byte & 0x80:
            return value, i + 1
    raise MQTTDecodeError("remaining length uses more than four bytes")


class _Reader:
    """Bounds-checked reader over one packet's variable header and payload."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    @property
    def remaining(self) -> int:
        return len(self.data) - self.pos

    def take(self, count: int, what: str) -> bytes:
        if count > self.remaining:
            raise MQTTDecodeError(f"truncated {what}")
        chunk = self.data[self.pos:self.pos + count]
        self.pos += count
        return chunk

    def u8(self, what: str) -> int:
        return self.take(1, what)[0]

    def u16(self, what: str) -> int:
        return int.from_bytes(self.take(2, what), "big")

    def binary(self, what: str) -> bytes:
        return self.take(self.u16(what + " length"), what)

    def text(self, what: str) -> str:
        try:
            return self.binary(what).decode("utf-8")
        except UnicodeDecodeError as e:
            raise MQTTDecodeError(f"{what} is not valid UTF-8") from e

    def finish(self, what: str) -> None:
        if self.remaining:
            raise MQTTDecodeError(f"{self.remaining} unexpected trailing byte(s) in {what}")


def decode_packet(packet: bytes) -> dict[str, Any]:
    """Decode exactly one complete MQTT 3.1.1 control packet, fixed header included.

    Returns a dict with ``type`` (e.g. ``"PUBLISH"``) and type-specific fields. Malformed
    input returns ``{"type": "INVALID", "error": "..."}``; this function never raises.
    PUBLISH payload bytes are returned as ``payload_bytes``; CONNECT passwords are never kept.
    """
    try:
        return _decode_packet(bytes(packet))
    except MQTTDecodeError as e:
        return {"type": "INVALID", "error": str(e)}


def _decode_packet(packet: bytes) -> dict[str, Any]:
    if len(packet) < 2:
        raise MQTTDecodeError("truncated fixed header")
    packet_type, flags = packet[0] >> 4, packet[0] & 0x0F
    name = PACKET_TYPES.get(packet_type)
    if name is None:
        raise MQTTDecodeError(f"reserved or unsupported packet type {packet_type}")
    header = _read_remaining_length(packet, 1)
    if header is None:
        raise MQTTDecodeError("truncated remaining length")
    length, size = header
    body = packet[1 + size:]
    if len(body) != length:
        raise MQTTDecodeError(f"{name} remaining length {length} does not match {len(body)} byte(s) supplied")
    required = _REQUIRED_FLAGS.get(packet_type)
    if required is not None and flags != required:
        raise MQTTDecodeError(f"{name} has invalid fixed-header flags 0x{flags:x}")
    reader = _Reader(body)
    result: dict[str, Any] = {"type": name}
    if packet_type == 1:
        result.update(_decode_connect(reader))
    elif packet_type == 2:
        acknowledge = reader.u8("CONNACK flags")
        if acknowledge & 0xFE:
            raise MQTTDecodeError("CONNACK reserved flag bits are set")
        result.update({"session_present": bool(acknowledge & 1), "return_code": reader.u8("CONNACK return code")})
        reader.finish(name)
    elif packet_type == 3:
        result.update(_decode_publish(reader, flags))
    elif packet_type in (4, 5, 6, 7, 11):
        result["packet_id"] = reader.u16(f"{name} packet identifier")
        reader.finish(name)
    elif packet_type == 8:
        result["packet_id"] = reader.u16("SUBSCRIBE packet identifier")
        topics = []
        while reader.remaining:
            topic = reader.text("SUBSCRIBE topic filter")
            qos = reader.u8("SUBSCRIBE requested QoS")
            if qos > 2:
                raise MQTTDecodeError("SUBSCRIBE requested QoS byte is invalid")
            topics.append({"topic": topic, "qos": qos})
        if not topics:
            raise MQTTDecodeError("SUBSCRIBE has no topic filters")
        result["topics"] = topics
    elif packet_type == 9:
        result["packet_id"] = reader.u16("SUBACK packet identifier")
        codes = list(reader.take(reader.remaining, "SUBACK return codes"))
        if not codes or any(code not in (0, 1, 2, 0x80) for code in codes):
            raise MQTTDecodeError("SUBACK return codes are missing or invalid")
        result["return_codes"] = codes
    elif packet_type == 10:
        result["packet_id"] = reader.u16("UNSUBSCRIBE packet identifier")
        topics = []
        while reader.remaining:
            topics.append(reader.text("UNSUBSCRIBE topic filter"))
        if not topics:
            raise MQTTDecodeError("UNSUBSCRIBE has no topic filters")
        result["topics"] = [{"topic": topic} for topic in topics]
    else:  # PINGREQ, PINGRESP, DISCONNECT carry no variable header.
        reader.finish(name)
    return result


def _decode_connect(reader: _Reader) -> dict[str, Any]:
    protocol_name = reader.text("CONNECT protocol name")
    level = reader.u8("CONNECT protocol level")
    if (protocol_name, level) not in (("MQTT", 4), ("MQIsdp", 3)):
        raise MQTTDecodeError(f"unsupported MQTT protocol {protocol_name!r} level {level} (only 3.1/3.1.1 are decoded)")
    flags = reader.u8("CONNECT flags")
    if flags & 0x01:
        raise MQTTDecodeError("CONNECT reserved flag bit is set")
    keep_alive = reader.u16("CONNECT keep alive")
    result: dict[str, Any] = {"protocol_name": protocol_name, "protocol_level": level,
                              "clean_session": bool(flags & 0x02), "keep_alive": keep_alive,
                              "client_id": reader.text("CONNECT client identifier")}
    if flags & 0x04:
        result["will_topic"] = reader.text("CONNECT will topic")
        reader.binary("CONNECT will message")
    if flags & 0x80:
        result["username"] = reader.text("CONNECT user name")
    if flags & 0x40:
        reader.binary("CONNECT password")  # Read to validate framing; never retained.
        result["has_password"] = True
    reader.finish("CONNECT")
    return result


def _decode_publish(reader: _Reader, flags: int) -> dict[str, Any]:
    qos = (flags >> 1) & 0x03
    if qos == 3:
        raise MQTTDecodeError("PUBLISH QoS 3 is invalid")
    topic = reader.text("PUBLISH topic name")
    if "+" in topic or "#" in topic:
        raise MQTTDecodeError("PUBLISH topic name contains a wildcard")
    packet_id = reader.u16("PUBLISH packet identifier") if qos else None
    payload = reader.take(reader.remaining, "PUBLISH payload")
    return {"topic": topic, "qos": qos, "dup": bool(flags & 0x08), "retain": bool(flags & 0x01),
            "packet_id": packet_id, "payload_bytes": payload}


class MQTTStreamDecoder:
    """Split one direction of an MQTT byte stream into decoded packets.

    ``feed`` returns the packets completed by the new bytes. After malformed data the
    decoder stops, sets ``failed`` to the reason, and ignores later input.
    """

    def __init__(self) -> None:
        self._buffer = bytearray()
        self.failed: str | None = None

    @property
    def pending_bytes(self) -> int:
        """Bytes of an incomplete packet still waiting for more data."""
        return len(self._buffer)

    def feed(self, data: bytes) -> list[dict[str, Any]]:
        if self.failed is not None:
            return []
        self._buffer.extend(data)
        packets: list[dict[str, Any]] = []
        while self._buffer:
            if self._buffer[0] >> 4 not in PACKET_TYPES:
                self.failed = f"reserved or unsupported packet type {self._buffer[0] >> 4}"
                break
            try:
                header = _read_remaining_length(self._buffer, 1)
            except MQTTDecodeError as e:
                self.failed = str(e)
                break
            if header is None:
                break
            total = 1 + header[1] + header[0]
            if len(self._buffer) < total:
                break
            packet = decode_packet(bytes(self._buffer[:total]))
            del self._buffer[:total]
            if packet["type"] == "INVALID":
                self.failed = packet["error"]
                break
            packets.append(packet)
        return packets


def _seq_delta(seq: int, reference: int) -> int:
    """Signed distance seq - reference in 32-bit TCP sequence space."""
    delta = (seq - reference) % _SEQ_MOD
    return delta - _SEQ_MOD if delta >= _SEQ_MOD // 2 else delta


class TCPStream:
    """Reassemble one direction of a TCP connection into in-order bytes.

    Segments are ordered by sequence number. Bytes already delivered (exact retransmits and
    overlaps) are dropped. Segments beyond a hole wait in a bounded buffer; if the buffer
    overflows, or ``close`` is called with data still waiting, the stream records a gap in
    ``gap`` and stops delivering.
    """

    def __init__(self) -> None:
        self.initial_seq: int | None = None
        self.next_seq: int | None = None
        self.saw_handshake = False
        self.delivered_bytes = 0
        self.duplicate_bytes = 0
        self.gap: str | None = None
        self._pending: dict[int, bytes] = {}

    @property
    def active(self) -> bool:
        """True once the stream has received data or queued out-of-order segments."""
        return bool(self.delivered_bytes or self._pending)

    def syn(self, seq: int) -> None:
        """Record a SYN: the first data byte is seq + 1."""
        self.initial_seq = seq
        self.next_seq = (seq + 1) % _SEQ_MOD
        self.saw_handshake = True

    def add(self, seq: int, payload: bytes) -> bytes:
        """Accept one segment; return the bytes that became contiguous (possibly empty)."""
        if self.gap is not None or not payload:
            return b""
        if self.next_seq is None:
            self.next_seq = seq  # Capture began mid-connection; start at the first segment seen.
        delta = _seq_delta(seq, self.next_seq)
        if delta + len(payload) <= 0:
            self.duplicate_bytes += len(payload)
            return b""
        if delta > 0:
            if len(payload) > len(self._pending.get(seq, b"")):
                self._pending[seq] = payload
            if len(self._pending) > MAX_PENDING_SEGMENTS or sum(map(len, self._pending.values())) > MAX_PENDING_BYTES:
                self._declare_gap()
            return b""
        if delta < 0:
            self.duplicate_bytes += -delta
            payload = payload[-delta:]
        out = bytearray(payload)
        self.next_seq = (self.next_seq + len(payload)) % _SEQ_MOD
        progressed = True
        while progressed and self._pending:
            progressed = False
            for pending_seq in list(self._pending):
                offset = _seq_delta(pending_seq, self.next_seq)
                if offset > 0:
                    continue
                data = self._pending.pop(pending_seq)
                progressed = True
                if offset + len(data) <= 0:
                    self.duplicate_bytes += len(data)
                    continue
                self.duplicate_bytes += -offset
                tail = data[-offset:] if offset else data
                out.extend(tail)
                self.next_seq = (self.next_seq + len(tail)) % _SEQ_MOD
        self.delivered_bytes += len(out)
        return bytes(out)

    def close(self) -> str | None:
        """End of input: report a gap if segments are still waiting behind a hole."""
        if self.gap is None and self._pending:
            self._declare_gap()
        return self.gap

    def _declare_gap(self) -> None:
        if self.next_seq is None:
            return
        first = min(self._pending, key=lambda s: _seq_delta(s, self.next_seq))
        missing = _seq_delta(first, self.next_seq)
        waiting = sum(map(len, self._pending.values()))
        self.gap = (f"{missing} byte(s) missing before relative sequence offset {self.delivered_bytes + missing}; "
                    f"{waiting} later byte(s) in {len(self._pending)} segment(s) were not decoded")
        self._pending.clear()


class _Direction:
    """Reassembly and MQTT decoding state for one TCP direction."""

    def __init__(self) -> None:
        self.tcp = TCPStream()
        self.mqtt = MQTTStreamDecoder()
        self.reported = False


def _flow_text(key: tuple[str, int, str, int]) -> str:
    return f"{key[0]}:{key[1]} -> {key[2]}:{key[3]}"


def _payload_fields(payload: bytes) -> dict[str, Any] | None:
    """Return the payload as a dict when it is a UTF-8 JSON object, else None."""
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    return value if isinstance(value, dict) else None


def _finish(direction: _Direction, key: tuple[str, int, str, int], filename: str, findings: list[str]) -> None:
    """Report the end state of one direction (gap, incomplete packet, decode failure)."""
    gap = direction.tcp.close()
    flow = _flow_text(key)
    if gap is not None:
        findings.append(f"{filename}: TCP stream {flow} has a sequence gap; MQTT decoding stopped there ({gap})")
    if direction.mqtt.failed is not None and not direction.reported:
        findings.append(f"{filename}: MQTT stream {flow} could not be decoded ({direction.mqtt.failed}); later bytes in that stream were skipped")
        direction.reported = True
    if direction.mqtt.failed is None and direction.mqtt.pending_bytes:
        findings.append(f"{filename}: MQTT stream {flow} ends with {direction.mqtt.pending_bytes} byte(s) of an incomplete packet")


def mqtt_messages(path: Path, ports: Iterable[int] = DEFAULT_PORTS) -> tuple[list[dict], list[str]]:
    """Decode MQTT 3.1.1 control packets carried over TCP in a PCAP/PCAPNG capture.

    A TCP flow is decoded when either port is in ``ports`` (the broker side). Each returned
    message has ``timestamp`` and ``packet`` of the capture packet that completed it,
    ``source_ip``/``source_port``/``destination_ip``/``destination_port``, ``direction``
    (``client_to_broker`` or ``broker_to_client``), ``type``, ``client_id`` (from that
    connection's CONNECT, else None) and type-specific fields. PUBLISH messages carry
    ``topic``, ``qos``, ``packet_id``, ``dup``, ``retain``, ``payload_size``, ``payload``
    (the JSON object's fields, or None when the payload is not a JSON object) and
    ``acknowledged`` (None for QoS 0; otherwise whether a PUBACK/PUBREC with the same packet
    identifier came back on the same connection within the capture). Raw payload bytes are
    not returned. Problems are returned as findings; this function never raises.
    """
    filename = path.name
    messages: list[dict] = []
    findings: list[str] = []
    try:
        broker_ports = {int(p) for p in ports}
    except (TypeError, ValueError):
        return [], [f"{filename}: invalid MQTT port list; MQTT decoding skipped"]
    directions: dict[tuple[str, int, str, int], _Direction] = {}
    client_ids: dict[tuple[str, int, str, int], str] = {}
    unhandshaken: set[tuple[str, int, str, int]] = set()
    truncated: set[tuple[str, int, str, int]] = set()
    unacknowledged: dict[tuple[tuple[str, int, str, int], bool, int], dict] = {}
    try:
        for segment in tcp_segments(path):
            to_broker = segment["destination_port"] in broker_ports
            if not to_broker and segment["source_port"] not in broker_ports:
                continue
            key = (segment["source_ip"], segment["source_port"], segment["destination_ip"], segment["destination_port"])
            connection = key if to_broker else (key[2], key[3], key[0], key[1])
            direction = directions.get(key)
            if segment["flags"] & TCP_SYN:
                if direction is not None and direction.tcp.active and direction.tcp.initial_seq != segment["seq"]:
                    _finish(direction, key, filename, findings)  # Port reuse: a new connection starts.
                    client_ids.pop(connection, None)
                    direction = None
                if direction is None:
                    direction = directions[key] = _Direction()
                if not direction.tcp.active:
                    direction.tcp.syn(segment["seq"])
                continue
            if direction is None:
                direction = directions[key] = _Direction()
            if not segment["payload"]:
                continue
            if not direction.tcp.saw_handshake and not direction.tcp.active:
                unhandshaken.add(key)
            if segment["truncated"]:
                truncated.add(key)
                direction.tcp.gap = direction.tcp.gap or f"capture snap length cut segment payload at packet {segment['packet']}"
            data = direction.tcp.add(segment["seq"], segment["payload"])
            for packet in direction.mqtt.feed(data) if data else []:
                if packet["type"] == "CONNECT" and to_broker:
                    client_ids[connection] = packet["client_id"]
                message: dict[str, Any] = {
                    "timestamp": segment["timestamp"], "packet": segment["packet"],
                    "source_ip": key[0], "source_port": key[1], "destination_ip": key[2], "destination_port": key[3],
                    "direction": "client_to_broker" if to_broker else "broker_to_client",
                    "client_id": client_ids.get(connection)}
                message.update(packet)
                if packet["type"] == "PUBLISH":
                    payload = message.pop("payload_bytes")
                    message["payload_size"] = len(payload)
                    message["payload"] = _payload_fields(payload)
                    message["acknowledged"] = None if not packet["qos"] else False
                    if packet["qos"]:
                        unacknowledged[(connection, to_broker, packet["packet_id"])] = message
                elif packet["type"] in ("PUBACK", "PUBREC"):
                    # The acknowledgement travels in the opposite direction to its PUBLISH.
                    publish = unacknowledged.pop((connection, not to_broker, packet["packet_id"]), None)
                    if publish is not None:
                        publish["acknowledged"] = True
                messages.append(message)
            if direction.mqtt.failed is not None and not direction.reported:
                findings.append(f"{filename}: MQTT stream {_flow_text(key)} could not be decoded at packet {segment['packet']} ({direction.mqtt.failed}); later bytes in that stream were skipped")
                direction.reported = True
    except (OSError, CaptureError) as e:
        findings.append(f"{filename}: capture read stopped ({e}); MQTT decoding covers only packets before that point")
    except Exception as e:  # Defensive: this public API reports problems instead of raising.
        findings.append(f"{filename}: unexpected MQTT decoding error ({type(e).__name__}: {e}); results are partial")
    for key, direction in directions.items():
        _finish(direction, key, filename, findings)
    if unhandshaken:
        findings.append(f"{filename}: {len(unhandshaken)} MQTT TCP stream direction(s) began without a captured handshake; decoding started at the first captured segment")
    if truncated:
        findings.append(f"{filename}: {len(truncated)} MQTT TCP stream direction(s) contain snap-length-truncated segments")
    return messages, findings
