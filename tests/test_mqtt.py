"""Tests for MQTT decoding, TCP reassembly, and MQTT evidence rows in the pipeline."""
from __future__ import annotations

import ipaddress
import json
import random
import struct
import tempfile
import unittest
from pathlib import Path

from nexus_iot.evaluate import score_case
from nexus_iot.mqtt import (MQTTDecodeError, MQTTStreamDecoder, TCPStream, _read_remaining_length,
                            decode_packet, encode_remaining_length, mqtt_messages)
from nexus_iot.pipeline import analyze

REPO_ROOT = Path(__file__).resolve().parents[1]
BROKER_IP = "172.30.0.10"
DOOR_IP = "172.30.0.21"
GATEWAY_IP = "172.30.0.11"

TCP_ACK = 0x10
TCP_PSH_ACK = 0x18
TCP_SYN = 0x02
TCP_SYN_ACK = 0x12


# ---------------------------------------------------------------------------
# MQTT packet builders
# ---------------------------------------------------------------------------

def mqtt_text(value: str) -> bytes:
    raw = value.encode("utf-8")
    return struct.pack("!H", len(raw)) + raw


def fixed(first_byte: int, body: bytes) -> bytes:
    return bytes([first_byte]) + encode_remaining_length(len(body)) + body


def connect(client_id: str, username: str | None = None, password: bytes | None = None,
            will: tuple[str, bytes] | None = None) -> bytes:
    flags = 0x02
    tail = mqtt_text(client_id)
    if will:
        flags |= 0x04
        tail += mqtt_text(will[0]) + struct.pack("!H", len(will[1])) + will[1]
    if username is not None:
        flags |= 0x80
        tail += mqtt_text(username)
    if password is not None:
        flags |= 0x40
        tail += struct.pack("!H", len(password)) + password
    return fixed(0x10, mqtt_text("MQTT") + bytes([4, flags]) + struct.pack("!H", 60) + tail)


def connack(return_code: int = 0) -> bytes:
    return fixed(0x20, bytes([0, return_code]))


def publish(topic: str, payload: bytes, qos: int = 1, packet_id: int = 1, dup: bool = False, retain: bool = False) -> bytes:
    first = 0x30 | (0x08 if dup else 0) | (qos << 1) | (1 if retain else 0)
    body = mqtt_text(topic) + (struct.pack("!H", packet_id) if qos else b"") + payload
    return fixed(first, body)


def ack(first_byte: int, packet_id: int) -> bytes:
    return fixed(first_byte, struct.pack("!H", packet_id))


def puback(packet_id: int) -> bytes:
    return ack(0x40, packet_id)


def subscribe(packet_id: int, topic: str, qos: int = 1) -> bytes:
    return fixed(0x82, struct.pack("!H", packet_id) + mqtt_text(topic) + bytes([qos]))


DISCONNECT = b"\xe0\x00"
PINGREQ = b"\xc0\x00"
PINGRESP = b"\xd0\x00"


def record(event_id: str, sequence: int, event: str, timestamp: float, device: str = "door-sensor") -> dict:
    return {"event_id": event_id, "sequence": sequence, "device": device, "event": event, "timestamp": timestamp}


def payload_of(row: dict) -> bytes:
    return json.dumps(row).encode("utf-8")


# ---------------------------------------------------------------------------
# Ethernet/IPv4/TCP + classic PCAP builders
# ---------------------------------------------------------------------------

def tcp_frame(src: str, sport: int, dst: str, dport: int, seq: int, payload: bytes = b"", flags: int = TCP_PSH_ACK) -> bytes:
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 5 << 4, flags, 65535, 0, 0)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp) + len(payload), 1, 0, 64, 6, 0,
                     ipaddress.ip_address(src).packed, ipaddress.ip_address(dst).packed)
    frame = bytes.fromhex("020000000002020000000001") + b"\x08\x00" + ip + tcp + payload
    return frame + b"\x00" * max(0, 60 - len(frame))  # Ethernet minimum-size padding.


def write_pcap(path: Path, frames: list[tuple[float, bytes]]) -> None:
    data = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for ts, frame in frames:
        sec = int(ts)
        usec = round((ts - sec) * 1_000_000)
        data += struct.pack("<IIII", sec, usec, len(frame), len(frame)) + frame
    path.write_bytes(bytes(data))


class Flow:
    """One TCP connection between a client and the broker, tracking sequence numbers."""

    def __init__(self, client_ip: str, client_port: int, broker_port: int = 1883,
                 client_isn: int = 1000, broker_isn: int = 900_000) -> None:
        self.client = (client_ip, client_port)
        self.broker = (BROKER_IP, broker_port)
        self.client_isn = client_isn
        self.broker_isn = broker_isn
        self.client_seq = client_isn + 1
        self.broker_seq = broker_isn + 1

    def handshake(self, ts: float) -> list[tuple[float, bytes]]:
        return [(ts, tcp_frame(*self.client, *self.broker, self.client_isn, flags=TCP_SYN)),
                (ts, tcp_frame(*self.broker, *self.client, self.broker_isn, flags=TCP_SYN_ACK)),
                (ts, tcp_frame(*self.client, *self.broker, self.client_seq, flags=TCP_ACK))]

    def segment(self, ts: float, data: bytes, from_client: bool = True, seq: int | None = None,
                advance: bool = True) -> tuple[float, bytes]:
        """A data segment; seq defaults to the next sequence number in that direction."""
        if from_client:
            start = self.client_seq if seq is None else seq
            frame = tcp_frame(*self.client, *self.broker, start, data)
            if advance:
                self.client_seq = start + len(data)
        else:
            start = self.broker_seq if seq is None else seq
            frame = tcp_frame(*self.broker, *self.client, start, data)
            if advance:
                self.broker_seq = start + len(data)
        return ts, frame


def decode_frames(frames: list[tuple[float, bytes]], ports: set[int] | None = None) -> tuple[list[dict], list[str]]:
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "capture.pcap"
        write_pcap(path, frames)
        return mqtt_messages(path, ports or {1883})


# ---------------------------------------------------------------------------
# Decoder unit tests
# ---------------------------------------------------------------------------

class RemainingLengthTests(unittest.TestCase):
    def test_boundary_values_round_trip(self):
        cases = {0: b"\x00", 127: b"\x7f", 128: b"\x80\x01", 16_383: b"\xff\x7f", 16_384: b"\x80\x80\x01",
                 2_097_151: b"\xff\xff\x7f", 2_097_152: b"\x80\x80\x80\x01", 268_435_455: b"\xff\xff\xff\x7f"}
        for value, encoded in cases.items():
            with self.subTest(value=value):
                self.assertEqual(encode_remaining_length(value), encoded)
                self.assertEqual(_read_remaining_length(b"\x30" + encoded), (value, len(encoded)))

    def test_incomplete_and_overlong_encodings(self):
        self.assertIsNone(_read_remaining_length(b"\x30"))
        self.assertIsNone(_read_remaining_length(b"\x30\x80\x80"))
        with self.assertRaises(MQTTDecodeError):
            _read_remaining_length(b"\x30\x80\x80\x80\x80\x01")
        with self.assertRaises(ValueError):
            encode_remaining_length(268_435_456)
        with self.assertRaises(ValueError):
            encode_remaining_length(-1)

    def test_overlong_varint_in_stream_is_a_failure_not_an_exception(self):
        decoder = MQTTStreamDecoder()
        self.assertEqual(decoder.feed(b"\x30\xff\xff\xff\xff\x01"), [])
        self.assertIn("more than four bytes", decoder.failed)


class DecodePacketTests(unittest.TestCase):
    def test_connect_with_will_username_and_password(self):
        packet = decode_packet(connect("door-sensor", username="examiner", password=b"secret", will=("nexus/lwt", b"gone")))
        self.assertEqual(packet["type"], "CONNECT")
        self.assertEqual(packet["client_id"], "door-sensor")
        self.assertEqual((packet["protocol_name"], packet["protocol_level"], packet["keep_alive"]), ("MQTT", 4, 60))
        self.assertTrue(packet["clean_session"])
        self.assertEqual(packet["will_topic"], "nexus/lwt")
        self.assertEqual(packet["username"], "examiner")
        self.assertTrue(packet["has_password"])
        self.assertNotIn(b"secret", repr(packet).encode())

    def test_connect_mqtt5_is_reported_invalid(self):
        mqtt5 = fixed(0x10, mqtt_text("MQTT") + bytes([5, 2]) + struct.pack("!H", 60) + b"\x00" + mqtt_text("x"))
        self.assertEqual(decode_packet(mqtt5)["type"], "INVALID")

    def test_connack(self):
        self.assertEqual(decode_packet(connack(5)), {"type": "CONNACK", "session_present": False, "return_code": 5})

    def test_publish_qos0_and_qos1(self):
        qos0 = decode_packet(publish("a/b", b"hi", qos=0, retain=True))
        self.assertEqual((qos0["topic"], qos0["qos"], qos0["packet_id"], qos0["retain"], qos0["payload_bytes"]),
                         ("a/b", 0, None, True, b"hi"))
        qos1 = decode_packet(publish("a/b", b"{}", qos=1, packet_id=513, dup=True))
        self.assertEqual((qos1["qos"], qos1["packet_id"], qos1["dup"]), (1, 513, True))

    def test_acknowledgement_types(self):
        for first, name in ((0x40, "PUBACK"), (0x50, "PUBREC"), (0x62, "PUBREL"), (0x70, "PUBCOMP"), (0xB0, "UNSUBACK")):
            with self.subTest(name=name):
                self.assertEqual(decode_packet(ack(first, 7)), {"type": name, "packet_id": 7})

    def test_subscribe_suback_unsubscribe(self):
        self.assertEqual(decode_packet(subscribe(3, "nexus/#", 1)),
                         {"type": "SUBSCRIBE", "packet_id": 3, "topics": [{"topic": "nexus/#", "qos": 1}]})
        self.assertEqual(decode_packet(fixed(0x90, struct.pack("!H", 3) + bytes([1, 0x80]))),
                         {"type": "SUBACK", "packet_id": 3, "return_codes": [1, 0x80]})
        self.assertEqual(decode_packet(fixed(0xA2, struct.pack("!H", 4) + mqtt_text("nexus/#"))),
                         {"type": "UNSUBSCRIBE", "packet_id": 4, "topics": [{"topic": "nexus/#"}]})

    def test_empty_packets(self):
        self.assertEqual(decode_packet(PINGREQ), {"type": "PINGREQ"})
        self.assertEqual(decode_packet(PINGRESP), {"type": "PINGRESP"})
        self.assertEqual(decode_packet(DISCONNECT), {"type": "DISCONNECT"})

    def test_malformed_packets_are_invalid(self):
        bad = {
            "empty": b"",
            "one byte": b"\x30",
            "reserved type 0": b"\x00\x00",
            "reserved type 15": b"\xf0\x00",
            "PUBREL wrong flags": ack(0x60, 1),
            "SUBSCRIBE wrong flags": fixed(0x80, struct.pack("!H", 1) + mqtt_text("t") + b"\x01"),
            "QoS 3": fixed(0x36, mqtt_text("t") + b"\x00\x01"),
            "wildcard topic": publish("a/+", b"", qos=0),
            "length mismatch": b"\x30\x05\x00\x01a",
            "truncated CONNECT": connect("door-sensor")[:-3],
            "DISCONNECT with body": b"\xe0\x01\x00",
            "SUBSCRIBE without topics": fixed(0x82, struct.pack("!H", 1)),
            "SUBSCRIBE bad QoS": fixed(0x82, struct.pack("!H", 1) + mqtt_text("t") + b"\x03"),
            "invalid UTF-8 topic": fixed(0x30, b"\x00\x02\xff\xfe"),
            "CONNACK reserved bits": fixed(0x20, b"\x02\x00"),
            "CONNECT trailing bytes": fixed(0x10, connect("x")[2:] + b"\x00"),
        }
        for name, data in bad.items():
            with self.subTest(name=name):
                self.assertEqual(decode_packet(data)["type"], "INVALID")

    def test_random_garbage_never_raises(self):
        rng = random.Random(1234)
        for _ in range(2_000):
            data = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 40)))
            result = decode_packet(data)
            self.assertIn("type", result)
            decoder = MQTTStreamDecoder()
            decoder.feed(data)
            decoder.feed(data)


class StreamDecoderTests(unittest.TestCase):
    def test_byte_at_a_time_feed(self):
        stream = publish("nexus/a/b", b"x" * 200, packet_id=9) + PINGREQ
        decoder = MQTTStreamDecoder()
        seen = []
        for i in range(len(stream)):
            seen.extend(decoder.feed(stream[i:i + 1]))
        self.assertEqual([p["type"] for p in seen], ["PUBLISH", "PINGREQ"])
        self.assertEqual(decoder.pending_bytes, 0)

    def test_garbage_stops_stream(self):
        decoder = MQTTStreamDecoder()
        self.assertEqual([p["type"] for p in decoder.feed(PINGREQ + b"\x00\x00")], ["PINGREQ"])
        self.assertIsNotNone(decoder.failed)
        self.assertEqual(decoder.feed(PINGREQ), [])


# ---------------------------------------------------------------------------
# TCP reassembly unit tests
# ---------------------------------------------------------------------------

class TCPStreamTests(unittest.TestCase):
    def test_in_order_split_and_out_of_order(self):
        stream = TCPStream()
        stream.syn(99)
        self.assertEqual(stream.add(100, b"abc"), b"abc")
        self.assertEqual(stream.add(106, b"ghi"), b"")  # Arrives before "def".
        self.assertEqual(stream.add(103, b"def"), b"defghi")
        self.assertIsNone(stream.close())

    def test_retransmit_and_partial_overlap(self):
        stream = TCPStream()
        stream.syn(0)
        self.assertEqual(stream.add(1, b"abcd"), b"abcd")
        self.assertEqual(stream.add(1, b"abcd"), b"")
        self.assertEqual(stream.add(3, b"cdEF"), b"EF")
        self.assertEqual(stream.duplicate_bytes, 6)

    def test_gap_is_reported_and_stops_delivery(self):
        stream = TCPStream()
        stream.syn(0)
        self.assertEqual(stream.add(1, b"ab"), b"ab")
        self.assertEqual(stream.add(10, b"zz"), b"")
        gap = stream.close()
        self.assertIn("7 byte(s) missing", gap)
        self.assertEqual(stream.add(3, b"c"), b"")

    def test_sequence_wraparound(self):
        stream = TCPStream()
        stream.syn(0xFFFFFFFD)
        self.assertEqual(stream.add(0xFFFFFFFE, b"ab"), b"ab")
        self.assertEqual(stream.add(0, b"cd"), b"cd")

    def test_capture_starting_mid_connection(self):
        stream = TCPStream()
        self.assertEqual(stream.add(5000, b"xy"), b"xy")
        self.assertFalse(stream.saw_handshake)


# ---------------------------------------------------------------------------
# mqtt_messages over synthetic captures
# ---------------------------------------------------------------------------

class CaptureMessageTests(unittest.TestCase):
    def setUp(self):
        self.flow = Flow(DOOR_IP, 40000)
        self.frames = self.flow.handshake(10.0) + [self.flow.segment(10.1, connect("door-sensor"))]

    def test_packet_split_across_segments_uses_completing_segment_time(self):
        packet = publish("nexus/door-sensor/door_open", payload_of(record("door-sensor-00001", 1, "door_open", 11.0)))
        self.frames += [self.flow.segment(11.0, packet[:10]), self.flow.segment(11.5, packet[10:])]
        messages, findings = decode_frames(self.frames)
        published = [m for m in messages if m["type"] == "PUBLISH"]
        self.assertEqual(len(published), 1)
        self.assertAlmostEqual(published[0]["timestamp"], 11.5)
        self.assertEqual(published[0]["client_id"], "door-sensor")
        self.assertEqual(published[0]["payload"]["event_id"], "door-sensor-00001")
        self.assertEqual(findings, [])

    def test_two_packets_in_one_segment(self):
        first = publish("t/a", b'{"n": 1}', packet_id=1)
        second = publish("t/b", b'{"n": 2}', packet_id=2)
        self.frames.append(self.flow.segment(11.0, first + second))
        messages, _ = decode_frames(self.frames)
        self.assertEqual([m["topic"] for m in messages if m["type"] == "PUBLISH"], ["t/a", "t/b"])
        self.assertTrue(all(m["packet"] == 5 for m in messages if m["type"] == "PUBLISH"))

    def test_out_of_order_segments(self):
        first = publish("t/a", b"1", packet_id=1)
        second = publish("t/b", b"2", packet_id=2)
        start = self.flow.client_seq
        self.frames += [self.flow.segment(11.0, second, seq=start + len(first), advance=False),
                        self.flow.segment(11.2, first, seq=start, advance=False)]
        messages, findings = decode_frames(self.frames)
        published = [m for m in messages if m["type"] == "PUBLISH"]
        self.assertEqual([m["topic"] for m in published], ["t/a", "t/b"])
        self.assertTrue(all(m["timestamp"] == 11.2 for m in published))
        self.assertEqual(findings, [])

    def test_retransmitted_segment_is_not_decoded_twice(self):
        packet = publish("t/a", b"1", packet_id=1)
        start = self.flow.client_seq
        self.frames += [self.flow.segment(11.0, packet), self.flow.segment(11.3, packet, seq=start, advance=False)]
        messages, _ = decode_frames(self.frames)
        self.assertEqual(sum(m["type"] == "PUBLISH" for m in messages), 1)

    def test_gap_stops_stream_with_finding(self):
        packet = publish("t/a", b"1", packet_id=1)
        self.frames += [self.flow.segment(11.0, packet[:5]), self.flow.segment(11.1, packet[5:8], advance=False),
                        self.flow.segment(11.2, PINGREQ, seq=self.flow.client_seq + 50)]
        messages, findings = decode_frames(self.frames)
        self.assertEqual([m["type"] for m in messages], ["CONNECT"])
        self.assertTrue(any("sequence gap" in f for f in findings), findings)

    def test_garbage_stream_produces_finding(self):
        self.frames.append(self.flow.segment(11.0, b"\x00\x01garbage"))
        messages, findings = decode_frames(self.frames)
        self.assertEqual([m["type"] for m in messages], ["CONNECT"])
        self.assertTrue(any("could not be decoded" in f for f in findings), findings)

    def test_direction_ack_and_ports(self):
        self.frames += [self.flow.segment(10.2, connack(), from_client=False),
                        self.flow.segment(11.0, publish("t/a", b"1", packet_id=4)),
                        self.flow.segment(11.1, puback(4), from_client=False),
                        self.flow.segment(12.0, publish("t/b", b"2", packet_id=5)),
                        self.flow.segment(13.0, publish("t/c", b"3", qos=0)),
                        self.flow.segment(14.0, DISCONNECT)]
        messages, _ = decode_frames(self.frames)
        connack_message = next(m for m in messages if m["type"] == "CONNACK")
        self.assertEqual((connack_message["direction"], connack_message["client_id"]), ("broker_to_client", "door-sensor"))
        acknowledged = {m["topic"]: m["acknowledged"] for m in messages if m["type"] == "PUBLISH"}
        self.assertEqual(acknowledged, {"t/a": True, "t/b": False, "t/c": None})
        self.assertEqual(messages[-1]["type"], "DISCONNECT")
        other_port, _ = decode_frames(self.frames, ports={8883})
        self.assertEqual(other_port, [])

    def test_pcapng_capture(self):
        self.frames.append(self.flow.segment(11.0, publish("t/a", b'{"n": 1}', packet_id=1)))
        blocks = bytearray(struct.pack("<IIIHHqI", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1, 28))
        blocks += struct.pack("<IIHHII", 1, 20, 1, 0, 65535, 20)
        for ts, frame in self.frames:
            ticks = round(ts * 1_000_000)
            body = struct.pack("<IIIII", 0, ticks >> 32, ticks & 0xFFFFFFFF, len(frame), len(frame))
            body += frame + b"\x00" * ((4 - len(frame) % 4) % 4)
            blocks += struct.pack("<II", 6, 12 + len(body)) + body + struct.pack("<I", 12 + len(body))
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "capture.pcapng"
            path.write_bytes(bytes(blocks))
            messages, findings = mqtt_messages(path)
        self.assertEqual([m["type"] for m in messages], ["CONNECT", "PUBLISH"])
        self.assertAlmostEqual(messages[1]["timestamp"], 11.0)
        self.assertEqual(findings, [])

    def test_unreadable_or_truncated_captures_do_not_raise(self):
        with tempfile.TemporaryDirectory() as td:
            missing, findings = mqtt_messages(Path(td) / "absent.pcap")
            self.assertEqual(missing, [])
            self.assertTrue(findings)
            path = Path(td) / "cut.pcap"
            write_pcap(path, self.frames)
            path.write_bytes(path.read_bytes()[:-7])
            messages, findings = mqtt_messages(path)
            self.assertTrue(any("capture read stopped" in f for f in findings), findings)
            garbage = Path(td) / "garbage.pcap"
            garbage.write_bytes(b"not a capture at all")
            self.assertEqual(mqtt_messages(garbage)[0], [])


# ---------------------------------------------------------------------------
# End-to-end through the analysis pipeline
# ---------------------------------------------------------------------------

DEVICE_OFFSET = 5.0
EVENTS = [("door-sensor-00001", "boot"), ("door-sensor-00002", "door_open"), ("door-sensor-00003", "door_close"),
          ("door-sensor-00004", "door_open"), ("door-sensor-00005", "door_close")]


def build_case(evidence: Path, devices: dict | None = None, door_client: str = "door-sensor") -> None:
    """Device log + gateway log + capture for five door-sensor events.

    Events 1-3 are published normally and copied to the gateway subscriber; event 4 uses a
    topic that does not match its payload; event 5 is never acknowledged by the broker.
    """
    evidence.mkdir(parents=True, exist_ok=True)
    device_rows, gateway_rows = [], []
    gateway = Flow(GATEWAY_IP, 45000, client_isn=7000, broker_isn=8000)
    door = Flow(DOOR_IP, 40000)
    frames = gateway.handshake(999.0) + [gateway.segment(999.1, connect("nexus-gateway")),
                                         gateway.segment(999.2, connack(), from_client=False),
                                         gateway.segment(999.3, subscribe(1, "nexus/#")),
                                         gateway.segment(999.4, fixed(0x90, b"\x00\x01\x01"), from_client=False)]
    frames += door.handshake(999.5) + [door.segment(999.6, connect(door_client)),
                                       door.segment(999.7, connack(), from_client=False)]
    for n, (event_id, event) in enumerate(EVENTS, 1):
        sent = 1000.0 + 2 * n
        row = record(event_id, n, event, sent + DEVICE_OFFSET)
        device_rows.append(row)
        topic = "nexus/door-sensor/wrong_event" if n == 4 else f"nexus/door-sensor/{event}"
        frames.append(door.segment(sent, publish(topic, payload_of(row), packet_id=n)))
        if n == 5:
            continue  # No PUBACK, no delivery to the gateway subscriber.
        frames.append(door.segment(sent + 0.001, puback(n), from_client=False))
        frames.append(gateway.segment(sent + 0.002, publish(topic, payload_of(row), packet_id=n), from_client=False))
        frames.append(gateway.segment(sent + 0.003, puback(n)))
        if n != 4:
            gateway_rows.append({"timestamp": sent + 0.002, "event": event, "event_id": event_id, "sequence": n,
                                 "peer": "door-sensor", "topic": topic, "device_timestamp": row["timestamp"]})
    frames.append(door.segment(1020.0, DISCONNECT))
    write_pcap(evidence / "gateway-1.pcap", frames)
    (evidence / "door-sensor.jsonl").write_text("".join(json.dumps(r) + "\n" for r in device_rows), encoding="utf-8")
    (evidence / "gateway.jsonl").write_text("".join(json.dumps(r) + "\n" for r in gateway_rows), encoding="utf-8")
    config = devices if devices is not None else {"device_ips": {"door-sensor": [DOOR_IP]}}
    (evidence / "devices.json").write_text(json.dumps(config), encoding="utf-8")


class PipelineMQTTTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.evidence = self.root / "evidence"

    def tearDown(self):
        self.tmp.cleanup()

    def test_publish_is_third_witness_and_session_packets_are_network_observations(self):
        build_case(self.evidence)
        report = analyze(self.evidence, self.root / "derived")
        timeline = {e["event_id"]: e for e in report["timeline"]}

        first = timeline["door-sensor-00002"]
        self.assertEqual(first["label"], "Confirmed")
        self.assertEqual(first["independent_source_count"], 3)
        mqtt_support = [x for x in first["supporting_evidence"] if "MQTT PUBLISH" in x]
        self.assertEqual(len(mqtt_support), 1, "broker-to-subscriber copy must not add a second row")
        self.assertIn("gateway-1.pcap packet", mqtt_support[0])
        self.assertAlmostEqual(first["timestamp"], 1004.002, places=2)

        # Event 4 lacks a gateway log row but is seen in the capture: device + capture.
        self.assertEqual(timeline["door-sensor-00004"]["independent_source_count"], 2)
        # Event 5 was never acknowledged, so only the device log supports it.
        self.assertEqual(timeline["door-sensor-00005"]["label"], "Single-source")

        clock = report["clock_estimates"]["door-sensor.jsonl"]
        self.assertTrue(clock["applied"])
        self.assertAlmostEqual(clock["offset_seconds"], DEVICE_OFFSET, places=2)

        session = [e for e in report["timeline"] if e["event"].startswith("mqtt_")]
        self.assertEqual(sorted(e["event"] for e in session),
                         ["mqtt_connect", "mqtt_connect", "mqtt_disconnect", "mqtt_subscribe"])
        for row in session:
            self.assertEqual(row["label"], "Single-source")
            self.assertEqual(row["time_basis"], "capture-clock-as-recorded")
            self.assertEqual(row["independent_source_count"], 1)
            self.assertTrue(row["event_id"].startswith("gateway-1.pcap:mqtt-"))
            self.assertEqual(row["network_summary"]["protocol"], "tcp")
        door_connect = next(e for e in session if e["network_summary"]["mqtt"].get("client_id") == "door-sensor")
        self.assertEqual(door_connect["network_summary"]["mapped_devices"], ["door-sensor"])

        issues = report["validation_issues"]
        self.assertTrue(any("MQTT topic mismatch for door-sensor-00004" in x for x in issues), issues)
        self.assertTrue(any("not acknowledged by the broker" in x and "door-sensor-00005" in x for x in issues), issues)
        self.assertFalse(any("duplicate event IDs" in x for x in issues), issues)
        self.assertFalse(any("device_ips does not list" in x for x in issues), issues)
        self.assertFalse(any("Unknown gap" == e["label"] for e in report["timeline"]))

    def test_source_ip_disagreeing_with_device_ips_is_a_finding(self):
        build_case(self.evidence, {"device_ips": {"door-sensor": ["192.0.2.99"]}})
        report = analyze(self.evidence, self.root / "derived")
        self.assertTrue(any("device_ips does not list" in x for x in report["validation_issues"]))
        self.assertEqual(next(e for e in report["timeline"] if e["event_id"] == "door-sensor-00002")["label"], "Confirmed")

    def test_mqtt_ports_override(self):
        build_case(self.evidence, {"mqtt_ports": [8883]})
        report = analyze(self.evidence, self.root / "derived")
        self.assertFalse(any(e["event"].startswith("mqtt_") for e in report["timeline"]))
        self.assertEqual(next(e for e in report["timeline"] if e["event_id"] == "door-sensor-00002")["independent_source_count"], 2)
        build_case(self.evidence, {"mqtt_ports": "1883"})
        report = analyze(self.evidence, self.root / "derived2")
        self.assertTrue(any("mqtt_ports must be" in x for x in report["validation_issues"]))

    def test_score_case_ignores_mqtt_session_rows(self):
        build_case(self.evidence)
        events = [{"event_id": event_id, "timestamp": 1000.0 + 2 * n, "device": "door-sensor", "event": event,
                   "expected_sources": ["door-sensor.jsonl"] + (["gateway.jsonl"] if n not in (4, 5) else [])}
                  for n, (event_id, event) in enumerate(EVENTS, 1)]
        truth = {"condition": "test", "events": events, "tampering_seeded": False}
        result = score_case(self.evidence, truth, self.root / "scored", "T1", "test")
        self.assertEqual(result["false_positive_events"], 0)
        self.assertEqual(result["event_f1"], 1.0)
        self.assertEqual(result["event_label_accuracy"], 1.0)


    def test_client_identity_rule_over_decoded_capture(self):
        rules_path = self.root / "rules.json"
        rules_path.write_text(json.dumps({"rules": [
            {"id": "M1", "title": "own id", "type": "mqtt_client", "allowed": ["{device}", "nexus-gateway"]}]}),
            encoding="utf-8")
        build_case(self.evidence)
        report = analyze(self.evidence, self.root / "derived", rules_path=rules_path)
        row = next(e for e in report["timeline"] if e["event_id"] == "door-sensor-00002")
        self.assertEqual(row["mqtt_publishers"], [{"client_id": "door-sensor", "device": "door-sensor"}])
        self.assertNotIn("mqtt_publishers", next(e for e in report["timeline"] if e["event_id"] == "door-sensor-00005"))
        self.assertEqual(report["rule_findings"], [])

        build_case(self.evidence, door_client="intruder")
        report = analyze(self.evidence, self.root / "derived2", rules_path=rules_path)
        flagged = {f["event_ids"][0] for f in report["rule_findings"]}
        # The CONNECT, three acknowledged publishes plus the mismatched-topic one, and the DISCONNECT.
        self.assertEqual(len(flagged), 6, report["rule_findings"])
        self.assertIn("door-sensor-00002", flagged)
        detail = next(f["detail"] for f in report["rule_findings"] if f["event_ids"] == ["door-sensor-00002"])
        self.assertIn("client 'intruder' published (device door-sensor)", detail)


class RealTestbedCaptureTests(unittest.TestCase):
    def test_every_publish_event_id_is_in_device_logs(self):
        captures = sorted(REPO_ROOT.glob("testbed/cases/*/S1/evidence/gateway-*.pcap"))
        if not captures:
            self.skipTest("no testbed S1 capture available")
        for capture in captures:
            with self.subTest(capture=str(capture.relative_to(REPO_ROOT))):
                device_ids = set()
                for log in capture.parent.glob("*.jsonl"):
                    if log.name.startswith("gateway"):
                        continue
                    for line in log.read_text(encoding="utf-8").splitlines():
                        if line.strip():
                            device_ids.add(json.loads(line).get("event_id"))
                messages, _ = mqtt_messages(capture)
                published = [m["payload"]["event_id"] for m in messages
                             if m["type"] == "PUBLISH" and m["direction"] == "client_to_broker" and m["payload"]]
                self.assertTrue(published)
                self.assertLessEqual(set(published), device_ids)


if __name__ == "__main__":
    unittest.main()
