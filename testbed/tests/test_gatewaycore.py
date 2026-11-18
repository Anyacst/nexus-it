"""Unit tests for testbed.gateway.gatewaycore (stdlib only, no broker needed)."""

import json
import unittest

from testbed.gateway.gatewaycore import gateway_record, parse_payload

VALID = {
    "event_id": "door-sensor-00002",
    "sequence": 2,
    "device": "door-sensor",
    "event": "door_open",
    "timestamp": 1700000003.1,
}
TOPIC = "nexus/door-sensor/door_open"


def encode(obj: object) -> bytes:
    return json.dumps(obj).encode("utf-8")


def with_field(**changes: object) -> dict:
    payload = dict(VALID)
    payload.update(changes)
    return payload


class ParsePayloadTests(unittest.TestCase):
    def test_valid_payload(self) -> None:
        self.assertEqual(parse_payload(TOPIC, encode(VALID)), VALID)

    def test_valid_payload_with_value_and_int_timestamp(self) -> None:
        payload = {
            "event_id": "temp-sensor-00002",
            "sequence": 2,
            "device": "temp-sensor",
            "event": "temperature_reading",
            "timestamp": 1700000003,
            "value": 21.4,
        }
        self.assertEqual(parse_payload("nexus/temp-sensor/temperature_reading", encode(payload)), payload)

    def test_rejects_non_json(self) -> None:
        self.assertIsNone(parse_payload(TOPIC, b"not json"))
        self.assertIsNone(parse_payload(TOPIC, b""))
        self.assertIsNone(parse_payload(TOPIC, b"\xff\xfe\x00"))

    def test_rejects_non_object_json(self) -> None:
        self.assertIsNone(parse_payload(TOPIC, encode([VALID])))
        self.assertIsNone(parse_payload(TOPIC, encode("door_open")))
        self.assertIsNone(parse_payload(TOPIC, encode(42)))

    def test_rejects_missing_fields(self) -> None:
        for field in VALID:
            payload = dict(VALID)
            del payload[field]
            self.assertIsNone(parse_payload(TOPIC, encode(payload)), field)

    def test_rejects_wrong_types(self) -> None:
        bad_values = [
            {"event_id": 7},
            {"sequence": "2"},
            {"sequence": 2.0},
            {"device": None},
            {"event": ["door_open"]},
            {"timestamp": "1700000003.1"},
            {"timestamp": None},
            {"timestamp": True},
        ]
        for change in bad_values:
            self.assertIsNone(parse_payload(TOPIC, encode(with_field(**change))), change)

    def test_rejects_bool_sequence(self) -> None:
        self.assertIsNone(parse_payload(TOPIC, encode(with_field(sequence=True))))
        self.assertIsNone(parse_payload(TOPIC, encode(with_field(sequence=False))))

    def test_rejects_topic_mismatch(self) -> None:
        self.assertIsNone(parse_payload("nexus/door-sensor/door_close", encode(VALID)))
        self.assertIsNone(parse_payload("nexus/smart-plug/door_open", encode(VALID)))
        self.assertIsNone(parse_payload("other/door-sensor/door_open", encode(VALID)))
        self.assertIsNone(parse_payload("nexus/door-sensor/door_open/extra", encode(VALID)))


class GatewayRecordTests(unittest.TestCase):
    def test_fields(self) -> None:
        record = gateway_record(TOPIC, encode(VALID), 1700000003.25, 5)
        self.assertEqual(
            record,
            {
                "timestamp": 1700000003.25,
                "event": "door_open",
                "event_id": "door-sensor-00002",
                "sequence": 5,
                "peer": "door-sensor",
                "topic": TOPIC,
                "device_timestamp": 1700000003.1,
            },
        )

    def test_sequence_is_gateway_counter_not_device_sequence(self) -> None:
        record = gateway_record(TOPIC, encode(VALID), 1.0, 1)
        self.assertEqual(record["sequence"], 1)

    def test_invalid_returns_none(self) -> None:
        self.assertIsNone(gateway_record(TOPIC, b"garbage", 1.0, 1))
        self.assertIsNone(gateway_record("nexus/x/y", encode(VALID), 1.0, 1))


if __name__ == "__main__":
    unittest.main()
