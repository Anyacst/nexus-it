"""Unit tests for testbed.device.devicecore (stdlib only, no broker needed)."""

import unittest

from testbed.device.devicecore import (
    DEVICE_PROFILES,
    device_record,
    device_time,
    event_id,
    schedule,
    truth_record,
)


class DeviceTimeTests(unittest.TestCase):
    START = 1_700_000_000.0

    def test_no_manipulation_returns_true_time(self) -> None:
        self.assertEqual(device_time(self.START + 10, self.START), self.START + 10)

    def test_constant_offset(self) -> None:
        self.assertAlmostEqual(device_time(self.START + 10, self.START, offset_s=5.0), self.START + 15)
        self.assertAlmostEqual(device_time(self.START + 10, self.START, offset_s=-3.0), self.START + 7)

    def test_linear_drift(self) -> None:
        # 5000 ppm over 100 s elapsed = 0.5 s ahead.
        result = device_time(self.START + 100, self.START, drift_ppm=5000.0)
        self.assertAlmostEqual(result, self.START + 100.5, places=6)
        # No drift at the start instant.
        self.assertEqual(device_time(self.START, self.START, drift_ppm=5000.0), self.START)

    def test_step_before_boundary(self) -> None:
        result = device_time(self.START + 19.999, self.START, step_at_s=20.0, step_s=90.0)
        self.assertAlmostEqual(result, self.START + 19.999)

    def test_step_at_and_after_boundary(self) -> None:
        at = device_time(self.START + 20.0, self.START, step_at_s=20.0, step_s=90.0)
        after = device_time(self.START + 25.0, self.START, step_at_s=20.0, step_s=90.0)
        self.assertAlmostEqual(at, self.START + 110.0)
        self.assertAlmostEqual(after, self.START + 115.0)

    def test_no_step_when_step_at_negative(self) -> None:
        result = device_time(self.START + 1000.0, self.START, step_at_s=-1.0, step_s=90.0)
        self.assertAlmostEqual(result, self.START + 1000.0)

    def test_offset_and_step_combine(self) -> None:
        result = device_time(self.START + 30.0, self.START, offset_s=5.0, step_at_s=20.0, step_s=90.0)
        self.assertAlmostEqual(result, self.START + 125.0)


class ScheduleTests(unittest.TestCase):
    def test_deterministic_for_same_seed(self) -> None:
        for device in DEVICE_PROFILES:
            self.assertEqual(schedule(device, 40, 7), schedule(device, 40, 7))

    def test_differs_for_different_seed(self) -> None:
        for device in DEVICE_PROFILES:
            self.assertNotEqual(schedule(device, 40, 7), schedule(device, 40, 8))

    def test_boot_first_at_zero(self) -> None:
        for device in DEVICE_PROFILES:
            first = schedule(device, 40, 7)[0]
            self.assertEqual(first["event"], "boot")
            self.assertEqual(first["offset_s"], 0.0)
            self.assertIsNone(first["value"])

    def test_offsets_below_duration_and_sorted(self) -> None:
        for device in DEVICE_PROFILES:
            for duration in (5, 10, 40, 41.9):
                entries = schedule(device, duration, 7)
                offsets = [entry["offset_s"] for entry in entries]
                self.assertTrue(all(offset < duration for offset in offsets), (device, duration))
                self.assertEqual(offsets, sorted(offsets))

    def test_jitter_within_bounds(self) -> None:
        for device, profile in DEVICE_PROFILES.items():
            entries = schedule(device, 40, 7)
            for k, entry in enumerate(entries[1:], start=1):
                nominal = k * profile["interval_s"]
                self.assertLessEqual(abs(entry["offset_s"] - nominal), 0.2 + 1e-9)

    def test_event_count_matches_interval(self) -> None:
        # 40 s at 3.0 s interval: nominal offsets 3..39 -> 13 events + boot.
        self.assertEqual(len(schedule("door-sensor", 40, 7)), 14)
        # 39 s at 4.0 s interval: nominal offsets 4..36 -> 9 events + boot.
        self.assertEqual(len(schedule("smart-plug", 39, 7)), 10)
        # 39 s at 5.0 s interval: nominal offsets 5..35 -> 7 events + boot.
        self.assertEqual(len(schedule("motion-sensor", 39, 7)), 8)
        # 40 s at 6.0 s interval: nominal offsets 6..36 -> 6 events + boot.
        self.assertEqual(len(schedule("smart-lock", 40, 7)), 7)

    def test_events_cycle_per_profile(self) -> None:
        for device, profile in DEVICE_PROFILES.items():
            events = [entry["event"] for entry in schedule(device, 40, 7)[1:]]
            expected = [profile["events"][i % len(profile["events"])] for i in range(len(events))]
            self.assertEqual(events, expected)

    def test_door_and_plug_cycles(self) -> None:
        door = [entry["event"] for entry in schedule("door-sensor", 13, 7)]
        self.assertEqual(door, ["boot", "door_open", "door_close", "door_open", "door_close"])
        plug = [entry["event"] for entry in schedule("smart-plug", 13, 7)]
        self.assertEqual(plug, ["boot", "plug_on", "plug_off", "plug_on"])

    def test_motion_and_lock_cycles(self) -> None:
        motion = [entry["event"] for entry in schedule("motion-sensor", 21, 7)]
        self.assertEqual(motion, ["boot", "motion_detected", "motion_cleared", "motion_detected", "motion_cleared"])
        lock = [entry["event"] for entry in schedule("smart-lock", 19, 7)]
        self.assertEqual(lock, ["boot", "lock_engaged", "lock_released", "lock_engaged"])

    def test_five_device_profiles(self) -> None:
        self.assertEqual(
            {device: profile["interval_s"] for device, profile in DEVICE_PROFILES.items()},
            {"door-sensor": 3.0, "temp-sensor": 2.0, "smart-plug": 4.0, "motion-sensor": 5.0, "smart-lock": 6.0},
        )

    def test_host_mirror_matches_profiles(self) -> None:
        # The host runner keeps its own copy of the profiles; it must not drift from devicecore.
        from testbed.runner.scenarios import DEVICE_EVENTS, DEVICE_INTERVALS
        from testbed.runner.variation import JITTER_S

        self.assertEqual(DEVICE_EVENTS, {d: p["events"] for d, p in DEVICE_PROFILES.items()})
        self.assertEqual(DEVICE_INTERVALS, {d: p["interval_s"] for d, p in DEVICE_PROFILES.items()})
        from testbed.device import devicecore

        self.assertEqual(JITTER_S, devicecore.JITTER_S)

    def test_temperature_values_present(self) -> None:
        entries = schedule("temp-sensor", 40, 7)[1:]
        self.assertTrue(entries)
        for entry in entries:
            self.assertEqual(entry["event"], "temperature_reading")
            self.assertIsInstance(entry["value"], float)
            self.assertTrue(15.0 < entry["value"] < 30.0)

    def test_non_temperature_values_are_none(self) -> None:
        for device in ("door-sensor", "smart-plug", "motion-sensor", "smart-lock"):
            self.assertTrue(all(entry["value"] is None for entry in schedule(device, 40, 7)))

    def test_unknown_device_raises(self) -> None:
        with self.assertRaises(ValueError):
            schedule("toaster", 40, 7)


class RecordTests(unittest.TestCase):
    def test_event_id_format(self) -> None:
        self.assertEqual(event_id("door-sensor", 1), "door-sensor-00001")
        self.assertEqual(event_id("smart-plug", 12345), "smart-plug-12345")

    def test_device_record_without_value(self) -> None:
        record = device_record("door-sensor", 3, "door_open", 1234.5)
        self.assertEqual(
            record,
            {
                "event_id": "door-sensor-00003",
                "sequence": 3,
                "device": "door-sensor",
                "event": "door_open",
                "timestamp": 1234.5,
            },
        )
        self.assertNotIn("value", record)

    def test_device_record_with_value(self) -> None:
        record = device_record("temp-sensor", 2, "temperature_reading", 99.0, value=21.37)
        self.assertEqual(record["value"], 21.37)
        self.assertEqual(record["event_id"], "temp-sensor-00002")
        self.assertEqual(record["timestamp"], 99.0)

    def test_truth_record_fields(self) -> None:
        record = truth_record("smart-plug", 4, "plug_off", 1000.0, 1005.0, True)
        self.assertEqual(
            record,
            {
                "event_id": "smart-plug-00004",
                "sequence": 4,
                "device": "smart-plug",
                "event": "plug_off",
                "true_time": 1000.0,
                "device_time": 1005.0,
                "published": True,
            },
        )


if __name__ == "__main__":
    unittest.main()
