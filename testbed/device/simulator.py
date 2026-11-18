"""Simulated IoT device: follows its schedule, logs locally, publishes over MQTT.

Runtime behaviour (see testbed/CONTRACT.md):
- every scheduled event is ALWAYS appended to /logs/<DEVICE_ID>.jsonl;
- it is published to nexus/<DEVICE_ID>/<event> only while connected
  (QoS 1, no offline queueing, no late redelivery);
- a ground-truth line goes to /truth/<DEVICE_ID>.truth.jsonl;
- SIGTERM or the end of the schedule ends the process cleanly with exit 0.
"""

from __future__ import annotations

import json
import os
import signal
import sys
import threading
import time
from typing import IO

import paho.mqtt.client as mqtt

try:
    from .devicecore import device_record, device_time, schedule, truth_record
except ImportError:
    from devicecore import device_record, device_time, schedule, truth_record

CONNECT_TIMEOUT_S = 30.0
PUBLISH_TIMEOUT_S = 1.5
KEEPALIVE_S = 4
QOS = 1


def env_float(name: str, default: float) -> float:
    """Read a float environment variable, falling back to ``default`` when empty."""
    raw = os.environ.get(name, "").strip()
    return float(raw) if raw else default


def log(message: str) -> None:
    """Write a diagnostic line to stderr (shown by ``docker logs``)."""
    print(f"[{os.environ.get('DEVICE_ID', 'device')}] {message}", file=sys.stderr, flush=True)


def append_jsonl(handle: IO[str], record: dict) -> None:
    """Append one JSON line and force it to disk."""
    handle.write(json.dumps(record) + "\n")
    handle.flush()
    os.fsync(handle.fileno())


def discard_unacked(client: mqtt.Client, mid: int) -> None:
    """Forget a QoS 1 message that was not acknowledged in time.

    paho keeps un-acked QoS 1 messages and resends them after a reconnect.
    The testbed must not deliver an event late, so a message that timed out
    is dropped here. paho has no public API for this, hence the guarded use
    of its internal queue.
    """
    lock = getattr(client, "_out_message_mutex", None)
    messages = getattr(client, "_out_messages", None)
    if lock is None or messages is None:
        return
    with lock:
        if messages.pop(mid, None) is not None and getattr(client, "_inflight_messages", 0) > 0:
            client._inflight_messages -= 1


def publish(client: mqtt.Client, topic: str, record: dict) -> bool:
    """Publish ``record`` if connected and wait for the PUBACK; return success."""
    if not client.is_connected():
        return False
    info = client.publish(topic, json.dumps(record), qos=QOS)
    try:
        info.wait_for_publish(timeout=PUBLISH_TIMEOUT_S)
    except (ValueError, RuntimeError) as exc:
        log(f"publish {record['event_id']} failed: {exc}")
        return False
    if info.is_published():
        return True
    log(f"publish {record['event_id']} not acknowledged within {PUBLISH_TIMEOUT_S} s; dropped")
    discard_unacked(client, info.mid)
    return False


def main() -> int:
    device_id = os.environ["DEVICE_ID"]
    broker_host = os.environ.get("BROKER_HOST", "broker")
    broker_port = int(os.environ.get("BROKER_PORT", "1883"))
    duration_s = env_float("DURATION_S", 40.0)
    seed = int(os.environ.get("SEED", "7") or "7")
    start_at = env_float("START_AT", 0.0)
    offset_s = env_float("CLOCK_OFFSET_S", 0.0)
    drift_ppm = env_float("CLOCK_DRIFT_PPM", 0.0)
    step_at_s = env_float("CLOCK_STEP_AT_S", -1.0)
    step_s = env_float("CLOCK_STEP_S", 0.0)
    log_dir = os.environ.get("LOG_DIR", "/logs")
    truth_dir = os.environ.get("TRUTH_DIR", "/truth")

    entries = schedule(device_id, duration_s, seed)

    stop = threading.Event()

    def on_sigterm(signum: int, frame: object) -> None:
        log("SIGTERM received; stopping")
        stop.set()

    signal.signal(signal.SIGTERM, on_sigterm)
    signal.signal(signal.SIGINT, on_sigterm)

    client = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2,
        client_id=device_id,
        protocol=mqtt.MQTTv311,
        clean_session=True,
    )
    client.max_queued_messages_set(1)
    client.reconnect_delay_set(min_delay=1, max_delay=2)

    def on_connect(client, userdata, flags, reason_code, properties) -> None:
        log(f"connected to {broker_host}:{broker_port} ({reason_code})")

    def on_disconnect(client, userdata, flags, reason_code, properties) -> None:
        log(f"disconnected ({reason_code})")

    client.on_connect = on_connect
    client.on_disconnect = on_disconnect

    # connect_async + loop_start: the network thread keeps retrying the first
    # connection and reconnects automatically after a loss.
    client.connect_async(broker_host, broker_port, keepalive=KEEPALIVE_S)
    client.loop_start()
    deadline = time.monotonic() + CONNECT_TIMEOUT_S
    while not client.is_connected() and time.monotonic() < deadline and not stop.is_set():
        stop.wait(0.2)
    if not client.is_connected():
        log(f"no broker connection after {CONNECT_TIMEOUT_S:.0f} s; continuing offline")

    start = start_at if start_at > 0 else time.time() + 2.0
    log(f"schedule start={start:.3f} events={len(entries)} duration={duration_s}")

    os.makedirs(log_dir, exist_ok=True)
    os.makedirs(truth_dir, exist_ok=True)
    log_path = os.path.join(log_dir, f"{device_id}.jsonl")
    truth_path = os.path.join(truth_dir, f"{device_id}.truth.jsonl")

    with open(log_path, "a", encoding="utf-8") as log_file, open(truth_path, "a", encoding="utf-8") as truth_file:
        for sequence, entry in enumerate(entries, start=1):
            delay = start + entry["offset_s"] - time.time()
            if delay > 0 and stop.wait(delay):
                break
            if stop.is_set():
                break

            true_time = time.time()
            ts = device_time(true_time, start, offset_s, drift_ppm, step_at_s, step_s)
            record = device_record(device_id, sequence, entry["event"], ts, entry["value"])
            append_jsonl(log_file, record)

            published = publish(client, f"nexus/{device_id}/{entry['event']}", record)
            append_jsonl(truth_file, truth_record(device_id, sequence, entry["event"], true_time, ts, published))

    if client.is_connected():
        client.disconnect()
    client.loop_stop()
    log("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
