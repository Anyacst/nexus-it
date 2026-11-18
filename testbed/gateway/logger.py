"""Gateway logger: records every valid device message seen on the broker.

Subscribes to nexus/# (QoS 1) as client ``nexus-gateway`` and appends one
JSON line per valid message to /logs/gateway.jsonl (flush + fsync). Runs
until SIGTERM, survives broker restarts, then exits 0.
"""

from __future__ import annotations

import json
import os
import signal
import sys
import threading
import time

import paho.mqtt.client as mqtt

try:
    from .gatewaycore import gateway_record
except ImportError:
    from gatewaycore import gateway_record

CLIENT_ID = "nexus-gateway"
TOPIC_FILTER = "nexus/#"
QOS = 1
KEEPALIVE_S = 10


def log(message: str) -> None:
    """Write a diagnostic line to stderr (shown by ``docker logs``)."""
    print(f"[gateway] {message}", file=sys.stderr, flush=True)


def main() -> int:
    broker_host = os.environ.get("BROKER_HOST", "broker")
    broker_port = int(os.environ.get("BROKER_PORT", "1883"))
    log_dir = os.environ.get("LOG_DIR", "/logs")
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, "gateway.jsonl")

    stop = threading.Event()

    def on_sigterm(signum: int, frame: object) -> None:
        log("SIGTERM received; stopping")
        stop.set()

    signal.signal(signal.SIGTERM, on_sigterm)
    signal.signal(signal.SIGINT, on_sigterm)

    out = open(log_path, "a", encoding="utf-8")
    state = {"counter": 1}

    def on_connect(client, userdata, flags, reason_code, properties) -> None:
        log(f"connected to {broker_host}:{broker_port} ({reason_code})")
        if not reason_code.is_failure:
            # Subscribing here re-subscribes after every reconnect.
            client.subscribe(TOPIC_FILTER, qos=QOS)

    def on_disconnect(client, userdata, flags, reason_code, properties) -> None:
        log(f"disconnected ({reason_code})")

    def on_message(client, userdata, message: mqtt.MQTTMessage) -> None:
        arrival = time.time()
        record = gateway_record(message.topic, message.payload, arrival, state["counter"])
        if record is None:
            log(f"ignored invalid payload on {message.topic!r}")
            return
        out.write(json.dumps(record) + "\n")
        out.flush()
        os.fsync(out.fileno())
        state["counter"] += 1

    client = mqtt.Client(
        mqtt.CallbackAPIVersion.VERSION2,
        client_id=CLIENT_ID,
        protocol=mqtt.MQTTv311,
        clean_session=True,
    )
    client.reconnect_delay_set(min_delay=1, max_delay=5)
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_message = on_message

    # connect_async + loop_start: the network thread retries the first
    # connection and reconnects automatically after any later loss.
    client.connect_async(broker_host, broker_port, keepalive=KEEPALIVE_S)
    client.loop_start()

    # Short waits keep the main thread responsive to signals.
    while not stop.wait(1.0):
        pass

    client.disconnect()
    client.loop_stop()
    out.close()
    log("stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
