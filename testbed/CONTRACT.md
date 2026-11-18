# NEXUS-IoT Docker testbed — interface contract

This file fixes every name, path, field and format shared between the testbed parts.
All parts MUST follow it exactly. Change it only by agreement.

## Scope and safety

- Benign simulation only: devices publish normal telemetry; the testbed generates forensic
  evidence (logs, captures) with known ground truth. No attack traffic, no credential
  guessing, no exploitation tooling.
- Nothing is exposed to the host network: no `ports:` mappings in compose.

## Layout

```text
testbed/
  __init__.py                 empty
  CONTRACT.md                 this file
  README.md                   how to run (written last)
  docker-compose.yml          [container side]
  mosquitto/mosquitto.conf    [container side]
  device/                     [container side]
    __init__.py               empty
    devicecore.py             pure stdlib: clock model, schedule, record builders (unit-tested)
    simulator.py              entry point; imports devicecore + paho-mqtt
    requirements.txt          paho-mqtt==2.1.0
    Dockerfile                FROM python:3.12-slim
  gateway/                    [container side]
    __init__.py               empty
    gatewaycore.py            pure stdlib: payload validation + gateway record builder (unit-tested)
    logger.py                 entry point; imports gatewaycore + paho-mqtt
    requirements.txt          paho-mqtt==2.1.0
    Dockerfile                FROM python:3.12-slim
  capture/
    Dockerfile                FROM alpine:3.20 + tcpdump  [container side]
  runner/                     [host side, stdlib only, Python >= 3.10]
    __init__.py
    scenarios.py              scenario definitions S1..S7 (reference table) + device topology mirror
    variation.py              seeded scenario parameters: build_scenario(id, seed, duration)
    truth.py                  ground-truth builder
    tamper.py                 post-collection tampering of evidence COPIES
    collect.py                copy run outputs into a case folder; write devices.json
    run_scenario.py           CLI: python -m testbed.runner.run_scenario ...
    benchmark.py              CLI: python -m testbed.runner.benchmark ... (scenarios x seeds -> metrics)
  results/<benchmark_id>/     metrics.json + metrics.md written by runner/benchmark.py
  tests/
    __init__.py
    test_devicecore.py, test_gatewaycore.py          [container side]
    test_truth.py, test_tamper.py, test_scenarios.py, test_collect.py   [runner side]
    test_variation.py, test_benchmark.py                                [runner side]
    test_integration_docker.py                       [main thread; skipped without Docker]
```

Imports: in-container scripts do `try: from .devicecore import X` / `except ImportError: from devicecore import X`
so tests can import `testbed.device.devicecore`. The `*core.py` modules must not import paho.
Tests run from the repo root with: `python3 -m unittest discover -s testbed/tests -t . -v`

## Pinned images and packages

`python:3.12-slim`, `eclipse-mosquitto:2.0.18`, `alpine:3.20`, `paho-mqtt==2.1.0`.

## Network and services (docker-compose.yml)

- Compose project name: `nexus-tb` (set top-level `name: nexus-tb`).
- One bridge network, explicit name `nexus-iotnet`, subnet `172.30.0.0/24`.
- Every service sets `container_name` as below and a fixed `ipv4_address`.

| Service / container_name | IP | Role |
| --- | --- | --- |
| `nexus-tb-broker` | 172.30.0.10 | Mosquitto, listener 1883, `allow_anonymous true` (closed network) |
| `nexus-tb-gateway` | 172.30.0.11 | gateway logger |
| `nexus-tb-capture` | (shares broker netns: `network_mode: "service:broker"`) | tcpdump |
| `nexus-tb-door-sensor` | 172.30.0.21 | device `door-sensor` |
| `nexus-tb-temp-sensor` | 172.30.0.22 | device `temp-sensor` |
| `nexus-tb-smart-plug` | 172.30.0.23 | device `smart-plug` |
| `nexus-tb-motion-sensor` | 172.30.0.24 | device `motion-sensor` |
| `nexus-tb-smart-lock` | 172.30.0.25 | device `smart-lock` |

Bind mounts (host paths come from env `RUN_DIR`, an absolute path created by the runner):

- `${RUN_DIR}/logs` -> `/logs` (devices + gateway write here)
- `${RUN_DIR}/truth` -> `/truth` (devices write ground truth here; never given to the analyzer)
- `${RUN_DIR}/capture` -> `/capture` (tcpdump)
- `${RUN_DIR}/broker` -> `/mosquitto/log` (broker log file `mosquitto.log`)

Capture command: `sh -c 'exec tcpdump -i eth0 -U -n -w /capture/gateway-$(date +%s%N).pcap tcp port 1883'`
with `cap_add: [NET_ADMIN, NET_RAW]`. Each (re)start writes a NEW file, so a stop/start leaves a gap.

Mosquitto config: `listener 1883`, `allow_anonymous true`, `persistence false`,
`log_dest file /mosquitto/log/mosquitto.log`, `log_type all`, `log_timestamp true`,
`log_timestamp_format %Y-%m-%dT%H:%M:%S`, `connection_messages true`.

Startup order: broker healthy (healthcheck with `mosquitto_sub -t '$$SYS/#' -C 1 -W 3`), then gateway,
capture; devices `depends_on` gateway started. Devices and gateway use `restart: "no"`.

## Device environment variables (compose interpolation with defaults)

Each device service gets, with `<P>` = `DOOR`, `TEMP`, `PLUG`, `MOTION`, `LOCK`:

| Var in container | Compose value | Meaning |
| --- | --- | --- |
| `DEVICE_ID` | literal `door-sensor` / `temp-sensor` / `smart-plug` / `motion-sensor` / `smart-lock` | name used everywhere |
| `BROKER_HOST` / `BROKER_PORT` | `broker` / `1883` | |
| `DURATION_S` | `${DURATION_S:-40}` | seconds of event generation after start |
| `SEED` | `${SEED:-7}` | RNG seed for jitter/values |
| `START_AT` | `${START_AT:-0}` | Unix time to begin schedule; 0 = now + 2 s |
| `CLOCK_OFFSET_S` | `${<P>_CLOCK_OFFSET_S:-0}` | constant device clock offset |
| `CLOCK_DRIFT_PPM` | `${<P>_CLOCK_DRIFT_PPM:-0}` | linear drift |
| `CLOCK_STEP_AT_S` | `${<P>_CLOCK_STEP_AT_S:--1}` | elapsed seconds when a step happens; <0 = never |
| `CLOCK_STEP_S` | `${<P>_CLOCK_STEP_S:-0}` | size of the step |

Per-device behaviour (fixed in devicecore, keyed by DEVICE_ID):

| DEVICE_ID | interval_s | events cycled in order (after a first `boot`) |
| --- | --- | --- |
| `door-sensor` | 3.0 | `door_open`, `door_close` |
| `temp-sensor` | 2.0 | `temperature_reading` (value = float °C, seeded) |
| `smart-plug` | 4.0 | `plug_on`, `plug_off` |
| `motion-sensor` | 5.0 | `motion_detected`, `motion_cleared` |
| `smart-lock` | 6.0 | `lock_engaged`, `lock_released` |

Jitter: each scheduled offset gets uniform ±0.2 s from `random.Random(f"{SEED}:{DEVICE_ID}")`.
The first event (`boot`) is at offset 0.0. Schedule covers offsets `< DURATION_S`.

## devicecore API (pure, deterministic)

```python
DEVICE_PROFILES: dict[str, dict]   # {"door-sensor": {"interval_s": 3.0, "events": ["door_open","door_close"]}, ...}

def device_time(true_time: float, start: float, offset_s: float = 0.0, drift_ppm: float = 0.0,
                step_at_s: float = -1.0, step_s: float = 0.0) -> float:
    """true_time + offset_s + drift_ppm*1e-6*(true_time-start) + (step_s if step_at_s>=0 and true_time-start>=step_at_s else 0)"""

def schedule(device_id: str, duration_s: float, seed: int) -> list[dict]:
    """[{"offset_s": float, "event": str, "value": float|None}], sorted by offset, first is boot at 0.0.
    Raises ValueError for an unknown device_id."""

def event_id(device_id: str, sequence: int) -> str:   # f"{device_id}-{sequence:05d}"

def device_record(device_id, sequence, event, device_ts, value=None) -> dict:
    """Device log line AND MQTT payload:
    {"event_id", "sequence", "device", "event", "timestamp": device_ts, ["value": value if not None]}"""

def truth_record(device_id, sequence, event, true_time, device_ts, published: bool) -> dict:
    """{"event_id", "sequence", "device", "event", "true_time", "device_time", "published"}"""
```

Sequence numbers start at 1 per device and increase by 1 for every scheduled event.

## Device runtime behaviour (simulator.py)

- Connect to broker (retry up to 30 s), `loop_start()`, MQTT client id = DEVICE_ID, protocol v3.1.1, QoS 1.
- For each scheduled event: sleep until `start + offset_s`; `true = time.time()`;
  `ts = device_time(true, start, ...)`; build record; append it as one JSON line to
  `/logs/<DEVICE_ID>.jsonl` (flush + fsync) — ALWAYS, even when offline.
- Publish to topic `nexus/<DEVICE_ID>/<event>` with the record as JSON payload ONLY if
  `client.is_connected()`; wait `wait_for_publish(timeout=1.5)`; `published` = success.
  Never queue offline messages for later delivery (set `max_queued_messages_set(1)` and skip when disconnected).
- Append `truth_record(...)` to `/truth/<DEVICE_ID>.truth.jsonl`.
- After the schedule: disconnect cleanly, exit 0. Handle SIGTERM by exiting cleanly.

## Gateway logger (logger.py + gatewaycore.py)

- Subscribe `nexus/#` QoS 1, client id `nexus-gateway`.
- On each message: `arrival = time.time()`; parse payload; `gatewaycore.gateway_record(topic, payload_bytes, arrival, counter)`;
  if it returns a record, append to `/logs/gateway.jsonl` (flush + fsync) and increment counter (starts at 1).
- Runs until SIGTERM, then exits 0.

```python
def parse_payload(topic: str, payload: bytes) -> dict | None:
    """Valid only if JSON object with str event_id, int sequence, str device, str event, numeric timestamp,
    and topic == f"nexus/{device}/{event}". Otherwise None."""

def gateway_record(topic: str, payload: bytes, arrival: float, counter: int) -> dict | None:
    """{"timestamp": arrival, "event": p["event"], "event_id": p["event_id"], "sequence": counter,
        "peer": p["device"], "topic": topic, "device_timestamp": p["timestamp"]}  or None if invalid"""
```

## Case folder (runner/collect.py)

```text
<cases_root>/<run_id>/<scenario_id>/
  evidence/            what the analyzer gets
    door-sensor.jsonl temp-sensor.jsonl smart-plug.jsonl motion-sensor.jsonl smart-lock.jsonl gateway.jsonl
    gateway-*.pcap     (all capture files)
    devices.json
  ground_truth/truth.json
  original/            byte-identical copies of evidence BEFORE any tampering (+ SHA-256 list original/SHA256SUMS)
  extra/mosquitto.log, extra/run.json (scenario id, params, "parameters" (seeded fault parameters),
                                       start/end times, docker actions performed)
```

devices.json:

```json
{"device_ips": {"door-sensor": ["172.30.0.21"], "temp-sensor": ["172.30.0.22"], "smart-plug": ["172.30.0.23"],
                "motion-sensor": ["172.30.0.24"], "smart-lock": ["172.30.0.25"]},
 "correlation_rules": [ one rule per (device, event) in DEVICE_PROFILES incl. boot:
   {"id": "<device>-<event>-mqtt", "device": "<device>", "event": "<event>", "protocol": "tcp",
    "direction": "outbound", "destination_port": 1883, "window_seconds": 2.0} ]}
```

## truth.json (must match nexus_iot/evaluate.py expectations)

```json
{"condition": "<scenario title>",
 "events": [{"event_id", "timestamp": <true_time>, "device", "event",
             "expected_sources": ["<device>.jsonl"] + (["gateway.jsonl"] if the event_id is in the PRE-TAMPER gateway log),
             "source_sequences": {"<device>.jsonl": <device sequence>, "gateway.jsonl": <gateway sequence if present>}}],
 "tampering_seeded": bool, "tamper_mechanisms": ["delete"|"edit"|"insert", ...],
 "clock_manipulated": bool,
 "expected_record_count": <sum of len(expected_sources)>,
 "parameters": {...}}   OPTIONAL: concrete seeded fault parameters (see "Seeded variation"); evaluate ignores it
```

Events sorted by timestamp. Truth comes from `/truth/*.truth.jsonl` + the pre-tamper `gateway.jsonl` only.

## Scenarios (runner/scenarios.py)

`Scenario` dataclass: `id`, `title`, `env: dict[str,str]` (extra compose env), `actions: list[Action]`,
`tamper: list[TamperOp]`, `clock_manipulated: bool`, `parameters: dict` (default `{}`; set by seeded builds).
`Action(at_s: float, kind: "disconnect"|"reconnect"|"stop_capture"|"start_capture", target: container_name|None)`.
`TamperOp(kind: "delete"|"edit"|"insert", file: "<device>.jsonl", index: int, new_event: str|None)` — `index` = 0-based record line in that file.

`SCENARIOS` is the fixed REFERENCE table below (nominal values, used when no seed is given).
The runner CLIs build seeded variants instead (next section).

| id | title | env / actions / tamper (reference values) |
| --- | --- | --- |
| S1 | Normal operation | none |
| S2 | Device disconnection | disconnect `nexus-tb-temp-sensor` at 12 s, reconnect at 22 s |
| S3 | Clock step | `DOOR_CLOCK_OFFSET_S=5`, `DOOR_CLOCK_STEP_AT_S=20`, `DOOR_CLOCK_STEP_S=90`; clock_manipulated |
| S4 | Clock drift | `PLUG_CLOCK_DRIFT_PPM=5000`; clock_manipulated |
| S5 | Capture gap | stop_capture at 12 s, start_capture at 22 s |
| S6 | Post-collection tampering | delete smart-plug.jsonl index 3; edit door-sensor.jsonl index 4 -> `door_close_forced`; insert door-sensor.jsonl index 6 (a fabricated `door_open` copying index 5's sequence) |
| S7 | Combined | S2 actions + S3 env + S6 tamper; clock_manipulated |

## Seeded variation (runner/variation.py)

`build_scenario(scenario_id, seed, duration_s) -> Scenario` derives the fault parameters with
`random.Random(f"{seed}:{scenario_id}")` (deterministic per seed and scenario). `get_scenarios(ids, seed=, duration=)`
returns seeded scenarios; without `seed` it returns the reference table. Requires `duration_s >= 30`.
Times are rounded to 0.1 s. `J` = schedule jitter 0.2 s, `I` = target device interval.

| Fault (scenarios) | Parameters and bounds |
| --- | --- |
| disconnect (S2, S7) | any device; length in `[max(6, 2*I), max(6, 2*I) + 10]` s (so >= 1 event is offline); start >= 6 s; reconnect <= duration - 6 s |
| clock step (S3, S7) | device with `6*I + 1.4 <= duration`; offset in `[-10, 10]` s; size `+/-[5, 120]` s (sign random); step time in `[3*I + 0.7, duration - 3*I - 0.7]` so >= 3 non-boot events (clock anchors) lie on each side |
| clock drift (S4) | any device; `+/-[2000, 20000]` ppm (integer, sign random) |
| capture gap (S5) | length in `[5, 15]` s; start >= 6 s; restart <= duration - 6 s |
| tamper (S6, S7) | two different devices A, B; delete A index in `[1, n_A-1]`; edit B index `e` in `[1, n_B-1]` (new event = next event in B's cycle, or `<event>_forced` for one-event devices); insert B index `i` in `[2, n_B-1]`, `i` not in `{e, e+1}`, new event = event of line `i-1`. `n` = guaranteed line count `1 + #{k >= 1: k*I + J < duration}` |

S7 = disconnect + clock step + tamper with disconnect device != clock-step device. `parameters` holds
`seed`, `duration_s` and, per fault present, `disconnect {device, container, start_s, end_s}`,
`clock_step {device, offset_s, step_at_s, step_s}`, `clock_drift {device, drift_ppm}`,
`capture_gap {start_s, end_s}`, `tamper [{kind, file, index, new_event}]`.
Env keys use the device prefix, e.g. `MOTION_CLOCK_STEP_S`.

Action timing is relative to the schedule start (`START_AT`). Docker commands used by the runner:
`docker network disconnect nexus-iotnet <c>`, `docker network connect --ip <ip> nexus-iotnet <c>`,
`docker stop nexus-tb-capture`, `docker start nexus-tb-capture`.

Tamper semantics (on `evidence/` only, after `original/` is written): delete removes the line;
edit replaces the `event` field only; insert puts a new JSON line BEFORE line `index`, copying line `index-1`
with `event_id` = `<device>-fab01` and its same `sequence` (duplicate sequence), timestamp = previous + 0.5.

## Runner CLI

```text
python -m testbed.runner.run_scenario S1 [S2 ...|all] [--duration 40] [--seed 7] [--cases-root testbed/cases]
                                           [--analyze] [--no-build] [--keep-run]
```

`--seed` sets both the device RNG seed (`SEED`) and the seeded scenario parameters.

Flow per scenario: make `RUN_DIR` under `testbed/runs/<run_id>/<sid>` (subdirs logs, truth, capture, broker);
`docker compose -f testbed/docker-compose.yml up -d --build` with env (RUN_DIR, START_AT=now+8, DURATION_S, SEED, scenario env);
perform actions at their times; `docker wait` each device container (timeout duration+60 s);
wait 2 s, then `docker stop -t 10 nexus-tb-capture` (SIGTERM so tcpdump flushes the final packets; run.json `capture_stopped_at`);
`docker compose ... down -t 5` (stops gateway/capture cleanly); collect -> case folder; build truth; tamper;
optionally `--analyze`: run `nexus_iot.evaluate.score_case` and print a one-line summary.
Always `down` in a `finally`. `testbed/runs/` and `testbed/cases/` are git-ignored.

## Benchmark CLI (runner/benchmark.py)

```text
python -m testbed.runner.benchmark --seeds 1 2 3 [--scenarios all|S1 ...] [--duration 60]
                                   [--out testbed/results] [--cases-root testbed/cases] [--no-build]
```

Builds images once (unless `--no-build`), then for each seed and each scenario: `build_scenario`,
`execute_scenario` (cases under `<cases-root>/<benchmark_id>/seed-<n>/<sid>`), and
`nexus_iot.evaluate.score_case` (output in the case's `derived/`). A failed run is recorded with
`status: "failed"` and does not stop the benchmark. Writes `<out>/<benchmark_id>/metrics.json` and
`metrics.md` (rewritten after every run). `benchmark_id` = `bench-YYYYmmdd-HHMMSS`. Exit code 1 if any run failed.

Aggregates (successful runs only; failed runs counted): per scenario mean, sample std (n-1; null for n < 2)
and min of event F1, precision, recall, time-within-1s, completeness, unknown-gap precision/recall.
Alert detection over all successful runs: tamper (positive = truth `tampering_seeded`, alert = `tamper_alert`)
and clock (positive = truth `clock_manipulated`, alert = `clock_anomaly_alert`): recall, false-positive rate,
precision; null when the denominator is 0.
