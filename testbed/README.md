# NEXUS-IoT Docker testbed

A closed Docker network of simulated IoT devices that produces realistic forensic evidence
(device logs, gateway log, packet capture) together with separately stored ground truth.
It replaces physical hardware for evaluating NEXUS-IoT. Interfaces are fixed in
[CONTRACT.md](CONTRACT.md).

## What runs

| Container | Role |
| --- | --- |
| `nexus-tb-broker` | Eclipse Mosquitto 2.0.18 MQTT broker (172.30.0.10) |
| `nexus-tb-gateway` | Subscribes to `nexus/#`, writes `gateway.jsonl` stamped with the gateway clock |
| `nexus-tb-capture` | tcpdump on the broker's network, writes `gateway-*.pcap` |
| `nexus-tb-door-sensor` | `door_open` / `door_close` every 3 s |
| `nexus-tb-temp-sensor` | `temperature_reading` every 2 s |
| `nexus-tb-smart-plug` | `plug_on` / `plug_off` every 4 s |
| `nexus-tb-motion-sensor` | `motion_detected` / `motion_cleared` every 5 s (172.30.0.24) |
| `nexus-tb-smart-lock` | `lock_engaged` / `lock_released` every 6 s (172.30.0.25) |

Each device writes its own JSONL log, publishes over MQTT only when connected, and records
the true event time in a truth file the analyzer never sees. Device clock faults (offset,
drift, step) are simulated in software. No ports are published to the host.

## Requirements

Docker Desktop (or Docker Engine) with Compose v2, and Python 3.10+ on the host. The host
side uses only the standard library.

## Run scenarios

From the repository root:

```bash
python3 -m testbed.runner.run_scenario S1 --analyze          # one scenario
python3 -m testbed.runner.run_scenario all --analyze         # S1..S7
python3 -m testbed.runner.run_scenario S3 --duration 60 --seed 11 --keep-run
```

`--seed` (default 7) sets the device jitter and values AND the fault parameters, so every seed
gives a different variant of each scenario. Seeded runs need `--duration` of at least 30 s.

| ID | Scenario | What happens (seeded; bounds in CONTRACT.md) |
| --- | --- | --- |
| S1 | Normal operation | All devices online, clocks in sync |
| S2 | Device disconnection | one device removed from the network for 6-22 s (covers at least one of its events) |
| S3 | Clock step | one device: offset up to ±10 s, then a ±5-120 s jump with at least 3 clock anchors on each side |
| S4 | Clock drift | one device drifts ±2,000-20,000 ppm |
| S5 | Capture gap | packet capture stopped for 5-15 s |
| S6 | Post-collection tampering | evidence copies: one line deleted in device A; one edited and one fabricated line inserted in device B |
| S7 | Combined | disconnect + clock step (different devices) + tampering |

The concrete values are stored in `extra/run.json` and `ground_truth/truth.json` (`"parameters"`).
The fixed reference values (seedless) remain in `testbed/runner/scenarios.py`.

Each run writes `testbed/cases/<run_id>/<scenario>/`:

```text
evidence/        given to NEXUS-IoT: device logs, gateway.jsonl, gateway-*.pcap, devices.json
ground_truth/    truth.json (scorer only)
original/        untouched evidence copies + SHA256SUMS (before any tampering)
extra/           mosquitto.log, run.json (parameters, docker actions, tamper log)
derived/         analyzer report and score (with --analyze)
```

Analyze a case by hand:

```bash
python3 -m nexus_iot analyze testbed/cases/<run_id>/S1/evidence --out testbed/cases/<run_id>/S1/derived
```

## Benchmark across seeds

```bash
python3 -m testbed.runner.benchmark --seeds 1 2 3 --scenarios all --duration 60   # 21 runs, ~25 min
python3 -m testbed.runner.benchmark --seeds 1 2 --scenarios S3 S6 --duration 45 --no-build
```

Each scenario x seed is run, collected (cases under `testbed/cases/<benchmark_id>/seed-<n>/`) and
scored with `nexus_iot.evaluate.score_case`. Results go to `testbed/results/<benchmark_id>/`:

- `metrics.json`: every run (parameters, scores, status), per-scenario mean / sample std / min across
  seeds, and tamper / clock alert recall, false-positive rate and precision over all runs;
- `metrics.md`: the same as readable tables, plus a limits section.

Both files are rewritten after every run. A failed run is recorded as failed (excluded from the
statistics, still counted) and the benchmark goes on; the exit code is then 1.

## Tests

```bash
python3 -m unittest discover -s testbed/tests -t . -v                         # unit tests, no Docker
NEXUS_DOCKER_TESTS=1 python3 -m unittest testbed.tests.test_integration_docker -v   # real containers, ~3 min
```

## Known limits

- All containers share the host clock; device clock faults are simulated in software.
- To stop paho-mqtt from resending a timed-out message after a reconnect, the simulator clears
  paho's internal outgoing queue. This depends on private attributes of the pinned
  `paho-mqtt==2.1.0` and is guarded, but may break on other versions.
- Telemetry is synthetic; a run is evidence of tool behaviour on this testbed, not on real hardware.
- A few seeds give a rough spread, not a confidence interval; Docker timing (disconnect detection,
  reconnect delay) adds run-to-run variance the seed does not control.
- Clock steps can be negative (clock set back). Backward timestamps may also be read as tampering,
  which the benchmark then counts as a tamper false positive.
