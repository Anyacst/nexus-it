# NEXUS-IoT Incident Reconstruction

Created: 2026-11-13T03:48:26.970778+00:00

## Evidence validation

- sensor-A.jsonl: only 2 valid clock anchor(s); offset estimate is diagnostic and was not applied

## Clock estimates

| Source | Offset (s) | Drift (ppm) | Uncertainty (s) | Anchors | Applied |
|---|---:|---:|---:|---:|---|
| sensor-A.jsonl | +5.000000 | +0.000 | unknown | 2 | False |
| sensor-B.jsonl | -2.000000 | +0.000 | ±0.050000 | 6 | True |

## Timeline

| UTC time / range | Event | Device / source | Label | Supporting evidence | Confidence / uncertainty and limitations |
|---|---|---|---|---|---|
| 2026-11-06T21:19:59.950000+00:00 to 2026-11-06T21:20:00.050000+00:00 | boot | gateway, sensor-A | **Confirmed** | gateway.jsonl record 1 (boot); sensor-A.jsonl record 1 (boot) | 2 agreeing source(s); time range ±0.050s plus source spread Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |
| 2026-11-06T21:20:01.950000+00:00 to 2026-11-06T21:20:02.050000+00:00 | auth_fail | gateway, sensor-A | **Confirmed** | gateway.jsonl record 2 (auth_fail); sensor-A.jsonl record 2 (auth_fail) | 2 agreeing source(s); time range ±0.050s plus source spread Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |
| 2026-11-06T21:20:02.950000+00:00 to 2026-11-06T21:20:03.050000+00:00 | alert | gateway, sensor-B | **Confirmed** | gateway.jsonl record 3 (alert); sensor-B.jsonl record 1 (alert) | 2 agreeing source(s); time range ±0.050s plus source spread Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |
| 2026-11-06T21:20:04.450000+00:00 to 2026-11-06T21:20:04.550000+00:00 | device_disconnected | gateway | **Single-source** | gateway.jsonl record 4 (device_disconnected) | 1 agreeing source(s); time range ±0.050s plus source spread Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |
| 2026-11-06T21:20:05.950000+00:00 to 2026-11-06T21:20:06.050000+00:00 | heartbeat | gateway, sensor-B | **Confirmed** | gateway.jsonl record 5 (heartbeat); sensor-B.jsonl record 2 (heartbeat) | 2 agreeing source(s); time range ±0.050s plus source spread Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |
| 2026-11-06T21:20:09.950000+00:00 to 2026-11-06T21:20:10.050000+00:00 | heartbeat | gateway, sensor-B | **Confirmed** | gateway.jsonl record 6 (heartbeat); sensor-B.jsonl record 3 (heartbeat) | 2 agreeing source(s); time range ±0.050s plus source spread Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |
| 2026-11-06T21:20:13.950000+00:00 to 2026-11-06T21:20:14.050000+00:00 | heartbeat | gateway, sensor-B | **Confirmed** | gateway.jsonl record 7 (heartbeat); sensor-B.jsonl record 4 (heartbeat) | 2 agreeing source(s); time range ±0.050s plus source spread Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |
| 2026-11-06T21:20:17.950000+00:00 to 2026-11-06T21:20:18.050000+00:00 | heartbeat | gateway, sensor-B | **Confirmed** | gateway.jsonl record 8 (heartbeat); sensor-B.jsonl record 5 (heartbeat) | 2 agreeing source(s); time range ±0.050s plus source spread Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |
| 2026-11-06T21:20:21.950000+00:00 to 2026-11-06T21:20:22.050000+00:00 | heartbeat | gateway, sensor-B | **Confirmed** | gateway.jsonl record 9 (heartbeat); sensor-B.jsonl record 6 (heartbeat) | 2 agreeing source(s); time range ±0.050s plus source spread Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |

## Evidence manifest

| File | Bytes | SHA-256 | Collected at |
|---|---:|---|---|
| gateway.jsonl | 990 | `3279dfea073213e43769941513c2661567f1845e3d12dc6025ddae213be53638` | 2026-11-13T03:48:26.955842+00:00 |
| sensor-A.jsonl | 215 | `84513e6a72b54c75d4ba0d632bd1ae143fea698ef7bdd137b3142ac4bd74d1f5` | 2026-11-13T03:48:26.955842+00:00 |
| sensor-B.jsonl | 656 | `5b2bc59d5cbba6004a10b9bee3f63a402351798a3622df4fafa6b987c4d0acd4` | 2026-11-13T03:48:26.955842+00:00 |

## Interpretation limits

- A SHA-256 hash records bytes seen during this run; it cannot establish provenance or integrity before acquisition.
- Prior-manifest hash comparisons detect byte changes only when a previous manifest exists and has not itself been replaced.
- Clock offsets require shared event IDs in the gateway and device evidence; estimates describe the observed anchors and do not prove gateway time is correct.
- PCAP and PCAPNG support is limited to classic formats and Ethernet, raw IP, or Linux cooked headers; packet payloads are not parsed. Repeated header flows are coalesced into one-second summaries.
- Sequence gaps and silence can reflect ordinary loss or device behavior; they are not proof of deletion or an attack.
- Periodic-event hypotheses are low-confidence and explicitly labeled Inferred; corroboration rules cannot establish authenticity.
