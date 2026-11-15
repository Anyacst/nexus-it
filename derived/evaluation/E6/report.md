# NEXUS-IoT Incident Reconstruction

Created: 2026-11-13T03:48:27.048838+00:00

## Evidence validation

- ev-002: conflicting event claims across sources: auth_fail, maintenance
- sensor-A.jsonl: timestamps move backwards in file order

## Clock estimates

| Source | Offset (s) | Drift (ppm) | Uncertainty (s) | Anchors | Applied |
|---|---:|---:|---:|---:|---|
| sensor-A.jsonl | +5.000000 | +0.000 | ±0.050000 | 5 | True |
| sensor-B.jsonl | -2.000000 | +0.000 | ±0.050000 | 6 | True |

## Timeline

| UTC time / range | Event | Device / source | Label | Supporting evidence | Confidence / uncertainty and limitations |
|---|---|---|---|---|---|
| 2026-11-06T21:19:59.950000+00:00 to 2026-11-06T21:20:00.050000+00:00 | boot | gateway, sensor-A | **Confirmed** | gateway.jsonl record 1 (boot); sensor-A.jsonl record 1 (boot) | 2 agreeing source(s); time range ±0.050s plus source spread Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |
| 2026-11-06T21:20:00.450000+00:00 to 2026-11-06T21:20:00.550000+00:00 | injected_admin_login | sensor-A | **Single-source** | sensor-A.jsonl record 7 (injected_admin_login) | 1 agreeing source(s); time range ±0.050s plus source spread Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |
| 2026-11-06T21:20:01.950000+00:00 to 2026-11-06T21:20:02.050000+00:00 | Conflicting claims: auth_fail / maintenance | gateway, sensor-A | **Single-source** | gateway.jsonl record 2 (auth_fail); sensor-A.jsonl record 2 (maintenance) | 0 agreeing source(s); time range ±0.050s plus source spread Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |
| 2026-11-06T21:20:02.950000+00:00 to 2026-11-06T21:20:03.050000+00:00 | alert | gateway, sensor-B | **Confirmed** | gateway.jsonl record 3 (alert); sensor-B.jsonl record 1 (alert) | 2 agreeing source(s); time range ±0.050s plus source spread Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |
| 2026-11-06T21:20:03.950000+00:00 to 2026-11-06T21:20:04.050000+00:00 | command | gateway, sensor-A | **Confirmed** | gateway.jsonl record 4 (command); sensor-A.jsonl record 3 (command) | 2 agreeing source(s); time range ±0.050s plus source spread Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |
| 2026-11-06T21:20:05.950000+00:00 to 2026-11-06T21:20:06.050000+00:00 | heartbeat | gateway, sensor-B | **Confirmed** | gateway.jsonl record 5 (heartbeat); sensor-B.jsonl record 2 (heartbeat) | 2 agreeing source(s); time range ±0.050s plus source spread Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |
| 2026-11-06T21:20:07.950000+00:00 to 2026-11-06T21:20:08.050000+00:00 | link_down | gateway, sensor-A | **Confirmed** | gateway.jsonl record 6 (link_down); sensor-A.jsonl record 4 (link_down) | 2 agreeing source(s); time range ±0.050s plus source spread Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |
| 2026-11-06T21:20:09.950000+00:00 to 2026-11-06T21:20:10.050000+00:00 | heartbeat | gateway, sensor-B | **Confirmed** | gateway.jsonl record 7 (heartbeat); sensor-B.jsonl record 3 (heartbeat) | 2 agreeing source(s); time range ±0.050s plus source spread Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |
| 2026-11-06T21:20:11.950000+00:00 to 2026-11-06T21:20:12.050000+00:00 | recovery | gateway, sensor-A | **Confirmed** | gateway.jsonl record 8 (recovery); sensor-A.jsonl record 5 (recovery) | 2 agreeing source(s); time range ±0.050s plus source spread Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |
| 2026-11-06T21:20:13.950000+00:00 to 2026-11-06T21:20:14.050000+00:00 | heartbeat | gateway, sensor-B | **Confirmed** | gateway.jsonl record 9 (heartbeat); sensor-B.jsonl record 4 (heartbeat) | 2 agreeing source(s); time range ±0.050s plus source spread Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |
| 2026-11-06T21:20:15.950000+00:00 to 2026-11-06T21:20:16.050000+00:00 | command | gateway, sensor-A | **Confirmed** | gateway.jsonl record 10 (command); sensor-A.jsonl record 6 (command) | 2 agreeing source(s); time range ±0.050s plus source spread Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |
| 2026-11-06T21:20:17.950000+00:00 to 2026-11-06T21:20:18.050000+00:00 | heartbeat | gateway, sensor-B | **Confirmed** | gateway.jsonl record 11 (heartbeat); sensor-B.jsonl record 5 (heartbeat) | 2 agreeing source(s); time range ±0.050s plus source spread Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |
| 2026-11-06T21:20:21.950000+00:00 to 2026-11-06T21:20:22.050000+00:00 | heartbeat | gateway, sensor-B | **Confirmed** | gateway.jsonl record 12 (heartbeat); sensor-B.jsonl record 6 (heartbeat) | 2 agreeing source(s); time range ±0.050s plus source spread Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |

## Evidence manifest

| File | Bytes | SHA-256 | Collected at |
|---|---:|---|---|
| gateway.jsonl | 1285 | `165429df22d683518a3f423bc0fb90840c488884d6ba1c51e25b3088fd379422` | 2026-11-13T03:48:27.032828+00:00 |
| sensor-A.jsonl | 777 | `a1216f8710f9f054e5dc6509cf0d8bea49cbdb5fbd673130bc2ce551a8ae8148` | 2026-11-13T03:48:27.032828+00:00 |
| sensor-B.jsonl | 656 | `5b2bc59d5cbba6004a10b9bee3f63a402351798a3622df4fafa6b987c4d0acd4` | 2026-11-13T03:48:27.032828+00:00 |

## Interpretation limits

- A SHA-256 hash records bytes seen during this run; it cannot establish provenance or integrity before acquisition.
- Prior-manifest hash comparisons detect byte changes only when a previous manifest exists and has not itself been replaced.
- Clock offsets require shared event IDs in the gateway and device evidence; estimates describe the observed anchors and do not prove gateway time is correct.
- PCAP and PCAPNG support is limited to classic formats and Ethernet, raw IP, or Linux cooked headers; packet payloads are not parsed. Repeated header flows are coalesced into one-second summaries.
- Sequence gaps and silence can reflect ordinary loss or device behavior; they are not proof of deletion or an attack.
- Periodic-event hypotheses are low-confidence and explicitly labeled Inferred; corroboration rules cannot establish authenticity.
