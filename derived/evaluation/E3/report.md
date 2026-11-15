# NEXUS-IoT Incident Reconstruction

Created: 2026-11-13T03:48:26.989955+00:00

## Evidence validation

- sensor-B.jsonl: possible missing sequence ranges [(3, 3)]; loss/deletion/sequence policy are all possible
- sensor-B: gateway observation ev-007 has no matching device log record; absence cause is undetermined

## Clock estimates

| Source | Offset (s) | Drift (ppm) | Uncertainty (s) | Anchors | Applied |
|---|---:|---:|---:|---:|---|
| sensor-A.jsonl | +5.000000 | +0.000 | ±0.050000 | 6 | True |
| sensor-B.jsonl | -2.000000 | +0.000 | ±0.050000 | 5 | True |

## Timeline

| UTC time / range | Event | Device / source | Label | Supporting evidence | Confidence / uncertainty and limitations |
|---|---|---|---|---|---|
| 2026-11-06T21:19:59.950000+00:00 to 2026-11-06T21:20:00.050000+00:00 | boot | gateway, sensor-A | **Confirmed** | gateway.jsonl record 1 (boot); sensor-A.jsonl record 1 (boot) | 2 agreeing source(s); time range ±0.050s plus source spread Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |
| 2026-11-06T21:20:01.950000+00:00 to 2026-11-06T21:20:02.050000+00:00 | auth_fail | gateway, sensor-A | **Confirmed** | gateway.jsonl record 2 (auth_fail); sensor-A.jsonl record 2 (auth_fail) | 2 agreeing source(s); time range ±0.050s plus source spread Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |
| 2026-11-06T21:20:02.950000+00:00 to 2026-11-06T21:20:03.050000+00:00 | alert | gateway, sensor-B | **Confirmed** | gateway.jsonl record 3 (alert); sensor-B.jsonl record 1 (alert) | 2 agreeing source(s); time range ±0.050s plus source spread Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |
| 2026-11-06T21:20:03.950000+00:00 to 2026-11-06T21:20:04.050000+00:00 | command | gateway, sensor-A | **Confirmed** | gateway.jsonl record 4 (command); sensor-A.jsonl record 3 (command) | 2 agreeing source(s); time range ±0.050s plus source spread Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |
| 2026-11-06T21:20:05.950000+00:00 to 2026-11-06T21:20:06.050000+00:00 | heartbeat | gateway, sensor-B | **Confirmed** | gateway.jsonl record 5 (heartbeat); sensor-B.jsonl record 2 (heartbeat) | 2 agreeing source(s); time range ±0.050s plus source spread Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |
| 2026-11-06T21:20:07.950000+00:00 to 2026-11-06T21:20:08.050000+00:00 | link_down | gateway, sensor-A | **Confirmed** | gateway.jsonl record 6 (link_down); sensor-A.jsonl record 4 (link_down) | 2 agreeing source(s); time range ±0.050s plus source spread Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |
| 2026-11-06T21:20:09.950000+00:00 to 2026-11-06T21:20:10.050000+00:00 | heartbeat | gateway | **Single-source** | gateway.jsonl record 7 (heartbeat) | 1 agreeing source(s); time range ±0.050s plus source spread Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |
| 2026-11-06T21:20:09.950000+00:00 to 2026-11-06T21:20:10.050000+00:00 | Device log record for ev-007 is absent; gateway recorded 'heartbeat' | sensor-B | **Unknown gap** | gateway.jsonl record 7 (heartbeat); no matching event ID in device log for sensor-B | Gateway record exists; absence from the supplied device file is observable, but the cause is unknown. Could reflect collection loss, device behavior, ID mismatch, gateway fabrication, or deletion. Absence alone does not prove tampering. |
| 2026-11-06T21:20:05.950000+00:00 to 2026-11-06T21:20:14.050000+00:00 | Unknown missing event(s), 1 sequence value(s) | sensor-B | **Unknown gap** | sensor-B.jsonl sequence 2; sensor-B.jsonl sequence 4 | Bounds are adjacent recorded sequence timestamps; missing event content and exact time are unknown. A sequence gap can reflect loss, deletion, or a sequence assignment rule; it does not prove tampering. |
| 2026-11-06T21:20:11.950000+00:00 to 2026-11-06T21:20:12.050000+00:00 | recovery | gateway, sensor-A | **Confirmed** | gateway.jsonl record 8 (recovery); sensor-A.jsonl record 5 (recovery) | 2 agreeing source(s); time range ±0.050s plus source spread Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |
| 2026-11-06T21:20:13.950000+00:00 to 2026-11-06T21:20:14.050000+00:00 | heartbeat | gateway, sensor-B | **Confirmed** | gateway.jsonl record 9 (heartbeat); sensor-B.jsonl record 3 (heartbeat) | 2 agreeing source(s); time range ±0.050s plus source spread Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |
| 2026-11-06T21:20:15.950000+00:00 to 2026-11-06T21:20:16.050000+00:00 | command | gateway, sensor-A | **Confirmed** | gateway.jsonl record 10 (command); sensor-A.jsonl record 6 (command) | 2 agreeing source(s); time range ±0.050s plus source spread Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |
| 2026-11-06T21:20:17.950000+00:00 to 2026-11-06T21:20:18.050000+00:00 | heartbeat | gateway, sensor-B | **Confirmed** | gateway.jsonl record 11 (heartbeat); sensor-B.jsonl record 4 (heartbeat) | 2 agreeing source(s); time range ±0.050s plus source spread Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |
| 2026-11-06T21:20:21.950000+00:00 to 2026-11-06T21:20:22.050000+00:00 | heartbeat | gateway, sensor-B | **Confirmed** | gateway.jsonl record 12 (heartbeat); sensor-B.jsonl record 5 (heartbeat) | 2 agreeing source(s); time range ±0.050s plus source spread Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |

## Evidence manifest

| File | Bytes | SHA-256 | Collected at |
|---|---:|---|---|
| gateway.jsonl | 1285 | `165429df22d683518a3f423bc0fb90840c488884d6ba1c51e25b3088fd379422` | 2026-11-13T03:48:26.975604+00:00 |
| sensor-A.jsonl | 650 | `bdbb57427fc14c2a31c7cfdf37b7e983f6db3d94dc69ddda97042188c03af69a` | 2026-11-13T03:48:26.975604+00:00 |
| sensor-B.jsonl | 546 | `84c5abc40ecf3222b7b7cdf4f51f71737cb0a6714ca3208bab42790ee78060c7` | 2026-11-13T03:48:26.975604+00:00 |

## Interpretation limits

- A SHA-256 hash records bytes seen during this run; it cannot establish provenance or integrity before acquisition.
- Prior-manifest hash comparisons detect byte changes only when a previous manifest exists and has not itself been replaced.
- Clock offsets require shared event IDs in the gateway and device evidence; estimates describe the observed anchors and do not prove gateway time is correct.
- PCAP and PCAPNG support is limited to classic formats and Ethernet, raw IP, or Linux cooked headers; packet payloads are not parsed. Repeated header flows are coalesced into one-second summaries.
- Sequence gaps and silence can reflect ordinary loss or device behavior; they are not proof of deletion or an attack.
- Periodic-event hypotheses are low-confidence and explicitly labeled Inferred; corroboration rules cannot establish authenticity.
