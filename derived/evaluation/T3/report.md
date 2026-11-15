# NEXUS-IoT Incident Reconstruction

Created: 2026-11-13T03:48:27.126053+00:00

## Evidence validation

- gateway.jsonl: possible missing sequence ranges [(7, 7)]; loss/deletion/sequence policy are all possible
- sensor-B.jsonl: possible missing sequence ranges [(3, 3)]; loss/deletion/sequence policy are all possible

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
| 2026-11-06T21:20:07.950000+00:00 to 2026-11-06T21:20:12.050000+00:00 | Unknown missing event(s), 1 sequence value(s) | gateway | **Unknown gap** | gateway.jsonl sequence 6; gateway.jsonl sequence 8 | Bounds are adjacent recorded sequence timestamps; missing event content and exact time are unknown. A sequence gap can reflect loss, deletion, or a sequence assignment rule; it does not prove tampering. |
| 2026-11-06T21:20:09+00:00 to 2026-11-06T21:20:11+00:00 | Possible missing periodic 'heartbeat' event | sensor-B | **Inferred** | sensor-B.jsonl heartbeat at 1794000006.000; sensor-B.jsonl heartbeat at 1794000014.000 | Low-confidence periodicity hypothesis; estimated period 4.000s; display window includes ±25% of period. Absence may be normal silence or an unobserved behavior. This hypothesis is never counted as a recorded fact. |
| 2026-11-06T21:20:05.950000+00:00 to 2026-11-06T21:20:14.050000+00:00 | Unknown missing event(s), 1 sequence value(s) | sensor-B | **Unknown gap** | sensor-B.jsonl sequence 2; sensor-B.jsonl sequence 4 | Bounds are adjacent recorded sequence timestamps; missing event content and exact time are unknown. A sequence gap can reflect loss, deletion, or a sequence assignment rule; it does not prove tampering. |
| 2026-11-06T21:20:11.950000+00:00 to 2026-11-06T21:20:12.050000+00:00 | recovery | gateway, sensor-A | **Confirmed** | gateway.jsonl record 7 (recovery); sensor-A.jsonl record 5 (recovery) | 2 agreeing source(s); time range ±0.050s plus source spread Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |
| 2026-11-06T21:20:13.950000+00:00 to 2026-11-06T21:20:14.050000+00:00 | heartbeat | gateway, sensor-B | **Confirmed** | gateway.jsonl record 8 (heartbeat); sensor-B.jsonl record 3 (heartbeat) | 2 agreeing source(s); time range ±0.050s plus source spread Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |
| 2026-11-06T21:20:15.950000+00:00 to 2026-11-06T21:20:16.050000+00:00 | command | gateway, sensor-A | **Confirmed** | gateway.jsonl record 9 (command); sensor-A.jsonl record 6 (command) | 2 agreeing source(s); time range ±0.050s plus source spread Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |
| 2026-11-06T21:20:17.950000+00:00 to 2026-11-06T21:20:18.050000+00:00 | heartbeat | gateway, sensor-B | **Confirmed** | gateway.jsonl record 10 (heartbeat); sensor-B.jsonl record 4 (heartbeat) | 2 agreeing source(s); time range ±0.050s plus source spread Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |
| 2026-11-06T21:20:21.950000+00:00 to 2026-11-06T21:20:22.050000+00:00 | heartbeat | gateway, sensor-B | **Confirmed** | gateway.jsonl record 11 (heartbeat); sensor-B.jsonl record 5 (heartbeat) | 2 agreeing source(s); time range ±0.050s plus source spread Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |

## Evidence manifest

| File | Bytes | SHA-256 | Collected at |
|---|---:|---|---|
| gateway.jsonl | 1177 | `81cf26104ee9fde13b3d4ed9a68aea8d84105821e25f4174181d373289d628c1` | 2026-11-13T03:48:27.110625+00:00 |
| sensor-A.jsonl | 650 | `bdbb57427fc14c2a31c7cfdf37b7e983f6db3d94dc69ddda97042188c03af69a` | 2026-11-13T03:48:27.110625+00:00 |
| sensor-B.jsonl | 546 | `84c5abc40ecf3222b7b7cdf4f51f71737cb0a6714ca3208bab42790ee78060c7` | 2026-11-13T03:48:27.110625+00:00 |

## Interpretation limits

- A SHA-256 hash records bytes seen during this run; it cannot establish provenance or integrity before acquisition.
- Prior-manifest hash comparisons detect byte changes only when a previous manifest exists and has not itself been replaced.
- Clock offsets require shared event IDs in the gateway and device evidence; estimates describe the observed anchors and do not prove gateway time is correct.
- PCAP and PCAPNG support is limited to classic formats and Ethernet, raw IP, or Linux cooked headers; packet payloads are not parsed. Repeated header flows are coalesced into one-second summaries.
- Sequence gaps and silence can reflect ordinary loss or device behavior; they are not proof of deletion or an attack.
- Periodic-event hypotheses are low-confidence and explicitly labeled Inferred; corroboration rules cannot establish authenticity.
