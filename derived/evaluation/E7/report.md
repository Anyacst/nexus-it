# NEXUS-IoT Incident Reconstruction

Created: 2026-11-13T03:48:27.067553+00:00

## Evidence validation

- ev-002: conflicting event claims across sources: auth_fail, maintenance
- gateway.jsonl: possible missing sequence ranges [(3, 3)]; loss/deletion/sequence policy are all possible
- sensor-A.jsonl: only 1 valid clock anchor(s); offset estimate is diagnostic and was not applied
- sensor-A.jsonl: timestamps move backwards in file order
- sensor-B.jsonl: clock anchors do not fit an allowed stable model (residual range 7.714s, drift +214285.7ppm, limits ±2.000s and ±1000ppm); correction was not applied; possible step change or manipulation
- sensor-B.jsonl: possible missing sequence ranges [(3, 3)]; loss/deletion/sequence policy are all possible
- sensor-B/alert: periodic inference skipped because source clock calibration is unstable for sensor-B.jsonl
- sensor-B/heartbeat: periodic inference skipped because source clock calibration is unstable for sensor-B.jsonl
- sensor-B: gateway observation ev-007 has no matching device log record; absence cause is undetermined

## Clock estimates

| Source | Offset (s) | Drift (ppm) | Uncertainty (s) | Anchors | Applied |
|---|---:|---:|---:|---:|---|
| sensor-A.jsonl | +5.000000 | +0.000 | unknown | 1 | False |
| sensor-B.jsonl | +9.142857 | +214285.714 | unknown | 4 | False |

## Timeline

| UTC time / range | Event | Device / source | Label | Supporting evidence | Confidence / uncertainty and limitations |
|---|---|---|---|---|---|
| 2026-11-06T21:19:59.950000+00:00 to 2026-11-06T21:20:00.050000+00:00 | boot | gateway, sensor-A | **Confirmed** | gateway.jsonl record 1 (boot); sensor-A.jsonl record 1 (boot) | 2 agreeing source(s); time range ±0.050s plus source spread Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |
| 2026-11-06T21:20:01+00:00 (uncalibrated; uncalibrated-source-clock) | alert | sensor-B | **Single-source** | sensor-B.jsonl record 1 (alert) | 1 agreeing source(s); clocks are not calibrated, so no UTC uncertainty bound is available Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |
| 2026-11-06T21:20:01.950000+00:00 to 2026-11-06T21:20:02.050000+00:00 | Conflicting claims: auth_fail / maintenance | gateway, sensor-A | **Single-source** | gateway.jsonl record 2 (auth_fail); sensor-A.jsonl record 2 (maintenance) | 0 agreeing source(s); time range ±0.050s plus source spread Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |
| 2026-11-06T21:20:01.950000+00:00 to 2026-11-06T21:20:04.550000+00:00 | Unknown missing event(s), 1 sequence value(s) | gateway | **Unknown gap** | gateway.jsonl sequence 2; gateway.jsonl sequence 4 | Bounds are adjacent recorded sequence timestamps; missing event content and exact time are unknown. A sequence gap can reflect loss, deletion, or a sequence assignment rule; it does not prove tampering. |
| 2026-11-06T21:20:04.450000+00:00 to 2026-11-06T21:20:04.550000+00:00 | device_disconnected | gateway | **Single-source** | gateway.jsonl record 3 (device_disconnected) | 1 agreeing source(s); time range ±0.050s plus source spread Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |
| 2026-11-06T21:20:05.500000+00:00 (uncalibrated; uncalibrated-source-clock) | injected_admin_login | sensor-A | **Single-source** | sensor-A.jsonl record 3 (injected_admin_login) | 1 agreeing source(s); clocks are not calibrated, so no UTC uncertainty bound is available Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |
| 2026-11-06T21:20:05.950000+00:00 to 2026-11-06T21:20:06.050000+00:00 | heartbeat | gateway, sensor-B | **Confirmed** | gateway.jsonl record 4 (heartbeat); sensor-B.jsonl record 2 (heartbeat) | 2 agreeing source(s); time range ±0.050s plus source spread Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |
| 2026-11-06T21:20:09.950000+00:00 to 2026-11-06T21:20:10.050000+00:00 | heartbeat | gateway | **Single-source** | gateway.jsonl record 5 (heartbeat) | 1 agreeing source(s); time range ±0.050s plus source spread Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |
| 2026-11-06T21:20:09.950000+00:00 to 2026-11-06T21:20:10.050000+00:00 | Device log record for ev-007 is absent; gateway recorded 'heartbeat' | sensor-B | **Unknown gap** | gateway.jsonl record 5 (heartbeat); no matching event ID in device log for sensor-B | Gateway record exists; absence from the supplied device file is observable, but the cause is unknown. Could reflect collection loss, device behavior, ID mismatch, gateway fabrication, or deletion. Absence alone does not prove tampering. |
| 2026-11-06T21:20:13.950000+00:00 to 2026-11-06T21:20:14.050000+00:00 | heartbeat | gateway, sensor-B | **Confirmed** | gateway.jsonl record 6 (heartbeat); sensor-B.jsonl record 3 (heartbeat) | 2 agreeing source(s); time range ±0.050s plus source spread Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |
| 2026-11-06T21:20:03.950000+00:00 to 2026-11-06T21:20:24.050000+00:00 [device-clock-uncalibrated] | Unknown missing event(s), 1 sequence value(s) | sensor-B | **Unknown gap** | sensor-B.jsonl sequence 2; sensor-B.jsonl sequence 4 | Bounds are adjacent recorded sequence timestamps; missing event content and exact time are unknown. A sequence gap can reflect loss, deletion, or a sequence assignment rule; it does not prove tampering. |
| 2026-11-06T21:20:17.950000+00:00 to 2026-11-06T21:20:18.050000+00:00 | heartbeat | gateway, sensor-B | **Confirmed** | gateway.jsonl record 7 (heartbeat); sensor-B.jsonl record 4 (heartbeat) | 2 agreeing source(s); time range ±0.050s plus source spread Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |
| 2026-11-06T21:20:21.950000+00:00 to 2026-11-06T21:20:22.050000+00:00 | heartbeat | gateway, sensor-B | **Confirmed** | gateway.jsonl record 8 (heartbeat); sensor-B.jsonl record 5 (heartbeat) | 2 agreeing source(s); time range ±0.050s plus source spread Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity. |

## Evidence manifest

| File | Bytes | SHA-256 | Collected at |
|---|---:|---|---|
| gateway.jsonl | 886 | `771e55e5e7d1dac3902b5f0d3618960d2545115c68ccc55ab50d7e453ef70178` | 2026-11-13T03:48:27.054001+00:00 |
| sensor-A.jsonl | 342 | `6479259009548260f3786a2ad74db8d33e8141d0ad4a68c037407f1559d83c4c` | 2026-11-13T03:48:27.054001+00:00 |
| sensor-B.jsonl | 546 | `bcdb417caba1da4901008e2e186cb2c1585d09c8af4c0843ce57ed5567228445` | 2026-11-13T03:48:27.054001+00:00 |

## Interpretation limits

- A SHA-256 hash records bytes seen during this run; it cannot establish provenance or integrity before acquisition.
- Prior-manifest hash comparisons detect byte changes only when a previous manifest exists and has not itself been replaced.
- Clock offsets require shared event IDs in the gateway and device evidence; estimates describe the observed anchors and do not prove gateway time is correct.
- PCAP and PCAPNG support is limited to classic formats and Ethernet, raw IP, or Linux cooked headers; packet payloads are not parsed. Repeated header flows are coalesced into one-second summaries.
- Sequence gaps and silence can reflect ordinary loss or device behavior; they are not proof of deletion or an attack.
- Periodic-event hypotheses are low-confidence and explicitly labeled Inferred; corroboration rules cannot establish authenticity.
