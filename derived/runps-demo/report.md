# NEXUS-IoT Incident Reconstruction

Created: 2026-11-10T22:33:56.541472+00:00

## Evidence validation

- No validation findings.

## Clock estimates

| Source | Offset (s) | Uncertainty (s) | Anchors |
|---|---:|---:|---:|
| No matched timestamp anchors | 0 | unknown | 0 |

## Timeline

| UTC time / range | Event | Device / source | Label | Supporting evidence | Confidence / uncertainty and limitations |
|---|---|---|---|---|---|
| 1970-01-01T00:16:40+00:00 | network_packet | gateway-demo.pcap | **Single-source** | gateway-demo.pcap packet 1: 192.0.2.10:42000 -> 198.51.100.20:1883 udp; mapped device(s): unknown | Capture timestamp as recorded; capture clock accuracy is not independently established. Header summary only; no packet payload inspected. Capture packet presence does not prove a device event. |
| 1970-01-01T00:16:42+00:00 | network_packet | gateway-demo.pcap | **Single-source** | gateway-demo.pcap packet 2: 198.51.100.20:1883 -> 192.0.2.10:42000 udp; mapped device(s): unknown | Capture timestamp as recorded; capture clock accuracy is not independently established. Header summary only; no packet payload inspected. Capture packet presence does not prove a device event. |

## Evidence manifest

| File | Bytes | SHA-256 | Collected at |
|---|---:|---|---|
| gateway-demo.pcap | 140 | `cc0c7560fad99048b5d21dcecb86b8ada4eb586210c0620085bbd7d597fd4da5` | 2026-11-10T22:33:56.540507+00:00 |

## Interpretation limits

- A SHA-256 hash records bytes seen during this run; it cannot establish provenance or integrity before acquisition.
- Prior-manifest hash comparisons detect byte changes only when a previous manifest exists and has not itself been replaced.
- Clock offsets require shared event IDs in the gateway and device evidence; estimates describe the observed anchors and do not prove gateway time is correct.
- PCAP and PCAPNG support is limited to classic formats and Ethernet, raw IP, or Linux cooked v1; packet payloads are not parsed.
- Sequence gaps and silence can reflect ordinary loss or device behavior; they are not proof of deletion or an attack.
- Periodic-event hypotheses are low-confidence and explicitly labeled Inferred; corroboration rules cannot establish authenticity.
