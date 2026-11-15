# NEXUS-IoT Incident Reconstruction

A local Python research application that builds a reviewable timeline from supplied IoT device logs and gateway captures. It performs read-only acquisition, hashes inputs, validates records and clocks, correlates matching observations, marks bounded hypotheses, and writes JSON and Markdown reports.

**It does not collect from live devices or networks.** It has no third-party runtime dependencies and has been designed for controlled datasets and examiner-supplied files, not production forensic certification.

## Quick start (Windows PowerShell)

From the project folder:

```powershell
python -m nexus_iot evaluate
python -m unittest discover -v
```

The first command creates synthetic `data/synthetic/evidence/` cases and separate ground truth under `data/synthetic/ground_truth/`. Evaluation reports are written under `derived/evaluation/`. The generator refuses to write into an unmarked or modified synthetic-data folder; it never touches legacy `data/evidence/` or `sample_inputs/`. If a future generator update requires replacing a verified generated dataset, use `python -m nexus_iot evaluate --regenerate`; this refuses unmarked or modified contents.

Analyze your own evidence folder:

```powershell
python -m nexus_iot analyze "D:\cases\case-001" --out "D:\cases\case-001-derived"
```

The output path must be outside the evidence folder. Each input is copied to a temporary analysis snapshot while it is hashed; parsing uses those snapshot bytes, and the temporary copies are removed when the run ends. The source files are never edited. Reuse the same output folder on later runs to compare file hashes with the previous project manifest.

To sign and later verify a manifest, provide an externally managed secret of at least 32 bytes:

```powershell
python -m nexus_iot analyze "D:\cases\case-001" --out "D:\cases\case-001-derived" --signing-key "D:\secure\nexus-hmac.key"
python -m nexus_iot verify-manifest "D:\cases\case-001-derived\evidence_manifest.json" "D:\cases\case-001-derived\evidence_manifest.sig" --key "D:\secure\nexus-hmac.key"
```

Keep that secret separately from the evidence and reports. HMAC signatures detect edits when the verification key is trusted; because HMAC is a shared secret, they do not establish who created a manifest or provide non-repudiation.

Start the local browser interface:

```powershell
python -m nexus_iot serve
```

Open `http://127.0.0.1:8765`, enter the full path to a supplied evidence directory, then inspect its timeline and findings. The server binds to loopback only. It creates `derived/web/<case-key>/` reports; using the same evidence path reuses that case’s prior hash manifest. Stop with Ctrl+C.

Example capture input: [`sample_inputs/gateway-demo.pcap`](sample_inputs/gateway-demo.pcap). Analyze it with:

```powershell
python -m nexus_iot analyze sample_inputs --out derived/capture-demo
```

## Project layout

```text
nexus_iot/       acquisition, capture parsing, validation, reconstruction, CLI, web UI
tests/           standard-library unit and integration tests
data/synthetic/evidence/      generated E1-E7 test evidence (not real device data)
data/synthetic/ground_truth/  separate scenario truth used only by evaluate.py
data/evidence/                retained legacy prototype fixtures; evaluator does not use or overwrite it
sample_inputs/   tiny synthetic PCAP example
derived/         generated manifests, timelines, reports, and benchmark metrics
```

Within `nexus_iot/pipeline.py`, the stages are kept as separate functions: `acquire`, `parse_time`/`_load_evidence`, `validate`, `_offset_estimates`, `_timeline`, and `_write_reports`. `capture.py` handles PCAP/PCAPNG separately; `scenarios.py` and `evaluate.py` keep testbed generation and scoring out of the evidence pipeline.

## Input format

Place evidence in a folder, optionally in subfolders. Supported files:

- UTF-8 JSON Lines: one JSON object per line. A device record needs `timestamp`, `device`, and a non-empty `event`. Use globally unique `event_id` values when records across files describe the same event; `sequence` is useful for gap detection. `source_id` can name an originating logger independently of its filename.
- A gateway JSONL filename must start with `gateway`; gateway records need `timestamp` and `event`, and can include `event_id`, `sequence`, and `peer`.
- Classic PCAP and PCAPNG captures are parsed as gateway evidence. Packet headers are summarized; payload bytes are not retained. Supported link layers are Ethernet (including VLAN tags), raw IP, and Linux cooked v1/v2. Repeated identical flows in one-second buckets are aggregated and shown with packet counts and timestamp ranges.

`timestamp` may be Unix seconds (integer or float) or an ISO-8601 string with an explicit timezone, such as `2026-11-10T09:30:00+05:30`. Naive date-time strings are rejected as ambiguous.

Example device record:

```json
{"event_id":"boot-001","sequence":1,"timestamp":"2026-11-10T09:30:00+05:30","device":"sensor-A","event":"boot"}
```

Optional `devices.json` supports device IP mappings and explicit flow-correlation rules. Packet evidence can support an event only when a rule matches the device, event type, protocol, direction, port, and configured time window. A stable gateway calibration is required unless the rule explicitly supplies a `device_clock_offset_seconds` assumption. Example:

```json
{
  "device_ips": {"sensor-A": ["192.0.2.10"]},
  "correlation_rules": [{
    "id": "mqtt-command-flow", "device": "sensor-A", "event": "command",
    "protocol": "tcp", "direction": "outbound", "destination_port": 8883,
    "window_seconds": 2.0
  }]
}
```

Rules are explicit analysis assumptions, not automatic protocol interpretation. Payloads are not decoded, so a flow match supports only the configured network-pattern claim.

Malformed JSON rows, invalid timestamps, invalid fields, unsupported or corrupt capture data, missing files from a previous manifest, and changed hashes are reported. Valid records in other files continue to be analyzed when one input is malformed.

## Workflow and evidence handling

1. **Acquire:** enumerate supplied JSONL, PCAP, and PCAPNG files; copy them into a temporary snapshot, record relative path, source folder, collection time, size, and SHA-256, and flag detectable source changes during the copy.
2. **Preserve:** leave source bytes untouched and write derived outputs elsewhere. On repeated analysis using the same output folder, compare current hashes with the previous manifest.
3. **Validate:** report malformed rows, file-order timestamp regressions, duplicate or missing sequence values, conflicting event claims, variable clock offsets, and changes relative to the previous hash manifest.
4. **Correlate:** match shared event IDs and estimate per-source clock offset and linear drift from event-name- and peer-matched gateway/device anchors. Corrections require at least three anchors and a stable residual; otherwise the offset remains diagnostic and is not applied. Explicit capture-flow rules can add packet support.
5. **Reconstruct:** produce confirmed, single-source, inferred, network observation, and unknown-gap rows. Packet observations remain separate unless a configured flow-correlation rule matches a device event.
6. **Report:** write `evidence_manifest.json`, `report.json`, and readable `report.md`. If `--signing-key` is provided, also write detached `evidence_manifest.sig`.

## Event labels

- **Confirmed:** at least two distinct source IDs report the same event ID and event name. Different files are treated as separate sources unless records explicitly share a `source_id`. The software cannot establish that sources are truly independent or honest.
- **Single-source:** one source supports the event claim, or sources disagree about the claim. Conflicts are called out in validation findings; they are not silently resolved.
- **Inferred:** the input contains at least four observations of the same event type on a device, and a gap is at least 1.75 times the median observed period. The software adds a low-confidence possible missing periodic event, estimated at the usual interval, with a ±25% period window. This is a hypothesis, never a fact.
- **Unknown gap:** sequence metadata or numbered event IDs show a discontinuity. The report bounds the gap using surrounding record times and states that the missing content and exact time are unknown.

There is no rule that labels the absence of a packet or log line as proof of an event or attack. With no sequence metadata, repeated cadence, or matching independent observation, the system cannot determine what may be missing.

## Clock analysis

Each source with at least three valid event-name- and peer-matched event IDs receives a robust offset and Theil–Sen linear drift estimate. The default timestamp tolerance is 50 ms (`--tolerance` can change this floor). Uncertainty is the larger of that floor and `1.4826 × MAD` of model residuals. Models beyond the default ±1,000 ppm drift bound or two-second residual bound are flagged; with at least six anchors, the analyzer also searches for one boundary that divides the anchors into two stable segments and applies those separate models. Use `--max-clock-drift-ppm` and `--max-clock-residual` to change thresholds. With fewer than three anchors, no correction is applied. A piecewise fit is an inferred model and does not prove a clock was manipulated; gateway time remains an assumption.

Gateway reference time is an assumption, not a guarantee. PCAP timestamps remain as recorded by the capture; without shared IDs they cannot calibrate a device clock. Capture timestamp precision does not establish capture-host clock accuracy.

## Evaluation design

`python -m nexus_iot evaluate` creates deterministic scenarios for normal operation, disconnection, missing device log, timestamp step change, gateway packet loss, conflicting/inserted log content, combined failures, edit-only and insertion-only tamper controls, and a periodic-event inference control (ten cases total). Ground truth is stored outside each evidence folder and is not passed to the analysis pipeline. The generator writes only its marked `data/synthetic/` directory and protects existing inputs by hashing them before any regeneration.

Each benchmark pass disables comparison with manifests from an earlier pass, so changed synthetic fixture bytes do not count as tamper alerts. Regular case analysis still compares prior manifests when you reuse an output folder.

Reported measures:

- **Event precision, recall, and F1:** exact event ID and event-name matches. Inserted, unsupported log claims count as false positives; missed ground-truth IDs count as false negatives.
- **Timing within 1 s:** correctly matched event times within one second of ground truth, divided by all ground-truth events. The one-second tolerance is a benchmark choice, not an uncertainty guarantee.
- **Median absolute time error:** event timestamp deviation for correct event matches.
- **Maximum absolute time error:** worst correct-match timestamp deviation; the median alone can hide individual failures.
- **Event-label accuracy:** Confirmed versus Single-source agreement with the known available sources. It does not score Inferred or Unknown-gap rows.
- **Pairwise order accuracy:** correctly ordered event pairs among correctly matched events.
- **Unknown-gap precision and recall:** compare predicted sequence values missing from a source with intentionally omitted expected source rows.
- **Inferred-event precision and recall:** match explicitly inferred events to events removed from every source, by event name and within one second.
- **Tamper alert recall, false-positive rate, and precision:** scenario-level alerts for conflicting event claims or a hash change from a prior manifest, scored against seeded tamper scenarios. This deliberately does not count ordinary gaps as tampering.
- **Evidence completeness:** expected source-event rows present, matched by event ID in the corresponding ground-truth device file and gateway file, divided by all expected source-event rows. Extra inserted rows do not compensate for a missing row.
- **Processing time:** measured across hashing, parsing, analysis, and report writing; machine and storage dependent.

The benchmark has ten deterministic cases, including four seeded tamper cases, two clock-manipulation cases, and one periodic inference control. These values demonstrate behavior against known fixtures, not general performance, prevalence, or courtroom suitability. The ground-truth model evaluates known event IDs; it cannot score every possible semantic reconstruction.

## Limitations and interpretation

- Hashes establish the bytes seen when calculated. A changed hash against a prior output manifest indicates byte changes since that recorded run, assuming the prior manifest is trustworthy. Hashes do not prove pre-acquisition integrity, chain of custody, authorship, or authenticity.
- An edited or inserted record may evade checks if it preserves event IDs, sequence metadata, timing patterns, and cross-source agreement. A first-run hash alone cannot reveal previous edits.
- Classic PCAP and PCAPNG support is intentionally narrow: Ethernet, raw IP, and Linux cooked v1/v2; packet headers only. No protocol payload parsing, TCP stream reconstruction, or arbitrary link type support. Capture bytes are read block by block. Repeated identical header flows in each one-second bucket are summarized to reduce timeline size; the analyzer still retains parsed event rows and reports, so very large or high-cardinality captures may require substantial memory.
- Clock models use at most one inferred step boundary and two linear segments. More complex clock behavior, inaccurate gateway time, or a coincidental data pattern can make the fitted correction wrong; the report records the model and uncertainty so an examiner can review it.
- Device IP mapping is descriptive only. The application does not infer device identity from encrypted traffic or MAC/IP addresses alone.
- The local web UI accepts only loopback binds/requests, checks the Host and Origin, uses a per-process CSRF token, and sets a restrictive content security policy. It has no user authentication and is for a single-user local demonstration.
- The benchmark is synthetic. Real-device validation requires a separately authorized controlled testbed, documented device/gateway clock sources, and independently captured ground truth; no physical network or device data is collected by this project.

## Tests

The project uses Python’s built-in `unittest`; no `pip install` step is required. The suite exercises evidence hashing and preservation, prior-hash changes, event labels, piecewise clock steps, gaps, inferred events, manifest signatures, malformed inputs, PCAP and PCAPNG parsing/aggregation, the synthetic evaluation, output-path safety, and the protected local web workflow.

```powershell
python -m unittest discover -v
```
