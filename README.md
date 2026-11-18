# NEXUS-IoT Incident Reconstruction

[![tests](https://github.com/Anyacst/nexus-it/actions/workflows/tests.yml/badge.svg)](https://github.com/Anyacst/nexus-it/actions/workflows/tests.yml)

A local Python research application that builds a reviewable timeline from supplied IoT device logs and gateway captures. It performs read-only acquisition, hashes inputs, validates records and clocks, decodes MQTT from packet captures, correlates matching observations, marks bounded hypotheses, and writes JSON, Markdown and self-contained HTML reports.

**It does not collect from live devices or networks.** It has no third-party runtime dependencies and has been designed for controlled datasets and examiner-supplied files, not production forensic certification. A separate Docker testbed ([`testbed/`](testbed/README.md)) generates realistic multi-device evidence with known ground truth for evaluation.

## Quick start

From the project folder (Python 3.10+, standard library only). On Windows use `python` instead of `python3`, or `.\run.ps1`; on macOS/Linux `./run.sh` is a shortcut for `python3 -m nexus_iot`.

```bash
python3 -m nexus_iot evaluate                       # synthetic benchmark (10 cases)
python3 -m unittest discover -s tests -t . -v       # tests
```

The first command creates synthetic `data/synthetic/evidence/` cases and separate ground truth under `data/synthetic/ground_truth/`. Evaluation reports are written under `derived/evaluation/`. The generator refuses to write into an unmarked or modified synthetic-data folder and never touches `sample_inputs/`. If a future generator update requires replacing a verified generated dataset, use `python3 -m nexus_iot evaluate --regenerate`; this refuses unmarked or modified contents.

Analyze your own evidence folder:

```bash
python3 -m nexus_iot analyze /cases/case-001 --out /cases/case-001-derived --case-number C-001 --examiner "A. Examiner"
```

The output path must be outside the evidence folder. Each input is copied to a temporary analysis snapshot while it is hashed; parsing uses those snapshot bytes, and the temporary copies are removed when the run ends. The source files are never edited. Reuse the same output folder on later runs to compare file hashes with the previous project manifest.

The output folder receives `evidence_manifest.json`, `report.json`, `report.md` and `report.html`. The HTML report is a single self-contained file (no scripts, no external resources) with the case header, rule findings (when `--rules` is given), evidence hashes, validation findings, clock estimates, an SVG timeline with one lane per device, and the full timeline table; print it to PDF from a browser for a paper copy. `--case-number` and `--examiner` only appear in the HTML header. Re-render a report later with:

```bash
python3 -m nexus_iot export-html /cases/case-001-derived/report.json --out case-001.html
```

To sign and later verify a manifest, provide an externally managed secret of at least 32 bytes:

```bash
python3 -m nexus_iot analyze /cases/case-001 --out /cases/case-001-derived --signing-key /secure/nexus-hmac.key
python3 -m nexus_iot verify-manifest /cases/case-001-derived/evidence_manifest.json /cases/case-001-derived/evidence_manifest.sig --key /secure/nexus-hmac.key
```

Keep that secret separately from the evidence and reports. HMAC signatures detect edits when the verification key is trusted; because HMAC is a shared secret, they do not establish who created a manifest or provide non-repudiation.

## Detection rules

A rules file lists patterns an examiner wants flagged in the reconstructed timeline. Pass it with `--rules`; findings are added to all three reports, and the rules file's path and SHA-256 are recorded with them:

```bash
python3 -m nexus_iot check-rules rules/smart_home.json          # validate and list the rules
python3 -m nexus_iot analyze /cases/case-001 --out /cases/case-001-derived --rules rules/smart_home.json
```

Rules are JSON (`{"rules": [...]}`). Each has an `id`, `title`, `type`, optional `severity` (info, low, medium, high) and `description`, and matches timeline rows by `event`, `device` and/or `label` (a string or a list):

| Type | Fires when | Example in `rules/smart_home.json` |
| --- | --- | --- |
| `match` | a row matches | R4: a lock event seen by only one source; R5: any Unknown gap |
| `absent_within` | a `trigger` row has no `expect` row within `window_seconds` (`direction`: before, after or both) | R1: lock released with no motion within 30 s |
| `sequence` | a `then` row follows a `first` row within `within_seconds` | R2: door opened within 10 s of a lock release |
| `count_within` | `count` matching rows fall within `window_seconds` | R3: 15 door openings in a minute |

A matcher without `label` only counts Confirmed and Single-source rows, so an Inferred event never satisfies an expectation and a gap is never mistaken for an event. Rules run on the clock-corrected times; a finding that cites uncalibrated rows says so, because its time window may not hold. Findings are leads for review, not conclusions.

## Chain of custody and examiner notes

Every case output folder has an append-only `custody.jsonl`. Each entry records the time, the action, the examiner, the OS user and host, the tool version and what was done, and carries the SHA-256 of the entry before it, so changing, removing or reordering any entry breaks the chain. An `analysis` entry stores the SHA-256 of every evidence file read and of the reports written, so the hash history survives later re-analysis.

```bash
python3 -m nexus_iot analyze /cases/case-001 --out /cases/case-001-derived --examiner "A. Examiner" --case-number C-001 --signing-key /secure/nexus-hmac.key
python3 -m nexus_iot note /cases/case-001-derived --event door-sensor-00012 --text "Door opened while occupant was away" --examiner "A. Examiner"
python3 -m nexus_iot note /cases/case-001-derived --retract 2 --text "Wrong row" --examiner "A. Examiner"
python3 -m nexus_iot custody /cases/case-001-derived --key /secure/nexus-hmac.key     # list and verify; exit code 1 on failure
```

Notes attach to a timeline row by event ID and are entries in the same log: a note is never edited or deleted, only retracted with a reason, so the history stays visible. `custody` verifies the chain, checks that `report.json`, `report.md` and `evidence_manifest.json` still match the last analysis, and, with the key, checks `custody.sig`, an HMAC of the latest entry. Without the key a person with write access could rebuild the whole log; the signature closes that gap up to the last signed entry. The HTML report shows notes on their rows, an examiner-notes list and the full custody log with its verification result; `export-html` records each export in the log.

## Browser interface

Start the local browser interface:

```bash
python3 -m nexus_iot serve
```

Open `http://127.0.0.1:8765`, enter the full path to a supplied evidence directory and, optionally, a case name, case number, examiner and rules file, then inspect its timeline and findings. Filter rows by device/source, label or free text (plain `GET` parameters such as `/?case=<id>&label=Confirmed&device=sensor-A&q=boot`), click a row to see its supporting evidence, and download the reports (`/report.html?case=<id>`, `.json`, `.md`).

Every analyzed folder is saved as a case under `derived/web/<case-id>/` with its reports, its custody log and a `case.json` (name, number, examiner, evidence path, rules file, first and last analysis time, analysis count). The home page lists all cases. An open case shows whether its custody log verifies; each timeline row has an *Add examiner note* form and each note a *Retract* form, and report downloads are recorded in the log. An open case can be re-analyzed with one click: the same folder keeps the same case, and file hashes are compared with the previous run, so changes to the evidence since then are reported. *Delete case outputs* removes only that case's derived folder, never the evidence; its custody log is first closed with a `case_deleted` entry and archived under `derived/web/_deleted/`.

The server binds to loopback only, checks Host and Origin, uses a CSRF token on every form and a strict content security policy. Stop with Ctrl+C.

Example capture input: [`sample_inputs/gateway-demo.pcap`](sample_inputs/gateway-demo.pcap). Analyze it with:

```bash
python3 -m nexus_iot analyze sample_inputs --out derived/capture-demo
```

## Docker testbed

[`testbed/`](testbed/README.md) runs five simulated MQTT devices, a Mosquitto broker, a gateway logger and tcpdump in a closed Docker network, injects faults (disconnection, clock step and drift, capture gap, post-collection tampering), collects each run as a case folder with separate ground truth, and scores it. A multi-seed benchmark aggregates the results:

```bash
python3 -m testbed.runner.run_scenario all --analyze
python3 -m testbed.runner.benchmark --seeds 1 2 3 --scenarios all --duration 60
```

## Project layout

```text
nexus_iot/       evidence.py (acquisition, hashing, parsing), clock.py (clock models),
                 timeline.py (validation, correlation, labels), reporting.py (reports, signatures),
                 pipeline.py (analyze), capture.py (PCAP/PCAPNG), mqtt.py (MQTT decoding),
                 rules.py (detection rules), custody.py (custody log, notes), report_html.py, web.py (browser UI and cases),
                 evaluate.py, scenarios.py, __main__.py (CLI)
rules/           example detection rules (smart_home.json)
tests/           standard-library unit and integration tests
.github/         GitHub Actions workflow: tests on every push, Docker testbed on main
testbed/         Docker simulation, scenario runner, benchmark and their tests
docs/            project documentation and diagrams
data/synthetic/  generated E1-E7 and T1-T3 evidence plus separate ground truth (not real device data)
sample_inputs/   tiny synthetic PCAP example
derived/         generated manifests, timelines, reports, and benchmark metrics
```

`nexus_iot.pipeline.analyze` wires the stages together: `acquire` and `_load_evidence` (evidence.py), `validate` and `_timeline` (timeline.py), `_offset_estimates` (clock.py) and `_write_reports` (reporting.py); every stage name stays importable from `nexus_iot.pipeline`. `scenarios.py` and `evaluate.py` keep synthetic generation and scoring out of the evidence pipeline.

## Input format

Place evidence in a folder, optionally in subfolders. Supported files:

- UTF-8 JSON Lines: one JSON object per line. A device record needs `timestamp`, `device`, and a non-empty `event`. Use globally unique `event_id` values when records across files describe the same event; `sequence` is useful for gap detection. `source_id` can name an originating logger independently of its filename.
- A gateway JSONL filename must start with `gateway`; gateway records need `timestamp` and `event`, and can include `event_id`, `sequence`, and `peer`.
- Classic PCAP and PCAPNG captures are parsed as gateway evidence. Packet headers are summarized; payload bytes are not retained, except that MQTT 3.1.1 traffic is decoded (see below). Supported link layers are Ethernet (including VLAN tags), raw IP, and Linux cooked v1/v2. Repeated identical flows in one-second buckets are aggregated and shown with packet counts and timestamp ranges.

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

Rules are explicit analysis assumptions, not automatic protocol interpretation. A flow match supports only the configured network-pattern claim.

**MQTT decoding.** TCP streams on MQTT ports (default 1883; override with `"mqtt_ports": [1883, ...]` in `devices.json`) are reassembled per direction and decoded (CONNECT client ID, PUBLISH topic/QoS/packet ID, PUBACK, SUBSCRIBE, DISCONNECT). A client-to-broker PUBLISH whose JSON payload carries string `event_id`, `event` and `device` fields becomes an independent gateway-clock witness of that event, so a device event logged by the device, the gateway log and the capture can be supported by three sources. Only those parsed fields are kept, not raw payload bytes. Broker-to-subscriber copies are not counted twice. A QoS 1/2 PUBLISH the broker never acknowledged is reported as a finding, not as an event (it may be a retransmit on a dead connection). A topic that disagrees with the payload, or a client address that disagrees with `device_ips`, is kept and reported. CONNECT, DISCONNECT and SUBSCRIBE appear as `mqtt_*` session rows and are excluded from event scoring. Capture time is network delivery time, not device event time.

Malformed JSON rows, invalid timestamps, invalid fields, unsupported or corrupt capture data, missing files from a previous manifest, and changed hashes are reported. Valid records in other files continue to be analyzed when one input is malformed.

## Workflow and evidence handling

1. **Acquire:** enumerate supplied JSONL, PCAP, and PCAPNG files; copy them into a temporary snapshot, record relative path, source folder, collection time, size, and SHA-256, and flag detectable source changes during the copy.
2. **Preserve:** leave source bytes untouched and write derived outputs elsewhere. On repeated analysis using the same output folder, compare current hashes with the previous manifest.
3. **Validate:** report malformed rows, file-order timestamp regressions (packet captures may reorder by up to 10 ms, reported as capture jitter), duplicate or missing sequence values, conflicting event claims, variable clock offsets, and changes relative to the previous hash manifest.
4. **Correlate:** match shared event IDs and estimate per-source clock offset and linear drift from event-name- and peer-matched gateway/device anchors. Corrections require at least three anchors and a stable residual; otherwise the offset remains diagnostic and is not applied. Explicit capture-flow rules and decoded MQTT PUBLISH messages can add capture support.
5. **Reconstruct:** produce confirmed, single-source, inferred, network observation, and unknown-gap rows. Packet observations remain separate unless a configured flow-correlation rule or a decoded MQTT PUBLISH matches a device event.
6. **Report:** write `evidence_manifest.json`, `report.json`, readable `report.md` and, from the CLI, the self-contained `report.html`. If `--signing-key` is provided, also write detached `evidence_manifest.sig`.

## Event labels

- **Confirmed:** at least two distinct source IDs report the same event ID and event name. Different files are treated as separate sources unless records explicitly share a `source_id`. The software cannot establish that sources are truly independent or honest.
- **Single-source:** one source supports the event claim, or sources disagree about the claim. Conflicts are called out in validation findings; they are not silently resolved.
- **Inferred:** the input contains at least four observations of the same event type on a device, and a gap is at least 1.75 times the median observed period. The software adds a low-confidence possible missing periodic event, estimated at the usual interval, with a ±25% period window. This is a hypothesis, never a fact.
- **Unknown gap:** sequence metadata or numbered event IDs show a discontinuity. The report bounds the gap using surrounding record times and states that the missing content and exact time are unknown.

There is no rule that labels the absence of a packet or log line as proof of an event or attack. With no sequence metadata, repeated cadence, or matching independent observation, the system cannot determine what may be missing.

## Clock analysis

Each source with at least three valid event-name- and peer-matched event IDs receives a robust offset and Theil–Sen linear drift estimate. The default timestamp tolerance is 50 ms (`--tolerance` can change this floor). Uncertainty is the larger of that floor and `1.4826 × MAD` of model residuals. Models beyond the default ±1,000 ppm drift bound or two-second residual bound are flagged; with at least six anchors, the analyzer also searches for one boundary that divides the anchors into two stable segments and applies those separate models. If device time runs backwards in file order (a clock set back), the anchors are segmented in record order instead, and a single backward jump at the inferred step is reported as a clock change rather than as possible log editing; any other backward timestamp is still reported. Use `--max-clock-drift-ppm` and `--max-clock-residual` to change thresholds. With fewer than three anchors, no correction is applied. A piecewise fit is an inferred model and does not prove a clock was manipulated; gateway time remains an assumption.

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
- Classic PCAP and PCAPNG support is intentionally narrow: Ethernet, raw IP, and Linux cooked v1/v2; packet headers only. Payloads are decoded only for MQTT 3.1.1 on configured ports; other protocols are headers only, and arbitrary link types are unsupported. TCP reassembly stops at a capture gap and reports it. Capture bytes are read block by block. Repeated identical header flows in each one-second bucket are summarized to reduce timeline size; the analyzer still retains parsed event rows and reports, so very large or high-cardinality captures may require substantial memory.
- Clock models use at most one inferred step boundary and two linear segments. More complex clock behavior, inaccurate gateway time, or a coincidental data pattern can make the fitted correction wrong; the report records the model and uncertainty so an examiner can review it.
- Device IP mapping is descriptive only. The application does not infer device identity from encrypted traffic or MAC/IP addresses alone.
- The local web UI accepts only loopback binds/requests, checks the Host and Origin, uses a per-process CSRF token, and sets a restrictive content security policy. It has no user authentication and is for a single-user local demonstration.
- The benchmark is synthetic. Real-device validation requires a separately authorized controlled testbed, documented device/gateway clock sources, and independently captured ground truth; no physical network or device data is collected by this project.

## Tests

The project uses Python's built-in `unittest`; no `pip install` step is required. The suite exercises evidence hashing and preservation, prior-hash changes, event labels, piecewise clock steps, gaps, inferred events, manifest signatures, malformed inputs, PCAP and PCAPNG parsing/aggregation, MQTT decoding and TCP reassembly, detection rules, the custody log and examiner notes (including tamper detection), the HTML report and web UI (including escaping of untrusted strings), case management, the synthetic evaluation, output-path safety, and the protected local web workflow.

```bash
python3 -m unittest discover -s tests -t . -v            # analyzer
python3 -m unittest discover -s testbed/tests -t . -v    # testbed (Docker tests skipped)
NEXUS_DOCKER_TESTS=1 python3 -m unittest testbed.tests.test_integration_docker -v   # real containers
```

GitHub Actions (`.github/workflows/tests.yml`) runs the analyzer and testbed unit tests and a CLI smoke test on Python 3.10 to 3.13 for every push and pull request. The Docker integration tests run on pushes to `main` and on manual dispatch.

## License

MIT, see [LICENSE](LICENSE).
