"""Evidence acquisition, validation, clock calibration, reconstruction, and reporting.

The stages live in evidence.py, clock.py, timeline.py and reporting.py; this module
wires them together in analyze() and re-exports their names for existing importers."""
from __future__ import annotations

from . import __version__

import json
import math
import tempfile
import time
from pathlib import Path

from .evidence import (  # noqa: F401  re-exported for existing importers
    SUPPORTED,
    utc_now,
    parse_time,
    read_jsonl,
    acquire,
    _read_devices_config,
    _normalise_json_rows,
    MQTT_CONTROL_EVENTS,
    _device_ip_map,
    _mqtt_ports,
    mqtt_rows,
    _load_evidence,
)
from .clock import (  # noqa: F401  re-exported for existing importers
    MAX_CLOCK_DRIFT_PPM,
    MAX_CLOCK_RESIDUAL_SECONDS,
    _offset_estimates,
    explain_backward_steps,
    _event_time,
)
from .timeline import (  # noqa: F401  re-exported for existing importers
    NETWORK_EVENTS,
    _is_network_observation,
    _sequence_number,
    _event_key,
    _capture_correlations,
    _timeline,
    _evidence_text,
    _mqtt_observation,
    validate,
)
from .reporting import (  # noqa: F401  re-exported for existing importers
    _write_reports,
    _manifest_bytes,
    sign_manifest,
    verify_manifest,
)

from .custody import record_analysis, sign_head
from .rules import RULES_LIMITATION, apply_rules, load_rules, rules_summary

VERSION = __version__


def analyze(evidence_dir: Path, output_dir: Path, tolerance_seconds: float=0.05, compare_previous: bool=True,
            max_clock_drift_ppm: float=MAX_CLOCK_DRIFT_PPM,
            max_clock_residual_seconds: float=MAX_CLOCK_RESIDUAL_SECONDS,
            signing_key: Path|None=None, rules_path: Path|None=None, *, examiner: str="",
            case_number: str="") -> dict:
    """Analyze supplied evidence read-only; all derived outputs go to output_dir.

    Each run appends an analysis entry to output_dir/custody.jsonl (evidence and report hashes,
    examiner, case number). With a signing key the manifest and the custody log head are signed.
    """
    start = time.perf_counter()
    evidence_dir = evidence_dir.resolve()
    output_dir = output_dir.resolve()
    if not evidence_dir.is_dir():
        raise FileNotFoundError(f"evidence directory does not exist: {evidence_dir}")
    if output_dir == evidence_dir or evidence_dir in output_dir.parents:
        raise ValueError("output directory must be outside evidence so source files stay unchanged")
    if tolerance_seconds <= 0 or not math.isfinite(tolerance_seconds):
        raise ValueError("tolerance must be a positive finite number")
    if max_clock_drift_ppm <= 0 or not math.isfinite(max_clock_drift_ppm):
        raise ValueError("maximum clock drift must be a positive finite number")
    if max_clock_residual_seconds <= 0 or not math.isfinite(max_clock_residual_seconds):
        raise ValueError("maximum clock residual must be a positive finite number")
    ruleset = load_rules(rules_path) if rules_path is not None else None
    prior_path = output_dir/"evidence_manifest.json"
    try:
        previous = json.loads(prior_path.read_text(encoding="utf-8")) if compare_previous and prior_path.exists() else []
    except (OSError, json.JSONDecodeError):
        previous = []
    with tempfile.TemporaryDirectory(prefix="nexus-iot-snapshot-") as temp_name:
        snapshot_root = Path(temp_name)
        manifest, hash_findings = acquire(evidence_dir, snapshot_root, previous if isinstance(previous, list) else [])
        errors = []
        config = _read_devices_config(snapshot_root)
        if config.get("_config_error"):
            errors.append(config["_config_error"])
        events = _load_evidence(snapshot_root, errors, config)
    issues = hash_findings+validate(events, errors, config)
    if not manifest:
        issues.append("No supported evidence files found (.jsonl, .pcap, .pcapng).")
    offsets = _offset_estimates(events, issues, tolerance_seconds, max_clock_drift_ppm, max_clock_residual_seconds)
    issues = explain_backward_steps(events, offsets, issues)
    capture_links = _capture_correlations(events, config, offsets, issues)
    timeline = _timeline(events, offsets, issues, tolerance_seconds, capture_links)
    result = {"schema_version":VERSION, "created_at":utc_now(), "evidence_directory":str(evidence_dir), "evidence_record_count":len(events),
        "processing_seconds":None, "evidence_manifest":manifest, "clock_estimates":offsets,
        "validation_issues":sorted(set(issues)), "timeline":timeline,
        "limitations":["A SHA-256 hash records bytes seen during this run; it cannot establish provenance or integrity before acquisition.",
            "Prior-manifest hash comparisons detect byte changes only when a previous manifest exists and has not itself been replaced.",
            "Clock offsets require shared event IDs in the gateway and device evidence; estimates describe the observed anchors and do not prove gateway time is correct.",
            "PCAP and PCAPNG support is limited to classic formats and Ethernet, raw IP, or Linux cooked headers. Only plain-text MQTT 3.1.1 over TCP on the configured broker ports is decoded from payloads; other payloads are not parsed. Repeated header flows are coalesced into one-second summaries.",
            "An MQTT PUBLISH in a capture is a gateway-clock witness of the payload the device sent; capture time is network delivery time, and payload content is the device's own claim.",
            "Sequence gaps and silence can reflect ordinary loss or device behavior; they are not proof of deletion or an attack.",
            "Periodic-event hypotheses are low-confidence and explicitly labeled Inferred; corroboration rules cannot establish authenticity."]}
    if ruleset is not None:
        result["rules"] = rules_summary(ruleset)
        result["rule_findings"] = apply_rules(timeline, ruleset["rules"])
        result["limitations"].append(RULES_LIMITATION)
    result["processing_seconds"] = round(time.perf_counter()-start, 6)
    _write_reports(result, output_dir)
    (output_dir/"evidence_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    if signing_key is not None:
        sign_manifest(manifest, signing_key, output_dir/"evidence_manifest.sig")
    result["processing_seconds"] = round(time.perf_counter()-start, 6)
    (output_dir/"report.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    record_analysis(output_dir, result, examiner=examiner, case_number=case_number, hash_findings=hash_findings,
                    rules_sha256=ruleset["sha256"] if ruleset else None)
    if signing_key is not None:
        sign_head(output_dir, signing_key)
    return result
