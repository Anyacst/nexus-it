"""Synthetic evaluation of event recovery, timing, labels, gaps, and anomaly alerts."""
from __future__ import annotations
import json, statistics
from pathlib import Path
from .pipeline import _read_devices_config, analyze, mqtt_rows, read_jsonl
from .scenarios import CONDITIONS, build

def _pairwise_order(rows: list[tuple[float, float]]) -> float | None:
    """Fraction of (predicted, true) time pairs whose relative order agrees; None if under 2."""
    if len(rows) < 2:
        return None
    total = correct = 0
    for i in range(len(rows)):
        for j in range(i+1, len(rows)):
            total += 1
            if (rows[i][0]-rows[j][0])*(rows[i][1]-rows[j][1]) > 0:
                correct += 1
    return correct/total if total else None

def _capture_witnesses(evdir: Path) -> dict[str, set[tuple[str, str]]]:
    """Map event ID -> {(capture filename, event name)} for MQTT PUBLISH rows the analyzer would use.

    Captures are an available evidence source like the JSONL files, so they count toward the
    expected Confirmed/Single-source label; they do not change evidence completeness.
    """
    config = _read_devices_config(evdir)
    witnesses: dict[str, set[tuple[str, str]]] = {}
    for path in sorted(p for p in evdir.glob("*") if p.is_file() and p.suffix.lower() in {".pcap", ".pcapng"}):
        for row in mqtt_rows(path, evdir, config, []):
            if row["event_id"]:
                witnesses.setdefault(row["event_id"], set()).add((path.name, row["event"]))
    return witnesses

def score_case(evdir: Path, truth: dict, outdir: Path, case: str, title: str) -> dict:
    """Analyze one evidence folder and score it against its ground truth (truth is never passed to analyze)."""
    # Ignore old output manifests during a benchmark replay; routine case analysis still compares them.
    report = analyze(evdir, outdir, compare_previous=False)
    truth_by_id = {e["event_id"]:e for e in truth["events"]}
    predictions = [e for e in report["timeline"] if e["label"] not in ("Unknown gap", "Inferred") and
                 e["event"] not in ("network_packet", "unsupported_link_packet") and not e["event"].startswith("mqtt_")]
    predicted_by_id = {e["event_id"]:e for e in predictions}
    correct = []
    for event_id, e in predicted_by_id.items():
        gt = truth_by_id.get(event_id)
        if gt and e["event"] == gt["event"]:
            correct.append((e, gt))
    tp = len(correct)
    fp = len(predicted_by_id)-tp
    fn = len(truth_by_id)-tp
    precision = tp/(tp+fp) if tp+fp else 0.0
    recall = tp/(tp+fn) if tp+fn else 0.0
    f1 = 2*precision*recall/(precision+recall) if precision+recall else 0.0
    errors = [abs(e["timestamp"]-gt["timestamp"]) for e, gt in correct]
    within = sum(d <= 1.0 for d in errors)/len(truth_by_id) if truth_by_id else 0.0
    order = _pairwise_order([(e["timestamp"], gt["timestamp"]) for e, gt in correct])

    observed_rows = {}
    for path in evdir.glob("*.jsonl"):
        rows, _ = read_jsonl(path)
        observed_rows[path.name] = rows
    expected_count = truth.get("expected_record_count", sum(len(e.get("expected_sources", [])) for e in truth_by_id.values()))
    capture_witnesses = _capture_witnesses(evdir)
    source_rows_present = 0
    label_correct = 0
    label_total = 0
    for event_id, gt in truth_by_id.items():
        expected_sources = gt.get("expected_sources", [f"{gt['device']}.jsonl", "gateway.jsonl"])
        agreeing_sources = set()
        for source in expected_sources:
            filename = Path(source).name
            if any(str(row.get("event_id") or "") == event_id for row in observed_rows.get(filename, [])):
                source_rows_present += 1
            if any(str(row.get("event_id") or "") == event_id and row.get("event") == gt["event"] for row in observed_rows.get(filename, [])):
                agreeing_sources.add(filename)
        agreeing_sources.update(name for name, event in capture_witnesses.get(event_id, set()) if event == gt["event"])
        # The analyzer labels any disagreement about an ID's event name Single-source.
        conflicting = any(str(row.get("event_id") or "") == event_id and row.get("event") != gt["event"]
                        for source in expected_sources for row in observed_rows.get(Path(source).name, []))
        conflicting = conflicting or any(event != gt["event"] for _, event in capture_witnesses.get(event_id, set()))
        expected_label = "Confirmed" if len(agreeing_sources) >= 2 and not conflicting else "Single-source"
        if agreeing_sources:
            label_total += 1
            if event_id in predicted_by_id and predicted_by_id[event_id]["label"] == expected_label:
                label_correct += 1
    completeness = source_rows_present/expected_count if expected_count else 0.0
    expected_gap_positions = {}
    for event_id, gt in truth_by_id.items():
        for source in gt.get("expected_sources", []):
            filename = Path(source).name
            if not any(str(row.get("event_id") or "") == event_id for row in observed_rows.get(filename, [])):
                sequence = gt.get("source_sequences", {}).get(filename)
                if isinstance(sequence, int):
                    expected_gap_positions.setdefault(filename, set()).add(sequence)
    predicted_ranges = {}
    for gap in report["timeline"]:
        rng = gap.get("missing_sequence_range")
        source = gap.get("source_id")
        if gap.get("label") == "Unknown gap" and source and isinstance(rng, list) and len(rng) == 2:
            predicted_ranges.setdefault(Path(source).name, []).append((int(rng[0]), int(rng[1])))
    gap_tp = gap_predicted = gap_expected = 0
    for source, ranges in predicted_ranges.items():
        merged = []
        for start, end in sorted(ranges):
            if merged and start <= merged[-1][1]+1:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))
        gap_predicted += sum(end-start+1 for start, end in merged)
        expected = expected_gap_positions.get(source, set())
        gap_expected += len(expected)
        gap_tp += sum(1 for n in expected if any(start <= n <= end for start, end in merged))
    for source, positions in expected_gap_positions.items():
        if source not in predicted_ranges:
            gap_expected += len(positions)
    gap_precision = gap_tp/gap_predicted if gap_predicted else (1.0 if gap_expected == 0 else 0.0)
    gap_recall = gap_tp/gap_expected if gap_expected else 1.0
    inferred_rows = [e for e in report["timeline"] if e["label"] == "Inferred"]
    unobserved_truth = []
    for event_id, gt in truth_by_id.items():
        if not any(str(row.get("event_id") or "") == event_id for source in gt.get("expected_sources", []) for row in observed_rows.get(Path(source).name, [])):
            unobserved_truth.append((event_id, gt))
    inferred_matches = set()
    for row in inferred_rows:
        for event_id, gt in unobserved_truth:
            if gt["event"] in row["event"] and abs(row["timestamp"]-gt["timestamp"]) <= 1.0:
                inferred_matches.add(event_id)
                break
    inferred_tp = len(inferred_matches)
    inferred_fp = len(inferred_rows)-inferred_tp
    inferred_precision = inferred_tp/(inferred_tp+inferred_fp) if inferred_tp+inferred_fp else (1.0 if not unobserved_truth else 0.0)
    inferred_recall = inferred_tp/len(unobserved_truth) if unobserved_truth else 1.0
    tamper_alert = any(any(term in issue.lower() for term in ("conflicting event claims", "sha-256 differs", "prior manifest is now missing", "timestamps move backwards")) for issue in report["validation_issues"])
    clock_alert = any("clock anchors do not fit" in issue.lower() for issue in report["validation_issues"])
    return {"condition":case, "scenario":title, "event_precision":precision, "event_recall":recall, "event_f1":f1,
        "true_positive_events":tp, "false_positive_events":fp, "missed_events":fn, "event_label_accuracy":label_correct/label_total if label_total else 0.0,
        "timing_within_tolerance":within, "median_absolute_time_error_seconds":statistics.median(errors) if errors else None,
        "maximum_absolute_time_error_seconds":max(errors) if errors else None,
        "pairwise_order_accuracy":order, "tamper_alert":tamper_alert, "tampering_seeded":truth["tampering_seeded"],
        "tamper_mechanisms":truth.get("tamper_mechanisms", []), "clock_anomaly_alert":clock_alert,
        "clock_manipulated":truth.get("clock_manipulated", False), "evidence_completeness":completeness,
        "unknown_gap_precision":gap_precision, "unknown_gap_recall":gap_recall,
        "expected_missing_source_rows":gap_expected, "detected_missing_source_rows":gap_tp,
        "inferred_event_precision":inferred_precision, "inferred_event_recall":inferred_recall,
        "expected_unobserved_events":len(unobserved_truth), "matched_inferred_events":inferred_tp,
        "expected_source_rows_present":source_rows_present, "expected_source_rows":expected_count,
        "raw_records_received":report["evidence_record_count"], "processing_seconds":report["processing_seconds"]}

def run(root: Path, regenerate: bool = False) -> list[dict]:
    """Generate the synthetic dataset, score every case, and write metrics.json and metrics.md."""
    dataset = build(root, regenerate=regenerate)
    outroot = root/"derived"/"evaluation"
    outroot.mkdir(parents=True, exist_ok=True)
    results = []
    for case, title in CONDITIONS.items():
        evdir = dataset/"evidence"/case
        truth = json.loads((dataset/"ground_truth"/case/"truth.json").read_text(encoding="utf-8"))
        results.append(score_case(evdir, truth, outroot/case, case, title))

    def binary_summary(positive_key: str, alert_key: str) -> dict:
        positive = [r for r in results if r[positive_key]]
        negative = [r for r in results if not r[positive_key]]
        tp = sum(r[alert_key] for r in positive)
        fp = sum(r[alert_key] for r in negative)
        return {"recall":tp/len(positive) if positive else None, "false_positive_rate":fp/len(negative) if negative else None,
                "precision":tp/(tp+fp) if tp+fp else 0.0, "true_positive_scenarios":tp, "false_positive_scenarios":fp,
                "positive_scenarios":len(positive), "negative_scenarios":len(negative)}
    tamper_summary = binary_summary("tampering_seeded", "tamper_alert")
    clock_summary = binary_summary("clock_manipulated", "clock_anomaly_alert")
    correct_total = sum(r["true_positive_events"] for r in results)
    aggregate = {"event_precision":correct_total/max(1, sum(r["true_positive_events"]+r["false_positive_events"] for r in results)),
        "event_recall":correct_total/max(1, sum(r["true_positive_events"]+r["missed_events"] for r in results)),
        "median_absolute_time_error_seconds":statistics.median([r["median_absolute_time_error_seconds"] for r in results if r["median_absolute_time_error_seconds"] is not None]),
        "mean_pairwise_order_accuracy":statistics.mean([r["pairwise_order_accuracy"] for r in results if r["pairwise_order_accuracy"] is not None]),
        "mean_event_label_accuracy":statistics.mean(r["event_label_accuracy"] for r in results),
        "mean_evidence_completeness":statistics.mean(r["evidence_completeness"] for r in results),
        "mean_unknown_gap_precision":statistics.mean(r["unknown_gap_precision"] for r in results),
        "mean_unknown_gap_recall":statistics.mean(r["unknown_gap_recall"] for r in results),
        "mean_inferred_event_precision":statistics.mean(r["inferred_event_precision"] for r in results),
        "mean_inferred_event_recall":statistics.mean(r["inferred_event_recall"] for r in results),
        "mean_processing_seconds":statistics.mean(r["processing_seconds"] for r in results)}
    payload = {"evaluation_version":"4.0", "scenario_count":len(results), "aggregate":aggregate,
        "tamper_detection":tamper_summary, "clock_anomaly_detection":clock_summary, "scenarios":results,
        "interpretation_limits":["All values are from deterministic synthetic evidence with known IDs and timestamps.",
            "Event precision/recall use exact event IDs and names; these do not establish forensic validity.",
            "Timing scores use a fixed one-second threshold and are not uncertainty calibration.",
            "Pairwise order scores only correctly recovered event pairs.",
            "Label accuracy checks only Confirmed and Single-source against known source-event support (JSONL files plus decoded MQTT PUBLISH messages in captures); inferred and unknown-gap quality are not scored.",
            "Tamper alerts use claim conflicts, prior-manifest hash changes, or timestamp order regression. These are anomaly indicators, not proof of tampering.",
            "Only four small tamper-control scenarios and two clock-manipulation scenarios are included; rates are unstable.",
            "Processing time varies by machine and storage."]}
    (outroot/"metrics.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    lines = ["# NEXUS-IoT synthetic evaluation", "", f"Scenario count: {len(results)}", "",
        "| Condition | Event P | Event R | Event F1 | Label accuracy | Time ≤1s | Median error | Max error | Order | Completeness | Processing (s) |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for r in results:
        med = "n/a" if r["median_absolute_time_error_seconds"] is None else f"{r['median_absolute_time_error_seconds']:.3f}s"
        maxerr = "n/a" if r["maximum_absolute_time_error_seconds"] is None else f"{r['maximum_absolute_time_error_seconds']:.3f}s"
        order = "n/a" if r["pairwise_order_accuracy"] is None else f"{r['pairwise_order_accuracy']:.1%}"
        lines.append(f"| {r['condition']} {r['scenario']} | {r['event_precision']:.1%} | {r['event_recall']:.1%} | {r['event_f1']:.1%} | {r['event_label_accuracy']:.1%} | {r['timing_within_tolerance']:.1%} | {med} | {maxerr} | {order} | {r['evidence_completeness']:.1%} | {r['processing_seconds']:.6f} |")
    lines += ["", "## Gap and inference quality", "", f"- Unknown-gap precision / recall: {aggregate['mean_unknown_gap_precision']:.1%} / {aggregate['mean_unknown_gap_recall']:.1%}", f"- Inferred-event precision / recall: {aggregate['mean_inferred_event_precision']:.1%} / {aggregate['mean_inferred_event_recall']:.1%}",
        "- Scores are averaged per scenario. The inference control removes a periodic event from every evidence source; the score does not establish general inference quality.",
        "", "## Tamper alerts", "", f"- Recall: {tamper_summary['recall']:.1%}", f"- False-positive rate: {tamper_summary['false_positive_rate']:.1%}", f"- Precision: {tamper_summary['precision']:.1%}",
        "", "## Clock anomaly alerts", "", f"- Recall: {clock_summary['recall']:.1%}", f"- False-positive rate: {clock_summary['false_positive_rate']:.1%}", f"- Precision: {clock_summary['precision']:.1%}",
        "", "## Aggregate metrics", "", f"- Event precision / recall: {aggregate['event_precision']:.1%} / {aggregate['event_recall']:.1%}",
        f"- Mean event-label accuracy: {aggregate['mean_event_label_accuracy']:.1%}", f"- Mean pairwise ordering: {aggregate['mean_pairwise_order_accuracy']:.1%}",
        f"- Mean completeness: {aggregate['mean_evidence_completeness']:.1%}", f"- Mean processing: {aggregate['mean_processing_seconds']:.6f}s",
        "", "## Metrics and limits", "", "- Event precision/recall/F1 are exact event-ID and event-name matching scores.",
        "- Label accuracy compares Confirmed/Single-source against known expected source rows and agreement.",
        "- Time≤1s counts correctly matched truth events whose reconstructed time is within one second; misses count as failures.",
        "- Pairwise order compares the order of correctly matched event pairs; it excludes misses.",
        "- Completeness counts expected source-event rows present by ID; extra inserted records cannot mask missing rows.",
        "- Tamper and clock alert rates are scenario-level indicators over small deterministic cases. They are not proof or general estimates.",
        "- Unknown-gap precision/recall compare predicted missing sequence values with source rows intentionally omitted from the synthetic fixtures; they do not score arbitrary semantic gaps.",
        "- Inferred-event scores use events absent from all supplied sources and match predictions by name and within one second. Only one dedicated synthetic inference control is present; this does not measure uncertainty calibration or general inference validity.",
        "- PCAP loss detection beyond sequence-bearing gateway logs and real testbed performance remain unscored.",
        "", "These results characterize the generated dataset only."]
    (outroot/"metrics.md").write_text("\n".join(lines)+"\n", encoding="utf-8")
    return results
