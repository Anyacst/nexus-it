"""Command-line entry point for the NEXUS-IoT local application."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from . import __version__
from .evaluate import run
from .pipeline import analyze, verify_manifest
from .custody import (CUSTODY_FILE, add_note, append_entry, custody_view, file_sha256, read_log,
                      retract_note, sign_head, verify_log)
from .rules import load_rules
from .report_html import case_info_from, render_report
from .web import serve


def _add_case_arguments(parser: argparse.ArgumentParser) -> None:
    """Add the optional HTML-header-only case metadata arguments."""
    parser.add_argument("--case-number", help="case number shown in the HTML report header")
    parser.add_argument("--examiner", help="examiner name shown in the HTML report header")


def build_parser() -> argparse.ArgumentParser:
    """Build the ``nexus-iot`` argument parser."""
    p = argparse.ArgumentParser(prog="nexus-iot", description="Local reconstruction of IoT incidents from supplied forensic evidence")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="analyze supplied JSONL, PCAP, or PCAPNG files")
    a.add_argument("evidence", type=Path)
    a.add_argument("--out", type=Path, default=Path("derived/case"))
    a.add_argument("--tolerance", type=float, default=.05)
    a.add_argument("--max-clock-drift-ppm", type=float, default=1000.0)
    a.add_argument("--max-clock-residual", type=float, default=2.0)
    a.add_argument("--signing-key", type=Path, help="external 32+ byte secret used to HMAC-sign the evidence manifest and custody log")
    a.add_argument("--rules", type=Path, help="JSON detection rules file to evaluate over the timeline (see rules/smart_home.json)")
    _add_case_arguments(a)

    x = sub.add_parser("export-html", help="render an existing report.json as a self-contained report.html")
    x.add_argument("report", type=Path, help="path to report.json")
    x.add_argument("--out", type=Path, help="output HTML file (default: report.html next to report.json)")
    x.add_argument("--title", help="report title shown in the HTML header")
    _add_case_arguments(x)

    k = sub.add_parser("custody", help="verify a case's chain-of-custody log and list its entries")
    k.add_argument("case", type=Path, help="case output folder (the --out folder of analyze)")
    k.add_argument("--key", type=Path, help="HMAC key to check custody.sig")

    n = sub.add_parser("note", help="add or retract an examiner note on a timeline row (recorded in the custody log)")
    n.add_argument("case", type=Path, help="case output folder")
    group = n.add_mutually_exclusive_group(required=True)
    group.add_argument("--event", help="event ID of the timeline row to annotate")
    group.add_argument("--retract", type=int, metavar="SEQ", help="custody entry number of the note to retract")
    n.add_argument("--text", required=True, help="note text, or the reason for a retraction")
    n.add_argument("--examiner", default="", help="examiner name recorded with the entry")
    n.add_argument("--signing-key", type=Path, help="re-sign the custody log head after this entry")

    c = sub.add_parser("check-rules", help="validate a detection rules file and list its rules")
    c.add_argument("rules", type=Path)

    v = sub.add_parser("verify-manifest", help="verify a detached evidence manifest HMAC signature")
    v.add_argument("manifest", type=Path)
    v.add_argument("signature", type=Path)
    v.add_argument("--key", required=True, type=Path)

    e = sub.add_parser("evaluate", help="generate the ten synthetic cases (E1-E7, T1-T3) and run the benchmark")
    e.add_argument("--root", type=Path, default=Path.cwd())
    e.add_argument("--regenerate", action="store_true", help="replace a verified generated dataset after a generator-version change")

    w = sub.add_parser("serve", help="start the local browser interface on loopback only")
    w.add_argument("--host", default="127.0.0.1", choices=["127.0.0.1", "localhost"])
    w.add_argument("--port", type=int, default=8765)
    return p


def show_custody(case: Path, key: Path | None = None) -> int:
    """Print a case's custody entries and verification result; return 0 if it verifies."""
    entries, _ = read_log(case)
    for e in entries:
        details = e.get("details", {})
        what = {"analysis": f"{len(details.get('evidence_files', []))} evidence file(s) hashed",
                "note_added": f"note on {details.get('event_id')}: {details.get('text', '')[:60]}",
                "note_retracted": f"retracted note {details.get('note_seq')}: {details.get('reason', '')[:60]}"}.get(
                    e.get("action"), details.get("file", ""))
        print(f"{e.get('seq'):>4}  {e.get('time')}  {e.get('action'):<17} {e.get('examiner')} "
              f"({e.get('os_user')}@{e.get('host')})  {what}")
    check = verify_log(case, key)
    for note in check["notes"]:
        print(f"note: {note}")
    if check["ok"]:
        signed = f", signed up to entry {check['signed_seq']}" if check["signed_seq"] else ""
        print(f"Custody log verified: {check['entries']} entries{signed}.")
        return 0
    for issue in check["issues"]:
        print(f"FAIL: {issue}")
    return 1


def export_html(report_path: Path, out: Path | None = None, *, title: str | None = None,
                case_number: str | None = None, examiner: str | None = None) -> Path:
    """Render ``report_path`` (a report.json) to HTML and return the written file path.

    When the report's folder has a custody log, the HTML includes its notes and entries, and
    the export itself is recorded in the log with the SHA-256 of the written file.
    """
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if not isinstance(report, dict):
        raise ValueError(f"{report_path} is not a NEXUS-IoT report object")
    target = out if out is not None else report_path.with_name("report.html")
    target.parent.mkdir(parents=True, exist_ok=True)
    case_dir = report_path.resolve().parent
    custody = custody_view(case_dir)
    html = render_report(report, title=title, case_info=case_info_from(case_number, examiner), custody=custody)
    target.write_text(html, encoding="utf-8")
    if custody is not None:
        append_entry(case_dir, "report_exported", {"file": str(target.resolve()), "sha256": file_sha256(target)},
                     examiner or "")
    return target


def main(argv: list[str] | None = None) -> int:
    """Run the CLI and return a process exit code."""
    args = build_parser().parse_args(argv)
    if args.command == "analyze":
        result = analyze(args.evidence, args.out, args.tolerance, True, args.max_clock_drift_ppm,
                         args.max_clock_residual, args.signing_key, args.rules,
                         examiner=args.examiner or "", case_number=args.case_number or "")
        out = args.out.resolve()
        html_path = out / "report.html"
        html_path.write_text(render_report(result, case_info=case_info_from(args.case_number, args.examiner),
                                           custody=custody_view(out, args.signing_key)), encoding="utf-8")
        print(f"Analyzed {len(result['evidence_manifest'])} evidence files; {len(result['timeline'])} timeline rows.")
        print(f"Markdown report: {out / 'report.md'}")
        print(f"HTML report: {html_path}")
        if "rule_findings" in result:
            print(f"Rule findings: {len(result['rule_findings'])} from {len(result['rules']['rules'])} rule(s)")
        if args.signing_key:
            print(f"Signed manifest: {out / 'evidence_manifest.sig'}; signed custody log: {out / 'custody.sig'}")
        print(f"Custody log: {out / CUSTODY_FILE}")
    elif args.command == "export-html":
        target = export_html(args.report, args.out, title=args.title, case_number=args.case_number, examiner=args.examiner)
        print(f"HTML report: {target.resolve()}")
    elif args.command == "custody":
        return show_custody(args.case.resolve(), args.key)
    elif args.command == "note":
        case = args.case.resolve()
        if args.event is not None:
            entry = add_note(case, args.event, args.text, args.examiner)
            print(f"Note added as custody entry {entry['seq']} on {args.event}.")
        else:
            entry = retract_note(case, args.retract, args.text, args.examiner)
            print(f"Note {args.retract} retracted in custody entry {entry['seq']}.")
        if args.signing_key:
            sign_head(case, args.signing_key)
            print(f"Custody log head re-signed: {case / 'custody.sig'}")
        html_path = case / "report.html"
        if html_path.is_file():
            report = json.loads((case / "report.json").read_text(encoding="utf-8"))
            html_path.write_text(render_report(report, custody=custody_view(case, args.signing_key)), encoding="utf-8")
            print(f"HTML report updated: {html_path}")
    elif args.command == "check-rules":
        ruleset = load_rules(args.rules)
        print(f"{len(ruleset['rules'])} valid rule(s) in {ruleset['source']} (SHA-256 {ruleset['sha256']})")
        for r in ruleset["rules"]:
            print(f"  {r['id']} [{r['severity']}] {r['type']}: {r['title']}")
    elif args.command == "verify-manifest":
        valid = verify_manifest(args.manifest, args.signature, args.key)
        print("Manifest signature valid." if valid else "Manifest signature INVALID.")
        return 0 if valid else 1
    elif args.command == "evaluate":
        results = run(args.root.resolve(), regenerate=args.regenerate)
        for r in results:
            print(f"{r['condition']} {r['scenario']}: event F1={r['event_f1']:.1%}, "
                  f"timing_within_1s={r['timing_within_tolerance']:.1%}, completeness={r['evidence_completeness']:.1%}")
        print(f"Metrics: {(args.root.resolve() / 'derived' / 'evaluation' / 'metrics.md')}")
    else:
        serve(args.host, args.port, Path.cwd())
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, FileNotFoundError, PermissionError) as e:
        print(f"error: {e}")
        raise SystemExit(2)
