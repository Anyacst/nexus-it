"""Chain-of-custody log and examiner notes: recording, verification, tamper detection, CLI and HTML."""
from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from nexus_iot.__main__ import export_html, main
from nexus_iot.custody import (CUSTODY_FILE, add_note, append_entry, custody_view, entry_hash, notes_by_event, read_log,
                               retract_note, sign_head, verify_log)
from nexus_iot.pipeline import analyze
from nexus_iot.report_html import render_report


def write_rows(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")


class CustodyTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()
        write_rows(self.evidence / "sensor-A.jsonl", [
            {"event_id": "a-1", "sequence": 1, "timestamp": 100, "device": "sensor-A", "event": "boot"},
            {"event_id": "a-2", "sequence": 2, "timestamp": 110, "device": "sensor-A", "event": "door_open"},
        ])
        self.case = self.root / "case"
        self.key = self.root / "key.bin"
        self.key.write_bytes(b"k" * 32)

    def tearDown(self):
        self.tmp.cleanup()

    def run_analysis(self, **kwargs) -> dict:
        return analyze(self.evidence, self.case, examiner=kwargs.pop("examiner", "Examiner One"),
                       case_number=kwargs.pop("case_number", "C-17"), **kwargs)

    def log(self) -> list[dict]:
        return read_log(self.case)[0]

    def rewrite(self, entries: list[dict]) -> None:
        (self.case / CUSTODY_FILE).write_text("".join(json.dumps(e, sort_keys=True) + "\n" for e in entries), encoding="utf-8")


class RecordingTests(CustodyTestCase):
    def test_analysis_entry_records_evidence_and_report_hashes(self):
        result = self.run_analysis()
        (entry,) = self.log()
        self.assertEqual((entry["seq"], entry["action"], entry["examiner"]), (1, "analysis", "Examiner One"))
        self.assertEqual(entry["prev_hash"], "0" * 64)
        self.assertEqual(entry["hash"], entry_hash(entry))
        self.assertTrue(entry["os_user"] and entry["host"])
        details = entry["details"]
        self.assertEqual(details["case_number"], "C-17")
        self.assertEqual(details["evidence_files"][0]["sha256"], result["evidence_manifest"][0]["sha256"])
        self.assertEqual(set(details["outputs"]), {"report.json", "report.md", "evidence_manifest.json"})
        check = verify_log(self.case)
        self.assertTrue(check["ok"], check)
        self.assertNotIn("custody", json.dumps(result["limitations"]).lower())

    def test_reanalysis_keeps_hash_history(self):
        first = self.run_analysis()["evidence_manifest"][0]["sha256"]
        with (self.evidence / "sensor-A.jsonl").open("a", encoding="utf-8") as f:
            f.write(json.dumps({"event_id": "a-3", "sequence": 3, "timestamp": 120, "device": "sensor-A", "event": "door_close"}) + "\n")
        self.run_analysis()
        one, two = self.log()
        self.assertEqual(two["prev_hash"], one["hash"])
        self.assertEqual(one["details"]["evidence_files"][0]["sha256"], first)
        self.assertNotEqual(two["details"]["evidence_files"][0]["sha256"], first)
        self.assertTrue(any("SHA-256 differs" in x for x in two["details"]["hash_changes_since_previous_run"]))
        self.assertTrue(verify_log(self.case)["ok"])

    def test_unknown_action_is_refused(self):
        with self.assertRaises(ValueError):
            append_entry(self.case, "made_up", {})


class TamperTests(CustodyTestCase):
    def setUp(self):
        super().setUp()
        self.run_analysis()
        add_note(self.case, "a-1", "first note")
        add_note(self.case, "a-2", "second note")

    def test_edited_entry_is_detected(self):
        entries = self.log()
        entries[1]["details"]["text"] = "changed"
        self.rewrite(entries)
        check = verify_log(self.case)
        self.assertFalse(check["ok"])
        self.assertIn("entry 2: content does not match its hash", check["issues"][0])

    def test_removed_entry_is_detected(self):
        entries = self.log()
        self.rewrite([entries[0], entries[2]])
        issues = verify_log(self.case)["issues"]
        self.assertTrue(any("expected sequence number 2" in i for i in issues), issues)
        self.assertTrue(any("does not link" in i for i in issues), issues)

    def test_damaged_log_is_not_extended(self):
        entries = self.log()
        entries[0]["examiner"] = "Someone Else"
        self.rewrite(entries)
        with self.assertRaises(ValueError) as ctx:
            add_note(self.case, "a-1", "more")
        self.assertIn("not appending", str(ctx.exception))
        with self.assertRaises(ValueError):
            self.run_analysis()

    def test_report_changed_after_analysis_is_detected(self):
        report = self.case / "report.json"
        report.write_text(report.read_text(encoding="utf-8").replace("door_open", "door_shut"), encoding="utf-8")
        issues = verify_log(self.case)["issues"]
        self.assertEqual(issues, ["report.json has changed since the last recorded analysis (entry 1)"])

    def test_signature_catches_a_rebuilt_log(self):
        sign_head(self.case, self.key)
        check = verify_log(self.case, self.key)
        self.assertTrue(check["ok"], check)
        self.assertEqual(check["signed_seq"], 3)
        # Rewrite history and recompute every hash: the chain checks pass, the signature does not.
        entries = self.log()
        entries[1]["details"]["text"] = "rewritten"
        previous = "0" * 64
        for e in entries:
            e["prev_hash"] = previous
            e["hash"] = entry_hash(e)
            previous = e["hash"]
        self.rewrite(entries)
        self.assertTrue(verify_log(self.case)["ok"])
        check = verify_log(self.case, self.key)
        self.assertFalse(check["ok"])
        self.assertIn("differs from the signed hash", check["issues"][0])

    def test_entries_after_signature_are_reported(self):
        sign_head(self.case, self.key)
        add_note(self.case, "a-1", "late note")
        check = verify_log(self.case, self.key)
        self.assertTrue(check["ok"])
        self.assertEqual(check["notes"], ["entries 4-4 were added after the last signature"])
        wrong = self.root / "wrong.bin"
        wrong.write_bytes(b"w" * 32)
        self.assertIn("does not verify with this key", verify_log(self.case, wrong)["issues"][0])


class NoteTests(CustodyTestCase):
    def setUp(self):
        super().setUp()
        self.run_analysis()

    def test_notes_and_retractions(self):
        note = add_note(self.case, "a-2", "  Door opened while occupant was away\n(see CCTV)  ", "Examiner Two")
        self.assertEqual(note["details"]["text"], "Door opened while occupant was away\n(see CCTV)")
        retraction = retract_note(self.case, note["seq"], "CCTV time was wrong", "Examiner Two")
        self.assertEqual(retraction["details"]["event_id"], "a-2")
        notes = notes_by_event(self.log())
        self.assertEqual(notes["a-2"][0]["retracted"]["seq"], retraction["seq"])
        with self.assertRaises(ValueError):
            retract_note(self.case, note["seq"], "again")
        with self.assertRaises(ValueError):
            retract_note(self.case, 1, "an analysis entry is not a note")

    def test_invalid_notes_are_refused(self):
        with self.assertRaises(ValueError):
            add_note(self.case, "no-such-event", "text")
        with self.assertRaises(ValueError):
            add_note(self.case, "a-1", "  \n ")
        with self.assertRaises(ValueError):
            add_note(self.case, "a-1", "x" * 5000)
        self.assertEqual(len(self.log()), 1)

    def test_html_shows_notes_and_custody(self):
        note = add_note(self.case, "a-1", "<b>check boot</b>", "Examiner Two")
        retract_note(self.case, add_note(self.case, "a-2", "wrong row")["seq"], "mistake")
        report = json.loads((self.case / "report.json").read_text(encoding="utf-8"))
        html = render_report(report, custody=custody_view(self.case))
        self.assertIn("id=notes", html)
        self.assertIn("&lt;b&gt;check boot&lt;/b&gt;", html)
        self.assertNotIn("<b>check boot</b>", html)
        self.assertIn(f"Note {note['seq']}", html)
        self.assertIn("class=retracted", html)
        self.assertIn("id=custody", html)
        self.assertIn("<span class=ok>Verified</span>: 4 entries", html)
        self.assertIn("C-17", html)  # case number taken from the analysis entry
        self.assertNotIn("<form", html)  # the static report has no forms


class CliTests(CustodyTestCase):
    def cli(self, *argv: str) -> tuple[int, str]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main(list(argv))
        return code, out.getvalue()

    def test_analyze_note_custody_and_export(self):
        code, out = self.cli("analyze", str(self.evidence), "--out", str(self.case), "--examiner", "Examiner One",
                             "--case-number", "C-9", "--signing-key", str(self.key))
        self.assertEqual(code, 0)
        self.assertIn("custody.jsonl", out)
        self.assertTrue((self.case / "custody.sig").is_file())
        code, out = self.cli("note", str(self.case), "--event", "a-1", "--text", "boot looks early", "--examiner", "E1",
                             "--signing-key", str(self.key))
        self.assertIn("custody entry 2", out)
        self.assertIn("boot looks early", (self.case / "report.html").read_text(encoding="utf-8"))
        code, out = self.cli("custody", str(self.case), "--key", str(self.key))
        self.assertEqual(code, 0, out)
        self.assertIn("signed up to entry 2", out)
        target = export_html(self.case / "report.json", self.root / "copy.html")
        last = self.log()[-1]
        self.assertEqual(last["action"], "report_exported")
        self.assertEqual(last["details"]["file"], str(target.resolve()))
        code, out = self.cli("note", str(self.case), "--retract", "2", "--text", "duplicate")
        self.assertIn("retracted", out)
        (self.case / "report.md").write_text("edited", encoding="utf-8")
        code, out = self.cli("custody", str(self.case))
        self.assertEqual(code, 1)
        self.assertIn("FAIL: report.md has changed", out)


if __name__ == "__main__":
    unittest.main()
