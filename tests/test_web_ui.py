"""Integration tests for the loopback web UI: filters, report download and request checks."""
from __future__ import annotations

import http.client
import json
import re
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.parse import urlencode

from nexus_iot.web import MAX_FILTER_LENGTH, MAX_QUERY_STRING, create_server


def write_rows(path: Path, rows: list[dict]) -> None:
    """Write ``rows`` as JSON Lines."""
    path.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")


class WebUiBase(unittest.TestCase):
    """Starts a server on a temporary project with a two-device evidence folder."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.evidence = self.root / "evidence"
        self.evidence.mkdir()
        write_rows(self.evidence / "sensor-A.jsonl", [
            {"event_id": "a-1", "sequence": 1, "timestamp": 100, "device": "sensor-A", "event": "boot"},
            {"event_id": "a-2", "sequence": 2, "timestamp": 110, "device": "sensor-A", "event": "heartbeat"},
        ])
        write_rows(self.evidence / "sensor-B.jsonl", [
            {"event_id": "b-1", "sequence": 1, "timestamp": 105, "device": "sensor-B", "event": "door_open"},
        ])
        self.server = create_server("127.0.0.1", 0, self.root)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.tmp.cleanup()

    def request(self, method: str, path: str, body: str | None = None, headers: dict | None = None):
        """Send one request on a fresh connection and return (status, headers, body)."""
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=10)
        try:
            conn.request(method, path, body, headers or {})
            response = conn.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            conn.close()

    def analyze_case(self) -> bytes:
        """Fetch the CSRF token, POST the evidence folder and return the result page."""
        status, _, page = self.request("GET", "/")
        self.assertEqual(status, 200)
        token = re.search(rb"name=csrf_token value='([^']+)'", page).group(1).decode()
        body = urlencode({"evidence": str(self.evidence), "csrf_token": token})
        status, _, page = self.request("POST", "/analyze", body, {"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(status, 200, page[:500])
        return page

    @staticmethod
    def rows(page: bytes) -> int:
        """Count rendered timeline table rows."""
        return page.count(b"<tr id='row-")

    def token(self) -> str:
        _, _, page = self.request("GET", "/cases")
        return re.search(rb"name=csrf_token value='([^']+)'", page).group(1).decode()

    def post(self, path: str, fields: dict) -> tuple[int, bytes]:
        body = urlencode({"csrf_token": self.token(), **fields})
        status, _, page = self.request("POST", path, body, {"Content-Type": "application/x-www-form-urlencoded"})
        return status, page

    def case_ids(self) -> list[str]:
        _, _, page = self.request("GET", "/cases")
        return [m.decode() for m in re.findall(rb"href='/\?case=([0-9a-f]{20})'", page)]


class WebUiTests(WebUiBase):
    def test_filters_and_expandable_rows(self):
        page = self.analyze_case()
        self.assertEqual(self.rows(page), 3)
        self.assertIn(b"<details class=evidence>", page)
        self.assertIn(b"sensor-A.jsonl record 1 (boot)", page)
        self.assertIn(b"<svg", page)

        _, _, page = self.request("GET", "/?device=sensor-B")
        self.assertEqual(self.rows(page), 1)
        self.assertIn(b"door_open", page)
        self.assertIn(b"showing 1 of 3", page)

        _, _, page = self.request("GET", "/?label=Single-source")
        self.assertEqual(self.rows(page), 3)
        _, _, page = self.request("GET", "/?label=Confirmed")
        self.assertEqual(self.rows(page), 0)
        self.assertIn(b"No rows match the current filters.", page)

        _, _, page = self.request("GET", "/?" + urlencode({"q": "HEARTBEAT"}))
        self.assertEqual(self.rows(page), 1)
        _, _, page = self.request("GET", "/?" + urlencode({"device": "sensor-A", "q": "boot"}))
        self.assertEqual(self.rows(page), 1)

    def test_page_csp_uses_style_nonce(self):
        self.analyze_case()
        status, headers, page = self.request("GET", "/?device=sensor-A")
        self.assertEqual(status, 200)
        csp = headers["Content-Security-Policy"]
        self.assertIn("default-src 'self'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertNotIn("unsafe-inline", csp)
        # Safari sends "Origin: null" on form posts under no-referrer, which the local-request check rejects.
        self.assertEqual(headers["Referrer-Policy"], "same-origin")
        nonce = re.search(r"'nonce-([^']+)'", csp).group(1)
        self.assertIn(f"<style nonce='{nonce}'>".encode(), page)
        self.assertNotIn(b"<script", page)

    def test_filter_params_are_escaped_and_capped(self):
        self.analyze_case()
        payload = "<script>alert('x')</script>\"'"
        status, _, page = self.request("GET", "/?" + urlencode({"q": payload, "device": payload, "label": payload}))
        self.assertEqual(status, 200)
        self.assertNotIn(b"<script>", page)
        self.assertIn(b"&lt;script&gt;alert(&#x27;x&#x27;)&lt;/script&gt;", page)
        _, _, page = self.request("GET", "/?" + urlencode({"q": "z" * 500}))
        self.assertTrue(b"z" * MAX_FILTER_LENGTH in page, "filter value should be kept up to the cap")
        self.assertFalse(b"z" * (MAX_FILTER_LENGTH + 1) in page, "filter value should be truncated at the cap")
        status, _, page = self.request("GET", "/?" + urlencode({"q": "y" * (MAX_QUERY_STRING + 10)}))
        self.assertEqual(status, 200)
        self.assertFalse(b"yyyy" in page, "oversized query strings should be ignored")

    def test_report_html_download(self):
        status, _, _ = self.request("GET", "/report.html")
        self.assertEqual(status, 404)
        self.analyze_case()
        status, headers, body = self.request("GET", "/report.html")
        self.assertEqual(status, 200)
        self.assertTrue(headers["Content-Type"].startswith("text/html"))
        self.assertRegex(headers["Content-Disposition"], r'^attachment; filename="nexus-iot-report-[A-Za-z0-9._-]+\.html"$')
        self.assertIn("style-src 'sha256-", headers["Content-Security-Policy"])
        self.assertIn(b"<svg", body)
        self.assertEqual(self.rows(body), 3)
        status, _, body = self.request("GET", "/report.json")
        self.assertEqual(status, 200)
        self.assertEqual(len(json.loads(body)["timeline"]), 3)

    def test_rejects_non_local_host_origin_and_unknown_paths(self):
        status, _, _ = self.request("GET", "/", headers={"Host": "evil.example"})
        self.assertEqual(status, 403)
        status, _, _ = self.request("GET", "/report.html", headers={"Host": "attacker.test:80"})
        self.assertEqual(status, 403)
        status, _, _ = self.request("POST", "/analyze", "x=1", {"Origin": "http://evil.example", "Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(status, 403)
        status, _, _ = self.request("GET", "/does-not-exist")
        self.assertEqual(status, 404)


class CaseManagementTests(WebUiBase):
    """Saved cases: list, open, re-analyze, rules and delete."""

    def make_evidence(self, name: str) -> Path:
        folder = self.root / name
        folder.mkdir()
        write_rows(folder / "lock.jsonl", [
            {"event_id": "l-1", "sequence": 1, "timestamp": 100, "device": "smart-lock", "event": "lock_released"},
        ])
        return folder

    def test_cases_are_listed_opened_and_kept_apart(self):
        status, page = self.post("/analyze", {"evidence": str(self.evidence), "name": "Case <A>", "case_number": "2026-17",
                                              "examiner": "Examiner One"})
        self.assertEqual(status, 200)
        self.assertIn(b"Case &lt;A&gt;", page)
        self.assertIn(b"2026-17", page)
        other = self.make_evidence("other")
        self.post("/analyze", {"evidence": str(other)})
        ids = self.case_ids()
        self.assertEqual(len(ids), 2)
        first = [i for i in ids if (self.root / "derived" / "web" / i / "case.json").read_text().find("Case <A>") >= 0][0]
        meta = json.loads((self.root / "derived" / "web" / first / "case.json").read_text())
        self.assertEqual((meta["name"], meta["case_number"], meta["examiner"]), ("Case <A>", "2026-17", "Examiner One"))

        status, _, page = self.request("GET", "/?case=" + first)
        self.assertEqual(status, 200)
        self.assertEqual(self.rows(page), 3)
        self.assertIn(f"case={first}&amp;device=sensor-A".encode(), page)
        self.assertIn(f"<input type=hidden name='case' value='{first}'>".encode(), page)
        status, _, body = self.request("GET", f"/report.json?case={first}")
        self.assertEqual(len(json.loads(body)["timeline"]), 3)
        status, _, body = self.request("GET", f"/report.html?case={first}")
        self.assertIn(b"Examiner One", body)

        for bad in ("../../etc", "0" * 20, "zz"):
            status, _, _ = self.request("GET", "/?" + urlencode({"case": bad}))
            self.assertEqual(status, 404, bad)
        status, _, _ = self.request("GET", "/report.json?case=../x")
        self.assertEqual(status, 404)

    def test_reanalysis_keeps_case_and_reports_evidence_changes(self):
        self.post("/analyze", {"evidence": str(self.evidence), "name": "Kept name"})
        (case_id,) = self.case_ids()
        with (self.evidence / "sensor-B.jsonl").open("a", encoding="utf-8") as f:
            f.write("\n" + json.dumps({"event_id": "b-2", "sequence": 2, "timestamp": 120, "device": "sensor-B", "event": "door_close"}))
        status, page = self.post("/analyze", {"evidence": str(self.evidence), "name": ""})
        self.assertEqual(status, 200)
        self.assertEqual(self.case_ids(), [case_id])
        meta = json.loads((self.root / "derived" / "web" / case_id / "case.json").read_text())
        self.assertEqual((meta["name"], meta["analysis_count"]), ("Kept name", 2))
        self.assertIn(b"SHA-256 differs from the prior project manifest", page)

    def test_rules_file_from_form(self):
        rules = self.root / "rules.json"
        rules.write_text(json.dumps({"rules": [{"id": "R1", "title": "Door seen", "type": "match", "severity": "high",
                                                "match": {"event": "door_open"}}]}), encoding="utf-8")
        status, page = self.post("/analyze", {"evidence": str(self.evidence), "rules": str(rules)})
        self.assertEqual(status, 200)
        self.assertIn(b"id=rules", page)
        self.assertIn(b"Door seen", page)
        _, _, page = self.request("GET", "/cases")
        self.assertIn(b"<td class=num>1</td></tr>", page)
        status, page = self.post("/analyze", {"evidence": str(self.evidence), "rules": str(self.root / "missing.json")})
        self.assertEqual(status, 400)
        self.assertIn(b"Rules file does not exist", page)

    def test_delete_removes_outputs_only(self):
        self.post("/analyze", {"evidence": str(self.evidence)})
        (case_id,) = self.case_ids()
        body = urlencode({"csrf_token": "wrong", "case": case_id})
        status, _, _ = self.request("POST", "/case/delete", body, {"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(status, 403)
        status, page = self.post("/case/delete", {"case": "../evidence"})
        self.assertEqual(status, 404)
        status, page = self.post("/case/delete", {"case": case_id})
        self.assertEqual(status, 200)
        self.assertIn(b"evidence folder was not changed", page)
        self.assertFalse((self.root / "derived" / "web" / case_id).exists())
        self.assertTrue((self.evidence / "sensor-A.jsonl").is_file())
        self.assertEqual(self.case_ids(), [])
        status, _, _ = self.request("GET", "/report.json")
        self.assertEqual(status, 404)


class CustodyWebTests(WebUiBase):
    """Examiner notes and the custody log through the browser interface."""

    def open_case(self) -> tuple[str, Path]:
        self.post("/analyze", {"evidence": str(self.evidence), "examiner": "Examiner One"})
        (case_id,) = self.case_ids()
        return case_id, self.root / "derived" / "web" / case_id

    def log(self, folder: Path) -> list[dict]:
        return [json.loads(line) for line in (folder / "custody.jsonl").read_text(encoding="utf-8").splitlines()]

    def test_add_and_retract_note(self):
        case_id, folder = self.open_case()
        _, _, page = self.request("GET", f"/?case={case_id}")
        self.assertIn(b"action=/case/note>", page)
        self.assertIn(b"<span class=ok>verified</span> (1 entries)", page)
        status, page = self.post("/case/note", {"case": case_id, "event_id": "b-1", "text": "Door opened <late>"})
        self.assertEqual(status, 303)
        entry = self.log(folder)[-1]
        self.assertEqual((entry["action"], entry["examiner"], entry["details"]["text"]),
                         ("note_added", "Examiner One", "Door opened <late>"))
        _, _, page = self.request("GET", f"/?case={case_id}")
        self.assertIn(b"Door opened &lt;late&gt;", page)
        self.assertIn(b"Examiner notes (1)", page)
        self.assertIn(b"Door opened &lt;late&gt;", (folder / "report.html").read_bytes())
        status, _ = self.post("/case/note/retract", {"case": case_id, "note_seq": str(entry["seq"]), "reason": "wrong door",
                                                     "examiner": "Examiner Two"})
        self.assertEqual(status, 303)
        _, _, page = self.request("GET", f"/?case={case_id}")
        self.assertIn(b"Retracted in entry 3 by Examiner Two: wrong door", page)
        self.assertIn(b"(3 entries)", page)

    def test_bad_notes_and_tokens_are_rejected(self):
        case_id, folder = self.open_case()
        status, page = self.post("/case/note", {"case": case_id, "event_id": "nope", "text": "x"})
        self.assertEqual(status, 400)
        self.assertIn(b"no timeline row with event ID", page)
        status, page = self.post("/case/note", {"case": "../x", "event_id": "b-1", "text": "x"})
        self.assertEqual(status, 404)
        body = urlencode({"csrf_token": "wrong", "case": case_id, "event_id": "b-1", "text": "x"})
        status, _, _ = self.request("POST", "/case/note", body, {"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(status, 403)
        self.assertEqual(len(self.log(folder)), 1)

    def test_downloads_are_logged_and_delete_archives_the_log(self):
        case_id, folder = self.open_case()
        self.request("GET", f"/report.json?case={case_id}")
        entry = self.log(folder)[-1]
        self.assertEqual((entry["action"], entry["details"]["file"]), ("report_downloaded", "report.json"))
        self.post("/case/delete", {"case": case_id})
        archived = list((self.root / "derived" / "web" / "_deleted").glob(f"{case_id}-*.custody.jsonl"))
        self.assertEqual(len(archived), 1)
        actions = [json.loads(line)["action"] for line in archived[0].read_text(encoding="utf-8").splitlines()]
        self.assertEqual(actions, ["analysis", "report_downloaded", "case_deleted"])
        self.assertEqual(self.case_ids(), [])


if __name__ == "__main__":
    unittest.main()
