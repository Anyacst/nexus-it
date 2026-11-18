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


class WebUiTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
