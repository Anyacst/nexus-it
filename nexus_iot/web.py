"""Loopback-only browser interface for analyzing user-selected evidence folders and managing cases.

Security model (unchanged from earlier versions): the server binds only to a
loopback address, rejects requests whose peer, ``Host`` or ``Origin`` is not
local, protects every POST form with a CSRF token, and sends a strict CSP.
The page uses no JavaScript; the stylesheet is allowed through a per-response
CSP nonce, and filtering is done server side from GET query parameters.

Cases: each analyzed evidence folder is one case, stored under
``derived/web/<case id>/`` with its reports and a ``case.json`` holding the
examiner's metadata, and a hash-chained ``custody.jsonl`` that records every
analysis, examiner note, note retraction and report download. The case id is
derived from the evidence path, so re-analyzing the same folder updates the
same case and compares its hashes with the previous run. Deleting a case
removes only its derived outputs (its custody log is archived under
``derived/web/_deleted/`` first); the evidence folder is never written to.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import secrets
import shutil
import threading
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

from .custody import CUSTODY_FILE, add_note, append_entry, custody_view, retract_note
from .pipeline import analyze, utc_now
from .report_html import ReportView, css_sha256, render_document, render_report, render_report_body, safe_filename

MAX_FILTER_LENGTH = 200
"""Maximum accepted length (characters) of the device and free-text filter values."""

MAX_LABEL_LENGTH = 64
"""Maximum accepted length (characters) of the label filter value."""

MAX_QUERY_STRING = 2048
"""Maximum accepted length of the raw GET query string."""

MAX_CASE_FIELD = 200
"""Maximum accepted length of case name, case number and examiner."""

CASE_ID = re.compile(r"[0-9a-f]{20}")
"""Case ids are the first 20 hex digits of the SHA-256 of the resolved evidence path."""

APP_TITLE = "NEXUS-IoT"

BANNER_HTML = (
    "<div class=no-print><h1><a href='/cases'>NEXUS-IoT</a></h1><div class=muted>Local evidence reconstruction · "
    "files are read only · no network/device collection</div></div>"
)

ARTIFACTS = ("report.html", "report.json", "report.md")


def _e(value) -> str:
    """Escape a value for HTML text or a single- or double-quoted attribute."""
    return escape(str(value), quote=True)


def _clean_param(values: list[str] | None, limit: int) -> str:
    """Return the first value of a query parameter, stripped of control characters and capped at ``limit``."""
    if not values:
        return ""
    text = "".join(ch for ch in values[0] if ch.isprintable())
    return text.strip()[:limit]


def _query_fields(query: str) -> dict[str, list[str]]:
    """Parse a GET query string, ignoring oversized ones."""
    if len(query) > MAX_QUERY_STRING:
        query = ""
    return parse_qs(query, keep_blank_values=False, max_num_fields=10)


def case_links(case_id: str | None) -> list[tuple[str, str]]:
    """Download links for a case's report files."""
    suffix = "?" + urlencode({"case": case_id}) if case_id else ""
    return [(name, f"/{name}{suffix}") for name in ARTIFACTS]


def parse_filters(query: str, case_id: str | None = None) -> ReportView:
    """Parse and validate ``device``, ``label`` and ``q`` filters from a raw query string."""
    fields = _query_fields(query)
    return ReportView(
        device=_clean_param(fields.get("device"), MAX_FILTER_LENGTH),
        label=_clean_param(fields.get("label"), MAX_LABEL_LENGTH),
        query=_clean_param(fields.get("q"), MAX_FILTER_LENGTH),
        base_path="/",
        links=case_links(case_id),
        hidden={"case": case_id} if case_id else {},
    )


def case_id_for(evidence: Path) -> str:
    """Return the case id for a resolved evidence folder."""
    return hashlib.sha256(str(evidence).encode("utf-8")).hexdigest()[:20]


def case_info(case: dict) -> dict[str, str]:
    """HTML report header fields for a case."""
    names = {"name": "Case name", "case_number": "Case number", "examiner": "Examiner"}
    return {label: str(case[key]) for key, label in names.items() if case.get(key)}


def load_case(derived: Path, case_id: str) -> dict | None:
    """Return a case's metadata, or None if the id is malformed or the case has no report.

    Case folders written before case management existed have no ``case.json``;
    their metadata is rebuilt from ``report.json``.
    """
    if not CASE_ID.fullmatch(case_id or ""):
        return None
    folder = derived / case_id
    if not (folder / "report.json").is_file():
        return None
    try:
        case = json.loads((folder / "case.json").read_text(encoding="utf-8"))
        if not isinstance(case, dict):
            raise ValueError
    except (OSError, ValueError):
        try:
            report = json.loads((folder / "report.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            report = {}
        evidence = str(report.get("evidence_directory", "")) if isinstance(report, dict) else ""
        case = {"evidence": evidence, "name": Path(evidence).name or case_id, "updated_at": report.get("created_at", "")
                if isinstance(report, dict) else ""}
    case["id"] = case_id
    return case


def list_cases(derived: Path) -> list[dict]:
    """Return every saved case, most recently analyzed first."""
    if not derived.is_dir():
        return []
    cases = [load_case(derived, child.name) for child in derived.iterdir() if child.is_dir()]
    return sorted((c for c in cases if c), key=lambda c: str(c.get("updated_at", "")), reverse=True)


def save_case(derived: Path, evidence: Path, fields: dict, report: dict, rules: Path | None) -> dict:
    """Write or update ``case.json`` for an analyzed case and return its metadata."""
    case_id = case_id_for(evidence)
    folder = derived / case_id
    previous = load_case(derived, case_id) or {}
    now = utc_now()
    case = {
        "id": case_id,
        "name": fields.get("name") or previous.get("name") or evidence.name,
        "case_number": fields.get("case_number", ""),
        "examiner": fields.get("examiner", ""),
        "evidence": str(evidence),
        "rules": str(rules) if rules else "",
        "created_at": previous.get("created_at") or now,
        "updated_at": now,
        "analysis_count": int(previous.get("analysis_count", 0) or 0) + 1,
        "timeline_rows": len(report.get("timeline", [])),
        "validation_issues": len(report.get("validation_issues", [])),
        "rule_findings": len(report["rule_findings"]) if "rule_findings" in report else None,
    }
    (folder / "case.json").write_text(json.dumps(case, indent=2, ensure_ascii=False), encoding="utf-8")
    return case


def analyze_form(csrf_token: str, case: dict | None = None) -> str:
    """The new-case form, or (with ``case``) the re-analyze form pre-filled from that case."""
    case = case or {}
    title = "Re-analyze this case" if case else "Analyze a case folder"
    intro = ("Runs the analysis again on the same folder. File hashes are compared with the previous run, so any change "
             "to the evidence since then is reported." if case else
             "Enter the full path to a folder containing device JSONL logs and/or supplied PCAP/PCAPNG captures. "
             "Reports go to the project’s derived folder; the evidence folder is only read.")
    evidence_field = (f"<input type=hidden name=evidence value='{_e(case['evidence'])}'>" if case else
                      "<label class=wide>Evidence folder<input class=wide name=evidence required "
                      "placeholder='Full path to evidence folder'></label>")

    def text(name: str, label: str, placeholder: str = "") -> str:
        return (f"<label>{_e(label)}<input name={name} maxlength={MAX_CASE_FIELD} value='{_e(case.get(name, ''))}' "
                f"placeholder='{_e(placeholder)}'></label>")

    return (
        f"<div class='card no-print'><h2>{title}</h2><p class=small>{intro}</p>"
        f"<form method=post action=/analyze><input type=hidden name=csrf_token value='{_e(csrf_token)}'>{evidence_field}"
        "<div class=filters>"
        f"{text('name', 'Case name', 'defaults to the folder name')}{text('case_number', 'Case number')}"
        f"{text('examiner', 'Examiner')}{text('rules', 'Rules file (optional)', 'e.g. rules/smart_home.json')}"
        f"</div><p><button>{'Re-analyze' if case else 'Analyze evidence'}</button></p></form></div>"
    )


def cases_table(cases: list[dict], active: str | None) -> str:
    """Render the saved-case list."""
    if not cases:
        return "<div class='card no-print' id=cases><h2>Cases</h2><p class=muted>No cases yet.</p></div>"
    rows = []
    for c in cases:
        findings = c.get("rule_findings")
        mark = " <span class=muted>(open)</span>" if c["id"] == active else ""
        rows.append(
            f"<tr><td><a href='/?{_e(urlencode({'case': c['id']}))}'>{_e(c.get('name') or c['id'])}</a>{mark}</td>"
            f"<td>{_e(c.get('case_number', ''))}</td><td>{_e(c.get('examiner', ''))}</td>"
            f"<td><code>{_e(c.get('evidence', ''))}</code></td><td class=time>{_e(c.get('updated_at', ''))}</td>"
            f"<td class=num>{_e(c.get('timeline_rows', ''))}</td><td class=num>{_e(c.get('validation_issues', ''))}</td>"
            f"<td class=num>{'–' if findings is None else _e(findings)}</td></tr>"
        )
    return (
        "<div class='card no-print' id=cases><h2>Cases</h2><div class=scroll><table><thead><tr><th>Case</th><th>Number</th>"
        "<th>Examiner</th><th>Evidence folder</th><th>Last analyzed (UTC)</th><th>Rows</th><th>Validation findings</th>"
        f"<th>Rule findings</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div></div>"
    )


def case_toolbar(csrf_token: str, case: dict) -> str:
    """Case header shown above an open report: metadata, re-analyze form and delete button."""
    details = [("Evidence folder", case.get("evidence", "")), ("Rules file", case.get("rules") or "none"),
               ("First analyzed", case.get("created_at", "")), ("Last analyzed", case.get("updated_at", "")),
               ("Analyses run", case.get("analysis_count", ""))]
    items = "".join(f"<dt>{_e(k)}</dt><dd>{_e(v)}</dd>" for k, v in details if v != "")
    check = case.get("custody_check")
    if check is not None:
        state = ("<span class=ok>verified</span>" if check["ok"] else
                 "<span class=bad>FAILED</span> — " + _e("; ".join(check["issues"][:3])))
        items += f"<dt>Chain of custody</dt><dd>{state} ({check['entries']} entries) · <a href='#custody'>view log</a></dd>"
    delete = (
        "<form method=post action=/case/delete><input type=hidden name=csrf_token value='{token}'>"
        "<input type=hidden name=case value='{case}'><button class=secondary>Delete case outputs</button> "
        "<span class='muted small'>Removes this case’s reports from the derived folder; the evidence is not touched.</span></form>"
    ).format(token=_e(csrf_token), case=_e(case["id"]))
    return (
        f"<div class='card no-print'><p class=small><a href='/cases'>All cases</a></p><h2>{_e(case.get('name') or case['id'])}</h2>"
        f"<dl class=meta>{items}</dl></div>{analyze_form(csrf_token, case)}<div class='card no-print'>{delete}</div>"
    )


def page_html(csrf_token: str, nonce: str, report: dict | None = None, view: ReportView | None = None,
              message_html: str = "", case: dict | None = None, cases: list[dict] | None = None,
              custody: dict | None = None) -> str:
    """Build the full web page: banner, message, then either an open case or the case list and new-case form."""
    if report is not None:
        top = case_toolbar(csrf_token, case) if case else analyze_form(csrf_token)
        content = render_report_body(report, title="Incident timeline report", case_info=case_info(case or {}),
                                     view=view or ReportView(links=case_links(None)), custody=custody)
        body = BANNER_HTML + message_html + top + content
    else:
        body = BANNER_HTML + message_html + analyze_form(csrf_token) + cases_table(cases or [], None)
    return render_document(APP_TITLE, body, nonce=nonce)


def write_html_report(report: dict, output_dir: Path, case: dict | None = None) -> Path:
    """Write the static ``report.html`` (with notes and custody log) into ``output_dir`` and return its path."""
    path = output_dir / "report.html"
    path.write_text(render_report(report, case_info=case_info(case or {}), custody=custody_view(output_dir)),
                    encoding="utf-8")
    return path


def create_server(host: str = "127.0.0.1", port: int = 8765, project_root: Path | None = None) -> ThreadingHTTPServer:
    """Create (but do not start) the loopback-only HTTP server."""
    if host != "localhost":
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = False
        if not loopback:
            raise ValueError("browser interface must bind to a loopback address")
    root = (project_root or Path.cwd()).resolve()
    derived = (root / "derived" / "web").resolve()
    state = {"active": None, "csrf": secrets.token_urlsafe(32), "lock": threading.Lock()}

    class Handler(BaseHTTPRequestHandler):
        """Request handler bound to this server's state."""

        def log_message(self, fmt, *args):
            pass

        def send(self, body: bytes, content_type: str, status: int = 200, *, nonce: str | None = None,
                 csp: str | None = None, extra_headers: dict[str, str] | None = None) -> None:
            """Send a complete response with the standard security headers."""
            if csp is None:
                style = f"; style-src 'nonce-{nonce}'" if nonce else ""
                csp = f"default-src 'self'{style}; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", csp)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            for name, value in (extra_headers or {}).items():
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def send_page(self, status: int = 200, report: dict | None = None, view: ReportView | None = None,
                      message_html: str = "", case: dict | None = None) -> None:
            """Render and send a page with a fresh style nonce (the case list when no report is given)."""
            nonce = secrets.token_urlsafe(16)
            cases = list_cases(derived) if report is None else None
            custody = None
            if report is not None and case is not None:
                custody = custody_view(derived / case["id"])
                case = {**case, "custody_check": custody["verification"] if custody else None}
                if view is not None:
                    view.csrf_token = state["csrf"]
            html = page_html(state["csrf"], nonce, report, view, message_html, case, cases, custody)
            self.send(html.encode("utf-8"), "text/html; charset=utf-8", status, nonce=nonce)

        def local_request(self) -> bool:
            """Return True only for loopback peers with a local Host and (if present) local Origin."""
            try:
                if not ipaddress.ip_address(self.client_address[0]).is_loopback:
                    return False
            except ValueError:
                return False
            allowed = {"localhost", "127.0.0.1", "::1"}
            hostname = (urlsplit("//" + self.headers.get("Host", "")).hostname or "").lower()
            if hostname not in allowed:
                return False
            origin = self.headers.get("Origin")
            return not origin or (urlsplit(origin).hostname or "").lower() in allowed

        def selected_case(self, query: str) -> tuple[str | None, bool]:
            """Return (case id, ok): the ``case`` query parameter if given, else the last opened case."""
            requested = _clean_param(_query_fields(query).get("case"), 64)
            if requested:
                if load_case(derived, requested) is None:
                    return None, False
                with state["lock"]:
                    state["active"] = requested
                return requested, True
            with state["lock"]:
                active = state["active"]
            if active and load_case(derived, active) is None:
                active = None
            return active, True

        def do_GET(self):
            if not self.local_request():
                return self.send(b"Local requests only", "text/plain", 403)
            parts = urlsplit(self.path)
            path = parts.path
            if path in {f"/{name}" for name in ARTIFACTS}:
                return self.send_artifact(path[1:], parts.query)
            if path == "/cases":
                return self.send_page()
            if path not in {"/", "/analyze"}:
                return self.send(b"Not found", "text/plain", 404)
            case_id, ok = self.selected_case(parts.query)
            if not ok:
                return self.send_page(404, message_html="<div class=card><b>Case not found.</b></div>")
            if case_id is None:
                return self.send_page()
            try:
                report = json.loads((derived / case_id / "report.json").read_text(encoding="utf-8"))
            except (OSError, ValueError) as e:
                return self.send_page(500, message_html=f"<div class=card><b>Could not load report:</b> {_e(e)}</div>")
            return self.send_page(report=report, view=parse_filters(parts.query, case_id), case=load_case(derived, case_id))

        def send_artifact(self, name: str, query: str) -> None:
            """Serve report.json, report.md or report.html for the selected (or last opened) case."""
            case_id, ok = self.selected_case(query)
            if not ok or case_id is None:
                return self.send(b"No report yet", "text/plain", 404)
            folder = derived / case_id
            target = folder / name
            if name == "report.html" and not target.is_file():
                try:
                    write_html_report(json.loads((folder / "report.json").read_text(encoding="utf-8")), folder,
                                      load_case(derived, case_id))
                except (OSError, ValueError):
                    return self.send(b"Report file not found", "text/plain", 404)
            try:
                body = target.read_bytes()
            except OSError:
                return self.send(b"Report file not found", "text/plain", 404)
            if (folder / CUSTODY_FILE).exists():
                try:
                    append_entry(folder, "report_downloaded", {"file": name, "sha256": hashlib.sha256(body).hexdigest()},
                                 (load_case(derived, case_id) or {}).get("examiner", ""))
                except ValueError:
                    pass  # a damaged log is reported on the case page; the download itself still works
            if name == "report.html":
                download = f"nexus-iot-report-{safe_filename(case_id)}.html"
                csp = (f"default-src 'none'; style-src {css_sha256()}; img-src data:; form-action 'none'; "
                       "frame-ancestors 'none'; base-uri 'none'")
                return self.send(body, "text/html; charset=utf-8", csp=csp,
                                 extra_headers={"Content-Disposition": f'attachment; filename="{download}"'})
            content_type = "application/json; charset=utf-8" if name.endswith(".json") else "text/markdown; charset=utf-8"
            return self.send(body, content_type)

        def read_form(self) -> dict[str, list[str]] | None:
            """Read a small urlencoded POST body; return None (after replying 403) if the CSRF token is wrong."""
            size = int(self.headers.get("Content-Length", "0"))
            if size < 0 or size > 8192:
                raise ValueError("request too large")
            fields = parse_qs(self.rfile.read(size).decode("utf-8"))
            if not secrets.compare_digest(fields.get("csrf_token", [""])[0], state["csrf"]):
                self.send(b"Invalid request token", "text/plain", 403)
                return None
            return fields

        def do_POST(self):
            if not self.local_request():
                return self.send(b"Local requests only", "text/plain", 403)
            path = urlsplit(self.path).path
            if path not in {"/analyze", "/case/delete", "/case/note", "/case/note/retract"}:
                return self.send(b"Not found", "text/plain", 404)
            try:
                fields = self.read_form()
                if fields is None:
                    return None
                if path == "/case/delete":
                    return self.delete_case(fields)
                if path in {"/case/note", "/case/note/retract"}:
                    return self.note(path, fields)
                raw = fields.get("evidence", [""])[0].strip()
                evidence = Path(raw).expanduser().resolve()
                if not raw or not evidence.is_dir():
                    raise ValueError("Evidence path is not an existing directory")
                meta = {key: _clean_param(fields.get(key), MAX_CASE_FIELD) for key in ("name", "case_number", "examiner")}
                rules_raw = _clean_param(fields.get("rules"), 1024)
                rules = None
                if rules_raw:
                    rules = Path(rules_raw).expanduser()
                    rules = (rules if rules.is_absolute() else root / rules).resolve()
                    if not rules.is_file():
                        raise ValueError("Rules file does not exist")
                case_id = case_id_for(evidence)
                out = derived / case_id
                report = analyze(evidence, out, rules_path=rules, examiner=meta["examiner"], case_number=meta["case_number"])
                case = save_case(derived, evidence, meta, report, rules)
                write_html_report(report, out, case)
                with state["lock"]:
                    state["active"] = case_id
                self.send_page(report=report, view=parse_filters("", case_id), case=case)
            except Exception as e:
                self.send_page(400, message_html=f"<div class=card><b>Could not analyze evidence:</b> {_e(e)}</div>")

        def delete_case(self, fields: dict[str, list[str]]) -> None:
            """Remove one case's derived folder (never the evidence) and show the case list."""
            case_id = fields.get("case", [""])[0]
            case = load_case(derived, case_id)
            folder = derived / case_id
            if case is None or folder.parent != derived or folder.is_symlink():
                return self.send_page(404, message_html="<div class=card><b>Case not found.</b></div>")
            if (folder / CUSTODY_FILE).exists():
                try:
                    append_entry(folder, "case_deleted", {"case_id": case_id, "evidence_directory": case.get("evidence", "")},
                                 case.get("examiner", ""))
                except ValueError:
                    pass  # archive the damaged log as it is
                archive = derived / "_deleted"
                archive.mkdir(exist_ok=True)
                stamp = utc_now().replace(":", "").replace("-", "").split(".")[0]
                shutil.copy2(folder / CUSTODY_FILE, archive / f"{case_id}-{stamp}.custody.jsonl")
            shutil.rmtree(folder)
            with state["lock"]:
                if state["active"] == case_id:
                    state["active"] = None
            name = case.get("name") or case_id
            self.send_page(message_html=f"<div class='card note'>Deleted the derived outputs of case <b>{_e(name)}</b>. "
                                        "The evidence folder was not changed; the custody log was archived in "
                                        "derived/web/_deleted/.</div>")

        def note(self, path: str, fields: dict[str, list[str]]) -> None:
            """Add or retract an examiner note, refresh report.html, then redirect back to the case."""
            case_id = fields.get("case", [""])[0]
            case = load_case(derived, case_id)
            if case is None:
                return self.send_page(404, message_html="<div class=card><b>Case not found.</b></div>")
            folder = derived / case_id
            examiner = _clean_param(fields.get("examiner"), MAX_CASE_FIELD) or case.get("examiner", "")
            try:
                if path == "/case/note":
                    event_id = fields.get("event_id", [""])[0]
                    add_note(folder, event_id, fields.get("text", [""])[0], examiner)
                else:
                    seq = int(fields.get("note_seq", ["0"])[0])
                    event_id = retract_note(folder, seq, fields.get("reason", [""])[0], examiner)["details"]["event_id"]
                report = json.loads((folder / "report.json").read_text(encoding="utf-8"))
            except (ValueError, OSError) as e:
                return self.send_page(400, message_html=f"<div class=card><b>Could not save the note:</b> {_e(e)}</div>")
            write_html_report(report, folder, case)
            index = next((i for i, r in enumerate(report.get("timeline", [])) if r.get("event_id") == event_id), None)
            location = "/?" + urlencode({"case": case_id}) + (f"#row-{index}" if index is not None else "")
            self.send_response(303)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()

    return ThreadingHTTPServer((host, port), Handler)


def serve(host: str = "127.0.0.1", port: int = 8765, project_root: Path | None = None) -> None:
    """Run the local browser interface until interrupted."""
    server = create_server(host, port, project_root)
    print(f"NEXUS-IoT local viewer: http://{host}:{port} (Ctrl+C to stop)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
