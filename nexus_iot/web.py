"""Loopback-only browser interface for analyzing user-selected evidence folders.

Security model (unchanged from earlier versions): the server binds only to a
loopback address, rejects requests whose peer, ``Host`` or ``Origin`` is not
local, protects the analyze form with a CSRF token, and sends a strict CSP.
The page uses no JavaScript; the stylesheet is allowed through a per-response
CSP nonce, and filtering is done server side from GET query parameters.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import secrets
import threading
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .pipeline import analyze
from .report_html import ReportView, css_sha256, render_document, render_report, render_report_body, safe_filename

MAX_FILTER_LENGTH = 200
"""Maximum accepted length (characters) of the device and free-text filter values."""

MAX_LABEL_LENGTH = 64
"""Maximum accepted length (characters) of the label filter value."""

MAX_QUERY_STRING = 2048
"""Maximum accepted length of the raw GET query string."""

APP_TITLE = "NEXUS-IoT"

FORM_HTML = (
    "<div class='card no-print'><h2>Analyze a case folder</h2><p>Enter the full path to a folder containing device JSONL logs "
    "and/or supplied PCAP/PCAPNG captures. Reports go to the project’s derived folder.</p>"
    "<form method=post action=/analyze><input type=hidden name=csrf_token value='{csrf_token}'>"
    "<input class=wide name=evidence required placeholder='Full path to evidence folder'>"
    "<p><button>Analyze evidence</button></p></form></div>"
)
"""Analyze form. ``{csrf_token}`` is replaced with the server's URL-safe token."""

BANNER_HTML = (
    "<div class=no-print><h1>NEXUS-IoT</h1><div class=muted>Local evidence reconstruction · files are read only · "
    "no network/device collection</div></div>"
)

DOWNLOAD_LINKS = [("report.html", "/report.html"), ("report.json", "/report.json"), ("report.md", "/report.md")]


def _clean_param(values: list[str] | None, limit: int) -> str:
    """Return the first value of a query parameter, stripped of control characters and capped at ``limit``."""
    if not values:
        return ""
    text = "".join(ch for ch in values[0] if ch.isprintable())
    return text.strip()[:limit]


def parse_filters(query: str) -> ReportView:
    """Parse and validate ``device``, ``label`` and ``q`` filters from a raw query string."""
    if len(query) > MAX_QUERY_STRING:
        query = ""
    fields = parse_qs(query, keep_blank_values=False, max_num_fields=10)
    return ReportView(
        device=_clean_param(fields.get("device"), MAX_FILTER_LENGTH),
        label=_clean_param(fields.get("label"), MAX_LABEL_LENGTH),
        query=_clean_param(fields.get("q"), MAX_FILTER_LENGTH),
        base_path="/",
        links=list(DOWNLOAD_LINKS),
    )


def page_html(csrf_token: str, nonce: str, report: dict | None = None, view: ReportView | None = None,
              message_html: str = "") -> str:
    """Build the full web page: banner, analyze form, optional message and optional interactive report."""
    form = FORM_HTML.replace("{csrf_token}", csrf_token)
    content = ""
    if report is not None:
        content = render_report_body(report, title="Incident timeline report", view=view or ReportView(links=list(DOWNLOAD_LINKS)))
    return render_document(APP_TITLE, BANNER_HTML + form + message_html + content, nonce=nonce)


def write_html_report(report: dict, output_dir: Path) -> Path:
    """Write the static ``report.html`` for ``report`` into ``output_dir`` and return its path."""
    path = output_dir / "report.html"
    path.write_text(render_report(report), encoding="utf-8")
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
                      message_html: str = "") -> None:
            """Render and send the main page with a fresh style nonce."""
            nonce = secrets.token_urlsafe(16)
            html = page_html(state["csrf"], nonce, report, view, message_html)
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

        def active_case(self) -> Path | None:
            """Return the output folder of the most recently analyzed case, if any."""
            with state["lock"]:
                return state["active"]

        def do_GET(self):
            if not self.local_request():
                return self.send(b"Local requests only", "text/plain", 403)
            parts = urlsplit(self.path)
            path = parts.path
            if path in {"/report.json", "/report.md", "/report.html"}:
                return self.send_artifact(path.rsplit("/", 1)[1])
            if path not in {"/", "/analyze"}:
                return self.send(b"Not found", "text/plain", 404)
            active = self.active_case()
            if active is None:
                return self.send_page()
            try:
                report = json.loads((active / "report.json").read_text(encoding="utf-8"))
            except (OSError, ValueError) as e:
                return self.send_page(500, message_html=f"<div class=card><b>Could not load report:</b> {escape(str(e))}</div>")
            return self.send_page(report=report, view=parse_filters(parts.query))

        def send_artifact(self, name: str) -> None:
            """Serve report.json, report.md or report.html for the active case."""
            active = self.active_case()
            if active is None:
                return self.send(b"No report yet", "text/plain", 404)
            target = active / name
            if name == "report.html" and not target.is_file():
                try:
                    write_html_report(json.loads((active / "report.json").read_text(encoding="utf-8")), active)
                except (OSError, ValueError):
                    return self.send(b"Report file not found", "text/plain", 404)
            try:
                body = target.read_bytes()
            except OSError:
                return self.send(b"Report file not found", "text/plain", 404)
            if name == "report.html":
                download = f"nexus-iot-report-{safe_filename(active.name)}.html"
                csp = (f"default-src 'none'; style-src {css_sha256()}; img-src data:; form-action 'none'; "
                       "frame-ancestors 'none'; base-uri 'none'")
                return self.send(body, "text/html; charset=utf-8", csp=csp,
                                 extra_headers={"Content-Disposition": f'attachment; filename="{download}"'})
            content_type = "application/json; charset=utf-8" if name.endswith(".json") else "text/markdown; charset=utf-8"
            return self.send(body, content_type)

        def do_POST(self):
            if not self.local_request():
                return self.send(b"Local requests only", "text/plain", 403)
            if urlsplit(self.path).path != "/analyze":
                return self.send(b"Not found", "text/plain", 404)
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if size > 8192:
                    raise ValueError("request too large")
                fields = parse_qs(self.rfile.read(size).decode("utf-8"))
                if not secrets.compare_digest(fields.get("csrf_token", [""])[0], state["csrf"]):
                    return self.send(b"Invalid request token", "text/plain", 403)
                raw = fields.get("evidence", [""])[0].strip()
                evidence = Path(raw).expanduser().resolve()
                if not evidence.is_dir():
                    raise ValueError("Evidence path is not an existing directory")
                case_key = hashlib.sha256(str(evidence).encode("utf-8")).hexdigest()[:20]
                out = derived / case_key
                report = analyze(evidence, out)
                write_html_report(report, out)
                with state["lock"]:
                    state["active"] = out
                self.send_page(report=report, view=parse_filters(""))
            except Exception as e:
                self.send_page(400, message_html=f"<div class=card><b>Could not analyze evidence:</b> {escape(str(e))}</div>")

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
