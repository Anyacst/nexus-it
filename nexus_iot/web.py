"""Loopback-only browser interface for analyzing user-selected evidence folders."""
from __future__ import annotations
from datetime import datetime, timezone
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs
import json
import hashlib
import ipaddress
import secrets
import threading
from urllib.parse import urlsplit

from .pipeline import analyze

PAGE = """<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>NEXUS-IoT</title>
<style>body{font:16px system-ui;max-width:1180px;margin:2rem auto;padding:0 1rem;color:#18212b;background:#f5f7fa}h1{margin-bottom:.2rem}.muted{color:#536273}.card{background:white;padding:1rem 1.3rem;border-radius:10px;margin:1rem 0;box-shadow:0 2px 12px #16263812}input{padding:.7rem;width:min(700px,90%)}button{padding:.7rem 1.3rem;background:#174c76;color:white;border:0;border-radius:6px}table{width:100%;border-collapse:collapse;font-size:.9rem}th,td{text-align:left;padding:.55rem;border-bottom:1px solid #ddd;vertical-align:top}th{background:#eff3f7}.label{font-weight:700}.Confirmed{color:#16734b}.Single-source{color:#795400}.Inferred{color:#6941a5}.Unknown{color:#9a3c32}.issue{padding:.35rem 0}.scroll{overflow:auto}code{overflow-wrap:anywhere}</style></head><body><h1>NEXUS-IoT</h1><div class=muted>Local evidence reconstruction · files are read only · no network/device collection</div>
<div class=card><h2>Analyze a case folder</h2><p>Enter the full path to a folder containing device JSONL logs and/or supplied PCAP/PCAPNG captures. Reports go to the project’s derived folder.</p><form method=post action=/analyze><input type=hidden name=csrf_token value='{csrf_token}'><input name=evidence required placeholder='Full path to evidence folder'><p><button>Analyze evidence</button></p></form></div>{content}</body></html>"""

def _timeline_html(report: dict) -> str:
    content=["<div class=card><h2>Validation findings</h2>"]
    if report["validation_issues"]:
        content += [f"<div class=issue>• {escape(x)}</div>" for x in report["validation_issues"]]
    else: content.append("<p>No validation findings.</p>")
    content.append("</div><div class=card><h2>Clock estimates</h2><div class=scroll><table><tr><th>Source</th><th>Offset</th><th>Drift</th><th>Uncertainty</th><th>Anchors</th><th>Applied</th></tr>")
    for s,x in report["clock_estimates"].items():
        unc="unknown" if x["uncertainty_seconds"] is None else f"±{x['uncertainty_seconds']:.3f}s"
        content.append(f"<tr><td>{escape(s)}</td><td>{x['offset_seconds']:+.3f}s</td><td>{x['drift_ppm']:+.3f} ppm</td><td>{unc}</td><td>{x['anchor_count']}</td><td>{x['applied']}</td></tr>")
    content.append("</table></div></div><div class=card><h2>Reconstructed timeline</h2><div class=scroll><table><tr><th>UTC timestamp / range</th><th>Event</th><th>Source</th><th>Label</th><th>Evidence and uncertainty</th></tr>")
    for e in report["timeline"]:
        label=e["label"]
        evidence="; ".join(e["supporting_evidence"])
        try:
            if e["time_range"] is None:
                ts=f"{datetime.fromtimestamp(e['timestamp'],timezone.utc).isoformat()} (uncalibrated; {e['time_basis']})"
            else:
                a,b=e["time_range"]
                ts=datetime.fromtimestamp(a,timezone.utc).isoformat() if a==b else f"{datetime.fromtimestamp(a,timezone.utc).isoformat()} – {datetime.fromtimestamp(b,timezone.utc).isoformat()}"
                if e.get("time_basis") not in {"gateway-clock-assumed","device-clock-calibrated-to-gateway"}:
                    ts+=f" [{e.get('time_basis','time basis unknown')}]"
        except (ValueError,OverflowError,OSError):ts=f"{e['timestamp']:.3f} ({e['time_basis']})"
        content.append(f"<tr><td>{escape(ts)}</td><td>{escape(e['event'])}</td><td>{escape(e['device_or_source'])}</td><td class='label {escape(label)}'>{escape(label)}</td><td>{escape(evidence)}<br><span class=muted>{escape(e['confidence_or_uncertainty'])}</span></td></tr>")
    content.append("</table></div><p>JSON: <a href='/report.json'>report.json</a> · Markdown: <a href='/report.md'>report.md</a></p></div>")
    return "".join(content)

def create_server(host: str="127.0.0.1", port: int=8765, project_root: Path|None=None) -> ThreadingHTTPServer:
    if host!="localhost":
        try: loopback=ipaddress.ip_address(host).is_loopback
        except ValueError: loopback=False
        if not loopback: raise ValueError("browser interface must bind to a loopback address")
    root=(project_root or Path.cwd()).resolve(); derived=(root/"derived"/"web").resolve()
    state={"active":None,"csrf":secrets.token_urlsafe(32),"lock":threading.Lock()}
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args): pass
        def send(self, body: bytes, content_type: str, status: int=200):
            self.send_response(status);self.send_header("Content-Type",content_type);self.send_header("X-Content-Type-Options","nosniff");self.send_header("Content-Security-Policy","default-src 'self'; form-action 'self'; frame-ancestors 'none'");self.send_header("Cache-Control","no-store");self.end_headers();self.wfile.write(body)
        def local_request(self):
            try:
                if not ipaddress.ip_address(self.client_address[0]).is_loopback:return False
            except ValueError:return False
            allowed={"localhost","127.0.0.1","::1"}
            hostname=(urlsplit("//"+self.headers.get("Host","")).hostname or "").lower()
            if hostname not in allowed:return False
            origin=self.headers.get("Origin")
            return not origin or (urlsplit(origin).hostname or "").lower() in allowed
        def do_GET(self):
            if not self.local_request():return self.send(b"Local requests only","text/plain",403)
            if self.path=="/report.json" or self.path=="/report.md":
                with state["lock"]:active=state["active"]
                if active is None: return self.send(b"No report yet", "text/plain",404)
                p=active/ self.path.rsplit("/",1)[1]
                return self.send(p.read_bytes(),"application/json; charset=utf-8" if p.suffix==".json" else "text/markdown; charset=utf-8")
            with state["lock"]:active=state["active"]
            content=_timeline_html(json.loads((active / "report.json").read_text(encoding="utf-8"))) if active else ""
            return self.send(PAGE.replace("{content}",content).replace("{csrf_token}",state["csrf"]).encode(),"text/html; charset=utf-8")
        def do_POST(self):
            if not self.local_request(): return self.send(b"Local requests only","text/plain",403)
            if self.path!="/analyze": return self.send(b"Not found","text/plain",404)
            try:
                size=int(self.headers.get("Content-Length","0"))
                if size>8192: raise ValueError("request too large")
                fields=parse_qs(self.rfile.read(size).decode("utf-8"))
                if not secrets.compare_digest(fields.get("csrf_token",[""])[0],state["csrf"]):return self.send(b"Invalid request token","text/plain",403)
                raw=fields.get("evidence",[""])[0].strip()
                evidence=Path(raw).expanduser().resolve()
                if not evidence.is_dir(): raise ValueError("Evidence path is not an existing directory")
                case_key=hashlib.sha256(str(evidence).encode("utf-8")).hexdigest()[:20]
                out=derived/case_key
                report=analyze(evidence,out)
                with state["lock"]:state["active"]=out
                body=PAGE.replace("{content}",_timeline_html(report)).replace("{csrf_token}",state["csrf"]).encode("utf-8")
                self.send(body,"text/html; charset=utf-8")
            except Exception as e:
                self.send(PAGE.replace("{content}",f"<div class=card><b>Could not analyze evidence:</b> {escape(str(e))}</div>").replace("{csrf_token}",state["csrf"]).encode(),"text/html; charset=utf-8",400)
    return ThreadingHTTPServer((host,port),Handler)

def serve(host: str="127.0.0.1", port: int=8765, project_root: Path|None=None) -> None:
    server=create_server(host,port,project_root)
    print(f"NEXUS-IoT local viewer: http://{host}:{port} (Ctrl+C to stop)",flush=True)
    try: server.serve_forever()
    except KeyboardInterrupt: pass
    finally: server.server_close()
