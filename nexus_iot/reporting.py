"""Report writing and detached HMAC signatures for evidence manifests."""
from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _write_reports(result: dict, output: Path) -> None:
    """Write report.json and the readable report.md into the output folder."""
    def md(value: Any) -> str:
        return str(value).replace("\r", " ").replace("\n", " ").replace("|", "\\|")
    output.mkdir(parents=True, exist_ok=True)
    (output/"report.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    rows = result["timeline"]
    lines = ["# NEXUS-IoT Incident Reconstruction", "", f"Created: {result['created_at']}", "", "## Evidence validation", ""]
    lines += [f"- {md(x)}" for x in result["validation_issues"]] or ["- No validation findings."]
    lines += ["", "## Clock estimates", "", "| Source | Offset (s) | Drift (ppm) | Uncertainty (s) | Anchors | Applied |", "|---|---:|---:|---:|---:|---|"]
    for source, x in result["clock_estimates"].items():
        unc = "unknown" if x["uncertainty_seconds"] is None else f"±{x['uncertainty_seconds']:.6f}"
        lines.append(f"| {md(source)} | {x['offset_seconds']:+.6f} | {x['drift_ppm']:+.3f} | {unc} | {x['anchor_count']} | {x['applied']} |")
    if not result["clock_estimates"]:
        lines.append("| No matched timestamp anchors | 0 | 0 | unknown | 0 | false |")
    lines += ["", "## Timeline", "", "| UTC time / range | Event | Device / source | Label | Supporting evidence | Confidence / uncertainty and limitations |", "|---|---|---|---|---|---|"]
    for e in rows:
        try:
            if e["time_range"] is None:
                time_text = f"{datetime.fromtimestamp(e['timestamp'],timezone.utc).isoformat()} (uncalibrated; {e['time_basis']})"
            else:
                a = datetime.fromtimestamp(e['time_range'][0], timezone.utc).isoformat()
                b = datetime.fromtimestamp(e['time_range'][1], timezone.utc).isoformat()
                time_text = a if a == b else f"{a} to {b}"
                if e.get("time_basis") not in {"gateway-clock-assumed", "device-clock-calibrated-to-gateway"}:
                    time_text += f" [{e.get('time_basis','time basis unknown')}]"
        except (ValueError, OverflowError, OSError):
            time_text = str(e['time_range'])
        lines.append(f"| {md(time_text)} | {md(e['event'])} | {md(e['device_or_source'])} | **{md(e['label'])}** | {md('; '.join(e['supporting_evidence']))} | {md(e['confidence_or_uncertainty'])} {md(e['limitations'])} |")
    lines += ["", "## Evidence manifest", "", "| File | Bytes | SHA-256 | Collected at |", "|---|---:|---|---|"]
    for x in result["evidence_manifest"]:
        lines.append(f"| {md(x['relative_path'])} | {x['bytes']} | `{x['sha256']}` | {md(x['collection_time'])} |")
    lines += ["", "## Interpretation limits", ""]+[f"- {md(x)}" for x in result["limitations"]]
    (output/"report.md").write_text("\n".join(lines)+"\n", encoding="utf-8")


def _manifest_bytes(manifest: list[dict]) -> bytes:
    """Serialise a manifest canonically (sorted keys, compact) for hashing and signing."""
    return json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign_manifest(manifest: list[dict], key_path: Path, signature_path: Path) -> dict:
    """Write a detached HMAC-SHA256 signature of the manifest using an external 32+ byte key."""
    try:
        key = key_path.read_bytes()
    except OSError as e:
        raise ValueError(f"cannot read manifest signing key: {e}") from e
    if len(key) < 32:
        raise ValueError("manifest signing key must contain at least 32 bytes")
    signature = {"algorithm":"HMAC-SHA256", "key_id":hashlib.sha256(key).hexdigest()[:16],
               "signature":hmac.new(key, _manifest_bytes(manifest), hashlib.sha256).hexdigest()}
    signature_path.write_text(json.dumps(signature, indent=2), encoding="utf-8")
    return signature


def verify_manifest(manifest_path: Path, signature_path: Path, key_path: Path) -> bool:
    """Return True if the detached signature matches the manifest under the given key."""
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        signature = json.loads(signature_path.read_text(encoding="utf-8"))
        key = key_path.read_bytes()
    except (OSError, json.JSONDecodeError) as e:
        raise ValueError(f"cannot read signed manifest material: {e}") from e
    if not isinstance(manifest, list) or not isinstance(signature, dict) or len(key) < 32:
        raise ValueError("invalid manifest/signature or signing key shorter than 32 bytes")
    expected = hmac.new(key, _manifest_bytes(manifest), hashlib.sha256).hexdigest()
    key_id = hashlib.sha256(key).hexdigest()[:16]
    return signature.get("algorithm") == "HMAC-SHA256" and hmac.compare_digest(signature.get("signature", ""), expected) and signature.get("key_id") == key_id
