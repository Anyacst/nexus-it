"""Evidence acquisition, validation, clock calibration, reconstruction, and reporting."""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import statistics
import time
import shutil
import tempfile
import os
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .capture import CaptureError, packets

SUPPORTED = {".jsonl", ".pcap", ".pcapng"}
VERSION = "1.0.0"
MAX_CLOCK_DRIFT_PPM = 1_000.0
MAX_CLOCK_RESIDUAL_SECONDS = 2.0


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_time(value: Any) -> float:
    """Accept Unix seconds or ISO-8601 with timezone; reject ambiguous naive strings."""
    if isinstance(value, bool): raise ValueError("boolean is not a timestamp")
    if isinstance(value, (int, float)):
        v = float(value)
        if not math.isfinite(v): raise ValueError("timestamp must be finite")
        return v
    if isinstance(value, str):
        try: dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as e: raise ValueError("expected Unix seconds or ISO-8601 timestamp") from e
        if dt.tzinfo is None: raise ValueError("ISO-8601 timestamp must include a timezone")
        return dt.astimezone(timezone.utc).timestamp()
    raise ValueError("timestamp must be numeric or ISO-8601 text")


def read_jsonl(path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    rows: list[dict[str, Any]] = []; errors: list[str] = []
    try:
        with path.open(encoding="utf-8-sig") as f:
            for n, raw in enumerate(f, 1):
                if not raw.strip(): continue
                try:
                    row = json.loads(raw)
                    if not isinstance(row, dict): raise ValueError("record must be a JSON object")
                    rows.append(row)
                except (json.JSONDecodeError, ValueError) as e:
                    errors.append(f"{path.name}:{n}: malformed JSON record ({e})")
    except (OSError, UnicodeError) as e:
        errors.append(f"{path.name}: cannot read text evidence ({e})")
    return rows, errors


def acquire(evidence_dir: Path, snapshot_dir: Path, previous: list[dict] | None = None) -> tuple[list[dict], list[str]]:
    """Snapshot inputs, hashing the exact copy later parsed by the pipeline."""
    prior = {x.get("relative_path"): x.get("sha256") for x in (previous or []) if isinstance(x,dict)}
    now = utc_now(); entries = []; findings = []
    files = sorted(p for p in evidence_dir.rglob("*") if p.is_file() and (p.suffix.lower() in SUPPORTED or p.name == "devices.json"))
    for path in files:
        rel = path.relative_to(evidence_dir).as_posix()
        snap=snapshot_dir/Path(rel);snap.parent.mkdir(parents=True,exist_ok=True)
        try:
            before=path.stat()
            with path.open("rb") as source, snap.open("wb") as target:
                opened_before=os.fstat(source.fileno())
                shutil.copyfileobj(source,target,1024*1024)
                opened_after=os.fstat(source.fileno())
            after=path.stat()
            stable=(before.st_size,before.st_mtime_ns,before.st_ino)==(after.st_size,after.st_mtime_ns,after.st_ino)==(opened_before.st_size,opened_before.st_mtime_ns,opened_before.st_ino)==(opened_after.st_size,opened_after.st_mtime_ns,opened_after.st_ino)
            hasher=hashlib.sha256()
            with snap.open("rb") as stream:
                for chunk in iter(lambda:stream.read(1024*1024),b""): hasher.update(chunk)
            digest=hasher.hexdigest()
        except OSError as e:
            findings.append(f"{rel}: could not snapshot/hash evidence ({e})")
            try: snap.unlink()
            except OSError: pass
            continue
        entries.append({"filename": path.name, "relative_path": rel, "source": path.parent.relative_to(evidence_dir).as_posix() or ".",
                        "collection_time": now, "sha256": digest, "bytes": snap.stat().st_size,"snapshot_stable":stable})
        if not stable: findings.append(f"{rel}: source metadata changed during snapshot; parsed snapshot may represent an unstable source")
        if rel in prior and prior[rel] != digest:
            findings.append(f"{rel}: SHA-256 differs from the prior project manifest; bytes changed since that recorded run")
    disappeared = sorted(set(prior) - {x["relative_path"] for x in entries})
    findings.extend(f"{name}: file present in prior manifest is now missing" for name in disappeared)
    return entries, findings


def _read_devices_config(root: Path) -> dict[str, Any]:
    p = root / "devices.json"
    if not p.exists(): return {}
    try:
        value = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(value, dict): raise ValueError("expected an object")
        return value
    except (OSError, json.JSONDecodeError, ValueError) as e:
        return {"_config_error": f"devices.json: invalid configuration ({e})"}


def _normalise_json_rows(path: Path, root: Path, errors: list[str]) -> list[dict]:
    records, errs = read_jsonl(path); errors.extend(errs); out = []
    gateway = path.name.lower().startswith("gateway")
    for n, row in enumerate(records, 1):
        try:
            timestamp = parse_time(row["timestamp"])
            event = row.get("event", row.get("type"))
            if not isinstance(event, str) or not event.strip(): raise ValueError("event must be non-empty text")
            device = "gateway" if gateway else row.get("device")
            if not gateway and (not isinstance(device, str) or not device.strip()): raise ValueError("device must be non-empty text")
            rel = path.relative_to(root).as_posix()
            out.append({"timestamp": timestamp, "raw_timestamp": row["timestamp"], "event": event.strip(),
                "device": device, "source_file": rel, "source_id": str(row.get("source_id") or rel), "record": n,
                "event_id": str(row.get("event_id") or "").strip(),
                "sequence": row.get("sequence"), "peer": str(row.get("peer") or ""),
                "metadata": {k: v for k, v in row.items() if k not in {"timestamp", "event", "type", "device", "source_id", "event_id", "sequence", "peer"}}})
        except (KeyError, TypeError, ValueError) as e:
            errors.append(f"{path.name}: record {n}: invalid evidence fields ({e})")
    return out


def _load_evidence(root: Path, errors: list[str]) -> list[dict]:
    out = []
    for path in sorted(p for p in root.rglob("*") if p.is_file() and p.suffix.lower() == ".jsonl"):
        out.extend(_normalise_json_rows(path, root, errors))
    for path in sorted(p for p in root.rglob("*") if p.is_file() and p.suffix.lower() in {".pcap", ".pcapng"}):
        try:
            for packet in packets(path,aggregate_seconds=1.0):
                packet.update({"raw_timestamp": packet["timestamp"], "device": "gateway", "source_file": path.relative_to(root).as_posix(),
                    "source_id": path.relative_to(root).as_posix(), "event_id": "", "sequence": None, "record": packet["packet"], "peer": ""})
                out.append(packet)
        except (OSError, CaptureError) as e:
            errors.append(f"{path.name}: capture parse failed ({e})")
    return out


def _sequence_number(e: dict) -> int | None:
    val = e.get("sequence")
    if val is not None:
        if isinstance(val,bool): return None
        if isinstance(val,int): return val
        if isinstance(val,str) and val.isdecimal(): return int(val)
        return None
    try: return int(e["event_id"].rsplit("-", 1)[1])
    except (IndexError, ValueError, KeyError): return None


def _offset_estimates(events: list[dict], issues: list[str], tolerance: float,
                      max_drift_ppm: float=MAX_CLOCK_DRIFT_PPM,
                      max_residual_seconds: float=MAX_CLOCK_RESIDUAL_SECONDS) -> dict[str, dict]:
    anchors: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        if e["event_id"]: anchors[e["event_id"]].append(e)
    deltas: dict[str, list[tuple[float,float]]] = defaultdict(list)
    for rows in anchors.values():
        for r in rows:
            if r["device"] == "gateway": continue
            gateways=[g for g in rows if g["device"]=="gateway" and g["event"]==r["event"] and (not g.get("peer") or g["peer"]==r["device"])]
            if not gateways: continue
            # Multiple gateway copies of one ID count as one anchor: use their median timestamp.
            gateway_time=statistics.median(g["timestamp"] for g in gateways)
            deltas[r["source_id"]].append((r["timestamp"],r["timestamp"]-gateway_time))
    estimates = {}
    def fit(samples):
        device_times=[x[0] for x in samples];raw_offsets=[x[1] for x in samples]
        reference=statistics.median(device_times);slopes=[]
        for i in range(len(samples)):
            for j in range(i+1,len(samples)):
                dt=device_times[j]-device_times[i]
                if dt:slopes.append((raw_offsets[j]-raw_offsets[i])/dt)
        drift=statistics.median(slopes) if len(samples)>=3 and slopes else 0.0
        center=statistics.median(offset-drift*(t-reference) for t,offset in samples)
        residuals=[offset-(center+drift*(t-reference)) for t,offset in samples]
        mad=statistics.median(abs(x-statistics.median(residuals)) for x in residuals)
        return {"offset_seconds":center,"drift_seconds_per_second":drift,"drift_ppm":drift*1_000_000,
            "reference_timestamp":reference,"uncertainty_seconds":max(tolerance,1.4826*mad),
            "anchor_count":len(samples),"residual_range_seconds":max(residuals)-min(residuals) if residuals else 0.0,
            "samples":samples}
    for source, samples in deltas.items():
        samples=sorted(samples);model=fit(samples)
        stable=(len(samples)>=3 and model["residual_range_seconds"]<=max(4*tolerance,max_residual_seconds) and abs(model["drift_ppm"])<=max_drift_ppm)
        segments=[]
        if not stable and len(samples)>=6:
            candidates=[]
            for split in range(3,len(samples)-2):
                left,right=fit(samples[:split]),fit(samples[split:])
                if all(m["residual_range_seconds"]<=max(4*tolerance,max_residual_seconds) and abs(m["drift_ppm"])<=max_drift_ppm for m in (left,right)):
                    candidates.append((max(left["residual_range_seconds"],right["residual_range_seconds"]),split,left,right))
            if candidates:
                _,split,left,right=min(candidates,key=lambda x:(x[0],abs((x[1]/len(samples))-.5)))
                segments=[{k:v for k,v in m.items() if k!="samples"} | {"start_device_timestamp":m["samples"][0][0],"end_device_timestamp":m["samples"][-1][0]} for m in (left,right)]
                stable=True
                issues.append(f"{source}: clock anchors do not fit a single stable model; step change detected and separate stable segments applied around an inferred boundary")
        estimates[source]={**{k:v for k,v in model.items() if k!="samples"},
            "uncertainty_seconds":model["uncertainty_seconds"] if stable else None,"max_drift_ppm":max_drift_ppm,
            "max_residual_seconds":max_residual_seconds,"applied":stable,"segments":segments}
        if len(samples)<3:
            issues.append(f"{source}: only {len(samples)} valid clock anchor(s); offset estimate is diagnostic and was not applied")
        elif not stable: issues.append(f"{source}: clock anchors do not fit an allowed stable model (residual range {model['residual_range_seconds']:.3f}s, drift {model['drift_ppm']:+.1f}ppm, limits ±{max_residual_seconds:.3f}s and ±{max_drift_ppm:.0f}ppm); correction was not applied; possible step change or manipulation")
    return estimates


def _event_time(e: dict, offsets: dict[str,dict], tolerance: float) -> tuple[float,float|None,str]:
    if e["device"]=="gateway": return e["timestamp"],tolerance,"gateway-clock-assumed"
    model=offsets.get(e["source_id"])
    if model and model.get("applied"):
        segments=model.get("segments",[])
        segment=next((s for s in segments if s["start_device_timestamp"]<=e["timestamp"]<=s["end_device_timestamp"]),None)
        if segment:
            offset=segment["offset_seconds"]+segment["drift_seconds_per_second"]*(e["timestamp"]-segment["reference_timestamp"])
            return e["timestamp"]-offset,segment["uncertainty_seconds"],"device-clock-piecewise-calibrated-to-gateway"
        if segments:
            nearest=min(segments,key=lambda s:min(abs(e["timestamp"]-s["start_device_timestamp"]),abs(e["timestamp"]-s["end_device_timestamp"])))
            offset=nearest["offset_seconds"]+nearest["drift_seconds_per_second"]*(e["timestamp"]-nearest["reference_timestamp"])
            return e["timestamp"]-offset,nearest["uncertainty_seconds"],"device-clock-piecewise-extrapolated-to-gateway"
        delta=e["timestamp"]-model["reference_timestamp"]
        offset=model["offset_seconds"]+model["drift_seconds_per_second"]*delta
        return e["timestamp"]-offset,model["uncertainty_seconds"],"device-clock-calibrated-to-gateway"
    return e["timestamp"],None,"device-clock-uncalibrated"


def _event_key(e: dict) -> str:
    return e["event_id"] or f"{e['source_id']}#record-{e['record']}"


def _capture_correlations(events: list[dict], config: dict, offsets: dict[str, dict], issues: list[str]) -> dict[str,list[dict]]:
    """Apply explicit flow rules; packet proximity without a rule never confirms an event."""
    rules=config.get("correlation_rules",[])
    if not isinstance(rules,list):
        issues.append("devices.json: correlation_rules must be a list")
        return {}
    captures=[e for e in events if e["event"]=="network_packet"]
    device_events=[e for e in events if e["device"]!="gateway" and e["event"]!="network_packet"]
    ips=config.get("device_ips",{})
    if not isinstance(ips,dict): ips={}
    mapping={}
    for device,values in ips.items():
        vals=[values] if isinstance(values,str) else values if isinstance(values,list) else []
        mapping[str(device)]={str(v) for v in vals}
    links: dict[str,list[dict]]=defaultdict(list)
    for i,rule in enumerate(rules):
        if not isinstance(rule,dict):
            issues.append(f"devices.json: correlation rule {i+1} must be an object");continue
        device,event,protocol=rule.get("device"),rule.get("event"),str(rule.get("protocol","")).lower()
        direction=rule.get("direction","either");window=rule.get("window_seconds",1.0)
        if not isinstance(device,str) or not isinstance(event,str) or protocol not in {"tcp","udp","icmp","icmpv6"}:
            issues.append(f"devices.json: correlation rule {i+1} requires device, event, and supported protocol");continue
        if direction not in {"inbound","outbound","either"} or isinstance(window,bool) or not isinstance(window,(int,float)) or not math.isfinite(window) or window<=0:
            issues.append(f"devices.json: correlation rule {i+1} has invalid direction/window_seconds");continue
        if any(rule.get(field) is not None and (isinstance(rule[field],bool) or not isinstance(rule[field],int) or not 0<=rule[field]<=65535) for field in ("source_port","destination_port")):
            issues.append(f"devices.json: correlation rule {i+1} has an invalid port");continue
        device_ips=mapping.get(device,set())
        if not device_ips:
            issues.append(f"devices.json: correlation rule {i+1} has no device_ips entry for {device}; it cannot attribute packets")
            continue
        rule_id=str(rule.get("id",f"rule-{i+1}"))
        for event_row in device_events:
            if event_row["device"]!=device or event_row["event"]!=event: continue
            offset=offsets.get(event_row["source_id"])
            manual_offset=rule.get("device_clock_offset_seconds")
            if offset and offset.get("applied"):
                event_time=_event_time(event_row,offsets,0.0)[0]
            elif isinstance(manual_offset,(int,float)) and not isinstance(manual_offset,bool) and math.isfinite(manual_offset):
                event_time=event_row["timestamp"]-manual_offset
            else:
                issues.append(f"{event_row['source_file']} record {event_row['record']}: correlation rule {rule_id} skipped because the device clock has no stable applied gateway calibration")
                continue
            candidates=[]
            for packet in captures:
                if packet.get("protocol")!=protocol or device not in packet.get("mapped_devices",[]):
                    continue
                src_is_device=packet.get("source_ip") in device_ips
                if (direction=="outbound" and not src_is_device) or (direction=="inbound" and src_is_device): continue
                if any(rule.get(field) is not None and packet.get(field)!=rule[field] for field in ("source_port","destination_port")): continue
                delta=max(packet.get("timestamp_start",packet["timestamp"])-event_time,0.0,
                          event_time-packet.get("timestamp_end",packet["timestamp"]))
                if delta<=float(window): candidates.append((delta,packet))
            if candidates:
                delta,packet=min(candidates,key=lambda x:x[0]);key=_event_key(event_row)
                support={"source_id":packet["source_id"],"display":f"{packet['source_file']} packet summary starting at {packet['record']} ({packet.get('packet_count',1)} packet(s)) matched configured rule {rule_id}; flow {packet.get('source_ip')}:{packet.get('source_port')} -> {packet.get('destination_ip')}:{packet.get('destination_port')} {protocol}; Δt={delta:.3f}s"}
                if all(x["source_id"]!=support["source_id"] for x in links[key]): links[key].append(support)
    return links


def _timeline(events: list[dict], offsets: dict[str, dict], issues: list[str], tolerance: float,
              capture_links: dict[str,list[dict]]|None=None) -> list[dict]:
    capture_links=capture_links or {}
    groups: dict[str, list[dict]] = defaultdict(list)
    for e in events: groups[_event_key(e)].append(e)
    result = []
    for key, rows in groups.items():
        if rows[0]["event"] in {"network_packet", "unsupported_link_packet"}: continue
        names = sorted(set(r["event"] for r in rows))
        linked=capture_links.get(key,[])
        unique_sources = sorted(set([r["source_id"] for r in rows]+[x["source_id"] for x in linked]))
        if len(names) > 1:
            issues.append(f"{key}: conflicting event claims across sources: {', '.join(names)}")
        estimates=[_event_time(r,offsets,tolerance) for r in rows]
        usable=[x for x in estimates if x[1] is not None]
        corrected=[x[0] for x in usable]
        unc=[x[1] for x in usable]
        if usable:
            lo,hi=min(t-u for t,u in zip(corrected,unc)),max(t+u for t,u in zip(corrected,unc))
            timestamp=statistics.median(corrected);time_basis="gateway-clock-assumed" if any(r["device"]=="gateway" for r in rows) else "device-clock-calibrated-to-gateway"
            uncertainty=max(unc)
        else:
            timestamp=statistics.median(r["timestamp"] for r in rows);lo=hi=None
            time_basis="uncalibrated-source-clock";uncertainty=None
        agreed_sources = {r["source_id"] for r in rows if len(names) == 1}
        if len(names)==1: agreed_sources.update(x["source_id"] for x in linked)
        if len(names) > 1: label = "Single-source"
        elif len(agreed_sources) >= 2: label = "Confirmed"
        else: label = "Single-source"
        event_name = names[0] if len(names) == 1 else "Conflicting claims: " + " / ".join(names)
        result.append({"timestamp": timestamp, "time_range": [lo,hi] if lo is not None else None, "time_basis":time_basis,"event": event_name,
            "device_or_source": ", ".join(sorted(set(str(r["device"]) for r in rows))), "event_id": key,
            "label": label, "supporting_evidence": [f"{r['source_file']} record {r['record']} ({r['event']})" for r in rows]+[x["display"] for x in linked],
            "independent_source_count": len(agreed_sources), "uncertainty_seconds": uncertainty,
            "confidence_or_uncertainty": (f"{len(agreed_sources)} agreeing source(s); time range ±{uncertainty:.3f}s plus source spread" if uncertainty is not None else f"{len(agreed_sources)} agreeing source(s); clocks are not calibrated, so no UTC uncertainty bound is available"),
            "limitations": "Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity.",
            "_observed_times": corrected, "_sources": unique_sources})
    # Explicitly unknown intervals inferred from internal sequence metadata/IDs.
    by_device: dict[tuple[str,str], list[dict]] = defaultdict(list)
    for e in events:
        if e["event"] not in {"network_packet","unsupported_link_packet"}: by_device[(str(e["device"]),str(e["source_id"]))].append(e)
    for (device,source_id), rows in by_device.items():
        seq_map = {}
        for e in rows:
            n = _sequence_number(e)
            if n is not None: seq_map.setdefault(n,e)
        if len(seq_map) < 2: continue
        seqs = sorted(seq_map)
        for left,right in zip(seqs,seqs[1:]):
            if right-left <= 1: continue
            a,b = seq_map[left],seq_map[right]
            ta,_,basis_a=_event_time(a,offsets,tolerance)
            tb,_,basis_b=_event_time(b,offsets,tolerance)
            result.append({"timestamp": (ta+tb)/2, "time_range": [min(ta,tb)-tolerance,max(ta,tb)+tolerance], "event": f"Unknown missing event(s), {right-left-1} sequence value(s)",
                "device_or_source":device, "event_id":f"{device}:{source_id}:gap:{left}-{right}", "label":"Unknown gap","time_basis":basis_a if basis_a==basis_b else "unreconciled-device-clocks",
                "source_id":source_id,"missing_sequence_range":[left+1,right-1],
                "supporting_evidence":[f"{a['source_file']} sequence {left}",f"{b['source_file']} sequence {right}"],
                "independent_source_count":0,"uncertainty_seconds":max(tolerance,abs(tb-ta)/2),
                "confidence_or_uncertainty":"Bounds are adjacent recorded sequence timestamps; missing event content and exact time are unknown.",
                "limitations":"A sequence gap can reflect loss, deletion, or a sequence assignment rule; it does not prove tampering."})
    ids_by_device: dict[str,set[str]]=defaultdict(set)
    for e in events:
        if e["device"]!="gateway" and e["event_id"]: ids_by_device[str(e["device"])].add(e["event_id"])
    for g in events:
        if g["device"]!="gateway" or not g["event_id"] or not g.get("peer"): continue
        if g["event_id"] in ids_by_device.get(g["peer"],set()): continue
        result.append({"timestamp":g["timestamp"],"time_range":[g["timestamp"]-tolerance,g["timestamp"]+tolerance],
            "event":f"Device log record for {g['event_id']} is absent; gateway recorded '{g['event']}'",
            "device_or_source":g["peer"],"event_id":f"{g['peer']}:missing-log:{g['event_id']}","label":"Unknown gap","time_basis":"gateway-clock-assumed",
            "supporting_evidence":[f"{g['source_file']} record {g['record']} ({g['event']})",f"no matching event ID in device log for {g['peer']}"],
            "independent_source_count":0,"uncertainty_seconds":tolerance,
            "confidence_or_uncertainty":"Gateway record exists; absence from the supplied device file is observable, but the cause is unknown.",
            "limitations":"Could reflect collection loss, device behavior, ID mismatch, gateway fabrication, or deletion. Absence alone does not prove tampering."})
    # Conservative periodic-event hypothesis: >=4 same-name samples, then a gap >=1.75 median period.
    periodic: dict[tuple[str,str], list[dict]] = defaultdict(list)
    for e in events:
        if e["device"] != "gateway" and e.get("event"):
            periodic[(str(e["device"]),e["event"])].append(e)
    for (device,name), rows in periodic.items():
        unstable_sources={r["source_id"] for r in rows if offsets.get(r["source_id"],{}).get("anchor_count",0)>=3 and not offsets.get(r["source_id"],{}).get("applied")}
        if unstable_sources:
            issues.append(f"{device}/{name}: periodic inference skipped because source clock calibration is unstable for {', '.join(sorted(unstable_sources))}")
            continue
        rows.sort(key=lambda x:_event_time(x,offsets,tolerance)[0])
        if len(rows)<4: continue
        times=[_event_time(r,offsets,tolerance)[0] for r in rows]
        intervals=[b-a for a,b in zip(times,times[1:]) if b>a]
        if len(intervals)<3: continue
        period=statistics.median(intervals)
        for i,delta in enumerate(intervals):
            if delta < 1.75*period: continue
            count=max(1,round(delta/period)-1)
            for k in range(1,count+1):
                estimate=times[i]+k*period
                if any(r["event"]==name and (not r.get("peer") or r["peer"]==device) and
                       abs(_event_time(r,offsets,tolerance)[0]-estimate)<=max(tolerance,period*.25)
                       for r in events if r["device"]=="gateway"):
                    continue
                result.append({"timestamp":estimate,"time_range":[estimate-max(tolerance,period*.25),estimate+max(tolerance,period*.25)],
                    "event":f"Possible missing periodic '{name}' event", "device_or_source":device,"time_basis":_event_time(rows[i],offsets,tolerance)[2],
                    "event_id":f"inferred:{device}:{name}:{estimate:.6f}","label":"Inferred",
                    "supporting_evidence":[f"{rows[i]['source_file']} {name} at {times[i]:.3f}",f"{rows[i+1]['source_file']} {name} at {times[i+1]:.3f}"],
                    "independent_source_count":1,"uncertainty_seconds":max(tolerance,period*.25),
                    "confidence_or_uncertainty":f"Low-confidence periodicity hypothesis; estimated period {period:.3f}s; display window includes ±25% of period.",
                    "limitations":"Absence may be normal silence or an unobserved behavior. This hypothesis is never counted as a recorded fact."})
    for e in events:
        if e["event"] in {"network_packet","unsupported_link_packet"}:
            packet_range=[e.get("timestamp_start",e["timestamp"]),e.get("timestamp_end",e["timestamp"])]
            result.append({"timestamp":e["timestamp"],"time_range":packet_range,"event":e["event"],
                "device_or_source":e["source_file"],"event_id":f"{e['source_file']}:packet-{e['record']}","label":"Single-source","time_basis":"capture-clock-as-recorded",
                "supporting_evidence":[f"{e['source_file']} packet {e['record']}: {e.get('source_ip')}:{e.get('source_port')} -> {e.get('destination_ip')}:{e.get('destination_port')} {e.get('protocol')}; mapped device(s): {', '.join(e.get('mapped_devices', [])) or 'unknown'}"],"independent_source_count":1,
                "uncertainty_seconds":0.0,"confidence_or_uncertainty":"Capture timestamp as recorded; capture clock accuracy is not independently established.",
            "network_summary":{k:e.get(k) for k in ("source_ip","destination_ip","protocol","source_port","destination_port","wire_bytes","linktype","mapped_devices","packet_count","timestamp_start","timestamp_end") if k in e},
                "limitations":"Header summary only; no packet payload inspected. Similar flows within a one-second bucket are coalesced; capture packet presence does not prove a device event."})
    result.sort(key=lambda e:(e["timestamp"],e["event_id"]))
    for e in result:
        e.pop("_observed_times",None);e.pop("_sources",None)
    return result


def _write_reports(result: dict, output: Path) -> None:
    def md(value: Any) -> str:
        return str(value).replace("\r", " ").replace("\n", " ").replace("|", "\\|")
    output.mkdir(parents=True,exist_ok=True)
    (output/"report.json").write_text(json.dumps(result,indent=2,ensure_ascii=False),encoding="utf-8")
    rows=result["timeline"]
    lines=["# NEXUS-IoT Incident Reconstruction", "",f"Created: {result['created_at']}","", "## Evidence validation", ""]
    lines += [f"- {md(x)}" for x in result["validation_issues"]] or ["- No validation findings."]
    lines += ["", "## Clock estimates", "", "| Source | Offset (s) | Drift (ppm) | Uncertainty (s) | Anchors | Applied |", "|---|---:|---:|---:|---:|---|"]
    for source,x in result["clock_estimates"].items():
        unc="unknown" if x["uncertainty_seconds"] is None else f"±{x['uncertainty_seconds']:.6f}"
        lines.append(f"| {md(source)} | {x['offset_seconds']:+.6f} | {x['drift_ppm']:+.3f} | {unc} | {x['anchor_count']} | {x['applied']} |")
    if not result["clock_estimates"]: lines.append("| No matched timestamp anchors | 0 | 0 | unknown | 0 | false |")
    lines += ["", "## Timeline", "", "| UTC time / range | Event | Device / source | Label | Supporting evidence | Confidence / uncertainty and limitations |", "|---|---|---|---|---|---|"]
    for e in rows:
        try:
            if e["time_range"] is None:
                time_text=f"{datetime.fromtimestamp(e['timestamp'],timezone.utc).isoformat()} (uncalibrated; {e['time_basis']})"
            else:
                a=datetime.fromtimestamp(e['time_range'][0],timezone.utc).isoformat();b=datetime.fromtimestamp(e['time_range'][1],timezone.utc).isoformat()
                time_text=a if a==b else f"{a} to {b}"
                if e.get("time_basis") not in {"gateway-clock-assumed","device-clock-calibrated-to-gateway"}:
                    time_text+=f" [{e.get('time_basis','time basis unknown')}]"
        except (ValueError,OverflowError,OSError): time_text=str(e['time_range'])
        lines.append(f"| {md(time_text)} | {md(e['event'])} | {md(e['device_or_source'])} | **{md(e['label'])}** | {md('; '.join(e['supporting_evidence']))} | {md(e['confidence_or_uncertainty'])} {md(e['limitations'])} |")
    lines += ["", "## Evidence manifest", "", "| File | Bytes | SHA-256 | Collected at |", "|---|---:|---|---|"]
    for x in result["evidence_manifest"]: lines.append(f"| {md(x['relative_path'])} | {x['bytes']} | `{x['sha256']}` | {md(x['collection_time'])} |")
    lines += ["", "## Interpretation limits", ""]+[f"- {md(x)}" for x in result["limitations"]]
    (output/"report.md").write_text("\n".join(lines)+"\n",encoding="utf-8")


def _manifest_bytes(manifest: list[dict]) -> bytes:
    return json.dumps(manifest,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode("utf-8")


def sign_manifest(manifest: list[dict], key_path: Path, signature_path: Path) -> dict:
    try: key=key_path.read_bytes()
    except OSError as e: raise ValueError(f"cannot read manifest signing key: {e}") from e
    if len(key)<32: raise ValueError("manifest signing key must contain at least 32 bytes")
    signature={"algorithm":"HMAC-SHA256","key_id":hashlib.sha256(key).hexdigest()[:16],
               "signature":hmac.new(key,_manifest_bytes(manifest),hashlib.sha256).hexdigest()}
    signature_path.write_text(json.dumps(signature,indent=2),encoding="utf-8")
    return signature


def verify_manifest(manifest_path: Path, signature_path: Path, key_path: Path) -> bool:
    try:
        manifest=json.loads(manifest_path.read_text(encoding="utf-8"))
        signature=json.loads(signature_path.read_text(encoding="utf-8"));key=key_path.read_bytes()
    except (OSError,json.JSONDecodeError) as e: raise ValueError(f"cannot read signed manifest material: {e}") from e
    if not isinstance(manifest,list) or not isinstance(signature,dict) or len(key)<32:
        raise ValueError("invalid manifest/signature or signing key shorter than 32 bytes")
    expected=hmac.new(key,_manifest_bytes(manifest),hashlib.sha256).hexdigest()
    key_id=hashlib.sha256(key).hexdigest()[:16]
    return signature.get("algorithm")=="HMAC-SHA256" and hmac.compare_digest(signature.get("signature",""),expected) and signature.get("key_id")==key_id


def validate(events: list[dict], errors: list[str], config: dict) -> list[str]:
    """Run structural consistency checks without making tampering conclusions."""
    issues=list(errors)
    by_source: dict[str,list[dict]]=defaultdict(list)
    for e in events: by_source[e["source_id"]].append(e)
    for source,rows in by_source.items():
        ordered=sorted(rows,key=lambda e:e["record"])
        ts=[e["timestamp"] for e in ordered]
        if any(b<a for a,b in zip(ts,ts[1:])): issues.append(f"{source}: timestamps move backwards in file order")
        ids=[e["event_id"] for e in ordered if e["event_id"]]
        duplicates=sorted(x for x,n in Counter(ids).items() if n>1)
        if duplicates: issues.append(f"{source}: duplicate event IDs {duplicates}")
        seen=set();dupes=[]
        for e in ordered:
            n=_sequence_number(e)
            if e.get("sequence") is not None and n is None:
                issues.append(f"{source}: record {e['record']} has an invalid sequence value")
            if n is not None:
                if n in seen: dupes.append(n)
                seen.add(n)
        if dupes: issues.append(f"{source}: duplicate sequence values {sorted(set(dupes))}")
        if len(seen)>1:
            ordered_seq=sorted(seen)
            gaps=[(left+1,right-1) for left,right in zip(ordered_seq,ordered_seq[1:]) if right-left>1]
            if gaps:
                sample=gaps[:20]
                issues.append(f"{source}: possible missing sequence ranges {sample}{' (additional ranges omitted)' if len(gaps)>20 else ''}; loss/deletion/sequence policy are all possible")
    device_ids: dict[str,set[str]]=defaultdict(set)
    for e in events:
        if e["device"]!="gateway" and e["event_id"]: device_ids[str(e["device"])].add(e["event_id"])
    for g in events:
        if g["device"]=="gateway" and g["event_id"] and g.get("peer") and g["event_id"] not in device_ids.get(g["peer"],set()):
            issues.append(f"{g['peer']}: gateway observation {g['event_id']} has no matching device log record; absence cause is undetermined")
    ip_map=config.get("device_ips",{})
    if isinstance(ip_map,dict):
        for e in events:
            if e["event"]=="network_packet":
                endpoints={e.get("source_ip"),e.get("destination_ip")}
                e["mapped_devices"]=[name for name,addresses in ip_map.items() if
                    bool(endpoints.intersection({addresses} if isinstance(addresses,str) else set(addresses) if isinstance(addresses,list) else set()))]
    return issues


def analyze(evidence_dir: Path, output_dir: Path, tolerance_seconds: float=0.05, compare_previous: bool=True,
            max_clock_drift_ppm: float=MAX_CLOCK_DRIFT_PPM,
            max_clock_residual_seconds: float=MAX_CLOCK_RESIDUAL_SECONDS,
            signing_key: Path|None=None) -> dict:
    """Analyze supplied evidence read-only; all derived outputs go to output_dir."""
    start=time.perf_counter(); evidence_dir=evidence_dir.resolve(); output_dir=output_dir.resolve()
    if not evidence_dir.is_dir(): raise FileNotFoundError(f"evidence directory does not exist: {evidence_dir}")
    if output_dir==evidence_dir or evidence_dir in output_dir.parents:
        raise ValueError("output directory must be outside evidence so source files stay unchanged")
    if tolerance_seconds<=0 or not math.isfinite(tolerance_seconds): raise ValueError("tolerance must be a positive finite number")
    if max_clock_drift_ppm<=0 or not math.isfinite(max_clock_drift_ppm): raise ValueError("maximum clock drift must be a positive finite number")
    if max_clock_residual_seconds<=0 or not math.isfinite(max_clock_residual_seconds): raise ValueError("maximum clock residual must be a positive finite number")
    prior_path=output_dir/"evidence_manifest.json"
    try: previous=json.loads(prior_path.read_text(encoding="utf-8")) if compare_previous and prior_path.exists() else []
    except (OSError,json.JSONDecodeError): previous=[]
    with tempfile.TemporaryDirectory(prefix="nexus-iot-snapshot-") as temp_name:
        snapshot_root=Path(temp_name)
        manifest,hash_findings=acquire(evidence_dir,snapshot_root,previous if isinstance(previous,list) else [])
        errors=[]; config=_read_devices_config(snapshot_root)
        if config.get("_config_error"): errors.append(config["_config_error"])
        events=_load_evidence(snapshot_root,errors)
    issues=hash_findings+validate(events,errors,config)
    if not manifest: issues.append("No supported evidence files found (.jsonl, .pcap, .pcapng).")
    offsets=_offset_estimates(events,issues,tolerance_seconds,max_clock_drift_ppm,max_clock_residual_seconds)
    capture_links=_capture_correlations(events,config,offsets,issues)
    timeline=_timeline(events,offsets,issues,tolerance_seconds,capture_links)
    result={"schema_version":VERSION,"created_at":utc_now(),"evidence_directory":str(evidence_dir),"evidence_record_count":len(events),
        "processing_seconds":None,"evidence_manifest":manifest,"clock_estimates":offsets,
        "validation_issues":sorted(set(issues)),"timeline":timeline,
        "limitations":["A SHA-256 hash records bytes seen during this run; it cannot establish provenance or integrity before acquisition.",
            "Prior-manifest hash comparisons detect byte changes only when a previous manifest exists and has not itself been replaced.",
            "Clock offsets require shared event IDs in the gateway and device evidence; estimates describe the observed anchors and do not prove gateway time is correct.",
            "PCAP and PCAPNG support is limited to classic formats and Ethernet, raw IP, or Linux cooked headers; packet payloads are not parsed. Repeated header flows are coalesced into one-second summaries.",
            "Sequence gaps and silence can reflect ordinary loss or device behavior; they are not proof of deletion or an attack.",
            "Periodic-event hypotheses are low-confidence and explicitly labeled Inferred; corroboration rules cannot establish authenticity."]}
    result["processing_seconds"]=round(time.perf_counter()-start,6)
    _write_reports(result,output_dir)
    (output_dir/"evidence_manifest.json").write_text(json.dumps(manifest,indent=2),encoding="utf-8")
    if signing_key is not None: sign_manifest(manifest,signing_key,output_dir/"evidence_manifest.sig")
    result["processing_seconds"]=round(time.perf_counter()-start,6)
    (output_dir/"report.json").write_text(json.dumps(result,indent=2,ensure_ascii=False),encoding="utf-8")
    return result
