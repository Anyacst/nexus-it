"""Validation, flow correlation and timeline reconstruction with evidence labels."""
from __future__ import annotations

import math
import statistics
from collections import Counter, defaultdict

from .clock import _event_time


NETWORK_EVENTS = {"network_packet", "unsupported_link_packet"}
# Packet timestamps from one capture can be reordered by a few microseconds; larger regressions are reported.
CAPTURE_REORDER_TOLERANCE_SECONDS = 0.01


def _is_network_observation(e: dict) -> bool:
    """Capture rows that describe traffic (packet summaries, MQTT session packets), not device event claims."""
    return e["event"] in NETWORK_EVENTS or bool(e.get("mqtt_control"))


def _sequence_number(e: dict) -> int | None:
    # Capture-derived rows interleave several devices' IDs; they carry no per-source sequence.
    """Return the record's sequence number, or the numeric suffix of its event ID, or None."""
    if e.get("capture_derived"):
        return None
    val = e.get("sequence")
    if val is not None:
        if isinstance(val, bool):
            return None
        if isinstance(val, int):
            return val
        if isinstance(val, str) and val.isdecimal():
            return int(val)
        return None
    try:
        return int(e["event_id"].rsplit("-", 1)[1])
    except (IndexError, ValueError, KeyError):
        return None


def _event_key(e: dict) -> str:
    """Key that groups observations of one event: its event ID, else source file and record number."""
    if e.get("mqtt_control"):
        return f"{e['source_id']}#mqtt-{e['mqtt_index']}"
    return e["event_id"] or f"{e['source_id']}#record-{e['record']}"


def _capture_correlations(events: list[dict], config: dict, offsets: dict[str, dict], issues: list[str]) -> dict[str, list[dict]]:
    """Apply explicit flow rules; packet proximity without a rule never confirms an event."""
    rules = config.get("correlation_rules", [])
    if not isinstance(rules, list):
        issues.append("devices.json: correlation_rules must be a list")
        return {}
    captures = [e for e in events if e["event"] == "network_packet"]
    device_events = [e for e in events if e["device"] != "gateway" and e["event"] != "network_packet"]
    ips = config.get("device_ips", {})
    if not isinstance(ips, dict):
        ips = {}
    mapping = {}
    for device, values in ips.items():
        vals = [values] if isinstance(values, str) else values if isinstance(values, list) else []
        mapping[str(device)] = {str(v) for v in vals}
    links: dict[str, list[dict]] = defaultdict(list)
    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            issues.append(f"devices.json: correlation rule {i+1} must be an object")
            continue
        device, event, protocol = rule.get("device"), rule.get("event"), str(rule.get("protocol", "")).lower()
        direction = rule.get("direction", "either")
        window = rule.get("window_seconds", 1.0)
        if not isinstance(device, str) or not isinstance(event, str) or protocol not in {"tcp", "udp", "icmp", "icmpv6"}:
            issues.append(f"devices.json: correlation rule {i+1} requires device, event, and supported protocol")
            continue
        if direction not in {"inbound", "outbound", "either"} or isinstance(window, bool) or not isinstance(window, (int, float)) or not math.isfinite(window) or window <= 0:
            issues.append(f"devices.json: correlation rule {i+1} has invalid direction/window_seconds")
            continue
        if any(rule.get(field) is not None and (isinstance(rule[field], bool) or not isinstance(rule[field], int) or not 0 <= rule[field] <= 65535) for field in ("source_port", "destination_port")):
            issues.append(f"devices.json: correlation rule {i+1} has an invalid port")
            continue
        device_ips = mapping.get(device, set())
        if not device_ips:
            issues.append(f"devices.json: correlation rule {i+1} has no device_ips entry for {device}; it cannot attribute packets")
            continue
        rule_id = str(rule.get("id", f"rule-{i+1}"))
        for event_row in device_events:
            if event_row["device"] != device or event_row["event"] != event:
                continue
            offset = offsets.get(event_row["source_id"])
            manual_offset = rule.get("device_clock_offset_seconds")
            if offset and offset.get("applied"):
                event_time = _event_time(event_row, offsets, 0.0)[0]
            elif isinstance(manual_offset, (int, float)) and not isinstance(manual_offset, bool) and math.isfinite(manual_offset):
                event_time = event_row["timestamp"]-manual_offset
            else:
                issues.append(f"{event_row['source_file']} record {event_row['record']}: correlation rule {rule_id} skipped because the device clock has no stable applied gateway calibration")
                continue
            candidates = []
            for packet in captures:
                if packet.get("protocol") != protocol or device not in packet.get("mapped_devices", []):
                    continue
                src_is_device = packet.get("source_ip") in device_ips
                if (direction == "outbound" and not src_is_device) or (direction == "inbound" and src_is_device):
                    continue
                if any(rule.get(field) is not None and packet.get(field) != rule[field] for field in ("source_port", "destination_port")):
                    continue
                delta = max(packet.get("timestamp_start", packet["timestamp"])-event_time, 0.0,
                          event_time-packet.get("timestamp_end", packet["timestamp"]))
                if delta <= float(window):
                    candidates.append((delta, packet))
            if candidates:
                delta, packet = min(candidates, key=lambda x:x[0])
                key = _event_key(event_row)
                support = {"source_id":packet["source_id"], "display":f"{packet['source_file']} packet summary starting at {packet['record']} ({packet.get('packet_count',1)} packet(s)) matched configured rule {rule_id}; flow {packet.get('source_ip')}:{packet.get('source_port')} -> {packet.get('destination_ip')}:{packet.get('destination_port')} {protocol}; Δt={delta:.3f}s"}
                if all(x["source_id"] != support["source_id"] for x in links[key]):
                    links[key].append(support)
    return links


def _mqtt_publishers(rows: list[dict]) -> list[dict]:
    """MQTT PUBLISH witnesses of one event as sorted {client_id, device} pairs (client_id None when unknown)."""
    pairs = {((r.get("metadata") or {}).get("client_id"), str(r.get("peer", ""))) for r in rows if r.get("mqtt_type") == "PUBLISH"}
    return [{"client_id": c, "device": d} for c, d in sorted(pairs, key=lambda p: (p[0] is None, p[0] or "", p[1]))]


def _timeline(events: list[dict], offsets: dict[str, dict], issues: list[str], tolerance: float,
              capture_links: dict[str, list[dict]]|None=None) -> list[dict]:
    """Build labelled timeline rows (Confirmed, Single-source, Inferred, Unknown gap, observations)."""
    capture_links = capture_links or {}
    groups: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        if not _is_network_observation(e):
            groups[_event_key(e)].append(e)
    result = []
    for key, rows in groups.items():
        names = sorted(set(r["event"] for r in rows))
        linked = capture_links.get(key, [])
        unique_sources = sorted(set([r["source_id"] for r in rows]+[x["source_id"] for x in linked]))
        if len(names) > 1:
            issues.append(f"{key}: conflicting event claims across sources: {', '.join(names)}")
        estimates = [_event_time(r, offsets, tolerance) for r in rows]
        usable = [x for x in estimates if x[1] is not None]
        corrected = [x[0] for x in usable]
        unc = [x[1] for x in usable]
        if usable:
            lo, hi = min(t-u for t, u in zip(corrected, unc)), max(t+u for t, u in zip(corrected, unc))
            timestamp = statistics.median(corrected)
            time_basis = "gateway-clock-assumed" if any(r["device"] == "gateway" for r in rows) else "device-clock-calibrated-to-gateway"
            uncertainty = max(unc)
        else:
            timestamp = statistics.median(r["timestamp"] for r in rows)
            lo = hi = None
            time_basis = "uncalibrated-source-clock"
            uncertainty = None
        agreed_sources = {r["source_id"] for r in rows if len(names) == 1}
        if len(names) == 1:
            agreed_sources.update(x["source_id"] for x in linked)
        if len(names) > 1:
            label = "Single-source"
        elif len(agreed_sources) >= 2:
            label = "Confirmed"
        else:
            label = "Single-source"
        event_name = names[0] if len(names) == 1 else "Conflicting claims: " + " / ".join(names)
        result.append({"timestamp": timestamp, "time_range": [lo, hi] if lo is not None else None, "time_basis":time_basis, "event": event_name,
            "device_or_source": ", ".join(sorted(set(str(r["device"]) for r in rows))), "event_id": key,
            "label": label, "supporting_evidence": [_evidence_text(r) for r in rows]+[x["display"] for x in linked],
            "independent_source_count": len(agreed_sources), "uncertainty_seconds": uncertainty,
            "confidence_or_uncertainty": (f"{len(agreed_sources)} agreeing source(s); time range ±{uncertainty:.3f}s plus source spread" if uncertainty is not None else f"{len(agreed_sources)} agreeing source(s); clocks are not calibrated, so no UTC uncertainty bound is available"),
            "limitations": "Distinct source IDs and matching event IDs support correlation but do not prove source independence or authenticity.",
            "_observed_times": corrected, "_sources": unique_sources})
        publishers = _mqtt_publishers(rows)
        if publishers:
            result[-1]["mqtt_publishers"] = publishers
    # Explicitly unknown intervals inferred from internal sequence metadata/IDs.
    by_device: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for e in events:
        if not _is_network_observation(e):
            by_device[(str(e["device"]), str(e["source_id"]))].append(e)
    for (device, source_id), rows in by_device.items():
        seq_map = {}
        for e in rows:
            n = _sequence_number(e)
            if n is not None:
                seq_map.setdefault(n, e)
        if len(seq_map) < 2:
            continue
        seqs = sorted(seq_map)
        for left, right in zip(seqs, seqs[1:]):
            if right-left <= 1:
                continue
            a, b = seq_map[left], seq_map[right]
            ta, _, basis_a = _event_time(a, offsets, tolerance)
            tb, _, basis_b = _event_time(b, offsets, tolerance)
            result.append({"timestamp": (ta+tb)/2, "time_range": [min(ta, tb)-tolerance, max(ta, tb)+tolerance], "event": f"Unknown missing event(s), {right-left-1} sequence value(s)",
                "device_or_source":device, "event_id":f"{device}:{source_id}:gap:{left}-{right}", "label":"Unknown gap", "time_basis":basis_a if basis_a == basis_b else "unreconciled-device-clocks",
                "source_id":source_id, "missing_sequence_range":[left+1, right-1],
                "supporting_evidence":[f"{a['source_file']} sequence {left}", f"{b['source_file']} sequence {right}"],
                "independent_source_count":0, "uncertainty_seconds":max(tolerance, abs(tb-ta)/2),
                "confidence_or_uncertainty":"Bounds are adjacent recorded sequence timestamps; missing event content and exact time are unknown.",
                "limitations":"A sequence gap can reflect loss, deletion, or a sequence assignment rule; it does not prove tampering."})
    ids_by_device: dict[str, set[str]] = defaultdict(set)
    for e in events:
        if e["device"] != "gateway" and e["event_id"]:
            ids_by_device[str(e["device"])].add(e["event_id"])
    absent_logs: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for g in events:
        if g["device"] != "gateway" or not g["event_id"] or not g.get("peer"):
            continue
        if g["event_id"] in ids_by_device.get(g["peer"], set()):
            continue
        absent_logs[(g["peer"], g["event_id"])].append(g)
    for (peer, event_id), witnesses in absent_logs.items():
        # Several gateway-side witnesses (gateway log, capture) of one ID produce one gap row.
        g = witnesses[0]
        gateway_time = statistics.median(w["timestamp"] for w in witnesses)
        recorded = " / ".join(sorted({w["event"] for w in witnesses}))
        result.append({"timestamp":gateway_time, "time_range":[gateway_time-tolerance, gateway_time+tolerance],
            "event":f"Device log record for {event_id} is absent; gateway recorded '{recorded}'",
            "device_or_source":peer, "event_id":f"{peer}:missing-log:{event_id}", "label":"Unknown gap", "time_basis":"gateway-clock-assumed",
            "supporting_evidence":[_evidence_text(w) for w in witnesses]+[f"no matching event ID in device log for {peer}"],
            "independent_source_count":0, "uncertainty_seconds":tolerance,
            "confidence_or_uncertainty":"Gateway record exists; absence from the supplied device file is observable, but the cause is unknown.",
            "limitations":"Could reflect collection loss, device behavior, ID mismatch, gateway fabrication, or deletion. Absence alone does not prove tampering."})
    # Conservative periodic-event hypothesis: >=4 same-name samples, then a gap >=1.75 median period.
    periodic: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for e in events:
        if e["device"] != "gateway" and e.get("event"):
            periodic[(str(e["device"]), e["event"])].append(e)
    for (device, name), rows in periodic.items():
        unstable_sources = {r["source_id"] for r in rows if offsets.get(r["source_id"], {}).get("anchor_count", 0) >= 3 and not offsets.get(r["source_id"], {}).get("applied")}
        if unstable_sources:
            issues.append(f"{device}/{name}: periodic inference skipped because source clock calibration is unstable for {', '.join(sorted(unstable_sources))}")
            continue
        rows.sort(key=lambda x:_event_time(x, offsets, tolerance)[0])
        if len(rows) < 4:
            continue
        times = [_event_time(r, offsets, tolerance)[0] for r in rows]
        intervals = [b-a for a, b in zip(times, times[1:]) if b > a]
        if len(intervals) < 3:
            continue
        period = statistics.median(intervals)
        for i, delta in enumerate(intervals):
            if delta < 1.75*period:
                continue
            count = max(1, round(delta/period)-1)
            for k in range(1, count+1):
                estimate = times[i]+k*period
                if any(r["event"] == name and (not r.get("peer") or r["peer"] == device) and
                       abs(_event_time(r, offsets, tolerance)[0]-estimate) <= max(tolerance, period*.25)
                       for r in events if r["device"] == "gateway"):
                    continue
                result.append({"timestamp":estimate, "time_range":[estimate-max(tolerance, period*.25), estimate+max(tolerance, period*.25)],
                    "event":f"Possible missing periodic '{name}' event", "device_or_source":device, "time_basis":_event_time(rows[i], offsets, tolerance)[2],
                    "event_id":f"inferred:{device}:{name}:{estimate:.6f}", "label":"Inferred",
                    "supporting_evidence":[f"{rows[i]['source_file']} {name} at {times[i]:.3f}", f"{rows[i+1]['source_file']} {name} at {times[i+1]:.3f}"],
                    "independent_source_count":1, "uncertainty_seconds":max(tolerance, period*.25),
                    "confidence_or_uncertainty":f"Low-confidence periodicity hypothesis; estimated period {period:.3f}s; display window includes ±25% of period.",
                    "limitations":"Absence may be normal silence or an unobserved behavior. This hypothesis is never counted as a recorded fact."})
    for e in events:
        if e.get("mqtt_control"):
            result.append(_mqtt_observation(e))
        elif e["event"] in NETWORK_EVENTS:
            packet_range = [e.get("timestamp_start", e["timestamp"]), e.get("timestamp_end", e["timestamp"])]
            result.append({"timestamp":e["timestamp"], "time_range":packet_range, "event":e["event"],
                "device_or_source":e["source_file"], "event_id":f"{e['source_file']}:packet-{e['record']}", "label":"Single-source", "time_basis":"capture-clock-as-recorded",
                "supporting_evidence":[f"{e['source_file']} packet {e['record']}: {e.get('source_ip')}:{e.get('source_port')} -> {e.get('destination_ip')}:{e.get('destination_port')} {e.get('protocol')}; mapped device(s): {', '.join(e.get('mapped_devices', [])) or 'unknown'}"], "independent_source_count":1,
                "uncertainty_seconds":0.0, "confidence_or_uncertainty":"Capture timestamp as recorded; capture clock accuracy is not independently established.",
            "network_summary":{k:e.get(k) for k in ("source_ip", "destination_ip", "protocol", "source_port", "destination_port", "wire_bytes", "linktype", "mapped_devices", "packet_count", "timestamp_start", "timestamp_end") if k in e},
                "limitations":"Header summary only; no packet payload inspected. Similar flows within a one-second bucket are coalesced; capture packet presence does not prove a device event."})
    result.sort(key=lambda e:(e["timestamp"], e["event_id"]))
    for e in result:
        e.pop("_observed_times", None)
        e.pop("_sources", None)
    return result


def _evidence_text(r: dict) -> str:
    """One supporting-evidence line for an evidence row."""
    if r.get("mqtt_type") == "PUBLISH":
        meta = r.get("metadata", {})
        return (f"{r['source_file']} packet {r['record']}: MQTT PUBLISH topic {meta.get('topic')} from client "
                f"{meta.get('client_id') or 'unknown'} {meta.get('source_ip')}:{meta.get('source_port')} ({r['event']})")
    return f"{r['source_file']} record {r['record']} ({r['event']})"


def _mqtt_observation(e: dict) -> dict:
    """Timeline row for an MQTT CONNECT/DISCONNECT/SUBSCRIBE seen in a capture."""
    details = e.get("mqtt", {})
    extra = f" client_id={details['client_id']}" if details.get("client_id") else ""
    if details.get("topics"):
        extra += " topics=" + ",".join(t["topic"] for t in details["topics"])
    flow = f"{e.get('source_ip')}:{e.get('source_port')} -> {e.get('destination_ip')}:{e.get('destination_port')}"
    return {"timestamp": e["timestamp"], "time_range": [e["timestamp"], e["timestamp"]], "event": e["event"],
            "device_or_source": e["source_file"], "event_id": f"{e['source_file']}:mqtt-{e['mqtt_index']}",
            "label": "Single-source", "time_basis": "capture-clock-as-recorded",
            "supporting_evidence": [f"{e['source_file']} packet {e['record']}: MQTT {details.get('type', '')}{extra} {flow} tcp; "
                                    f"mapped device(s): {', '.join(e.get('mapped_devices', [])) or 'unknown'}"],
            "independent_source_count": 1, "uncertainty_seconds": 0.0,
            "confidence_or_uncertainty": "Capture timestamp as recorded; capture clock accuracy is not independently established.",
            "network_summary": {"source_ip": e.get("source_ip"), "destination_ip": e.get("destination_ip"), "protocol": "tcp",
                                "source_port": e.get("source_port"), "destination_port": e.get("destination_port"),
                                "mapped_devices": e.get("mapped_devices", []), "mqtt": details},
            "limitations": "MQTT session packet decoded from the capture; it shows client/broker session activity, not a device event."}


def validate(events: list[dict], errors: list[str], config: dict) -> list[str]:
    """Run structural consistency checks without making tampering conclusions."""
    issues = list(errors)
    by_source: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        by_source[e["source_id"]].append(e)
    for source, rows in by_source.items():
        ordered = sorted(rows, key=lambda e:e["record"])
        ts = [e["timestamp"] for e in ordered]
        regressions = [a - b for a, b in zip(ts, ts[1:]) if b < a]
        is_capture = source.lower().endswith((".pcap", ".pcapng"))
        if regressions and is_capture and max(regressions) <= CAPTURE_REORDER_TOLERANCE_SECONDS:
            issues.append(f"{source}: {len(regressions)} packet timestamp(s) out of order by at most "
                          f"{max(regressions) * 1e6:.0f} µs; normal capture jitter, not treated as an anomaly")
        elif regressions:
            issues.append(f"{source}: timestamps move backwards in file order")
        ids = [e["event_id"] for e in ordered if e["event_id"]]
        duplicates = sorted(x for x, n in Counter(ids).items() if n > 1)
        if duplicates:
            issues.append(f"{source}: duplicate event IDs {duplicates}")
        seen = set()
        dupes = []
        for e in ordered:
            n = _sequence_number(e)
            if e.get("sequence") is not None and n is None:
                issues.append(f"{source}: record {e['record']} has an invalid sequence value")
            if n is not None:
                if n in seen:
                    dupes.append(n)
                seen.add(n)
        if dupes:
            issues.append(f"{source}: duplicate sequence values {sorted(set(dupes))}")
        if len(seen) > 1:
            ordered_seq = sorted(seen)
            gaps = [(left+1, right-1) for left, right in zip(ordered_seq, ordered_seq[1:]) if right-left > 1]
            if gaps:
                sample = gaps[:20]
                issues.append(f"{source}: possible missing sequence ranges {sample}{' (additional ranges omitted)' if len(gaps)>20 else ''}; loss/deletion/sequence policy are all possible")
    device_ids: dict[str, set[str]] = defaultdict(set)
    for e in events:
        if e["device"] != "gateway" and e["event_id"]:
            device_ids[str(e["device"])].add(e["event_id"])
    for g in events:
        if g["device"] == "gateway" and g["event_id"] and g.get("peer") and g["event_id"] not in device_ids.get(g["peer"], set()):
            issues.append(f"{g['peer']}: gateway observation {g['event_id']} has no matching device log record; absence cause is undetermined")
    ip_map = config.get("device_ips", {})
    if isinstance(ip_map, dict):
        for e in events:
            if e["event"] == "network_packet":
                endpoints = {e.get("source_ip"), e.get("destination_ip")}
                e["mapped_devices"] = [name for name, addresses in ip_map.items() if
                    bool(endpoints.intersection({addresses} if isinstance(addresses, str) else set(addresses) if isinstance(addresses, list) else set()))]
    return issues
