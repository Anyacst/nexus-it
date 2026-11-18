"""Device clock calibration against gateway anchors (offset, drift and one step change)."""
from __future__ import annotations

import statistics
from collections import defaultdict


MAX_CLOCK_DRIFT_PPM = 1_000.0


MAX_CLOCK_RESIDUAL_SECONDS = 2.0


def _offset_estimates(events: list[dict], issues: list[str], tolerance: float,
                      max_drift_ppm: float=MAX_CLOCK_DRIFT_PPM,
                      max_residual_seconds: float=MAX_CLOCK_RESIDUAL_SECONDS) -> dict[str, dict]:
    """Fit a per-source clock model (offset, Theil-Sen drift, optional step) from gateway anchors."""
    anchors: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        if e["event_id"]:
            anchors[e["event_id"]].append(e)
    deltas: dict[str, list[tuple[float, float]]] = defaultdict(list)
    for rows in anchors.values():
        for r in rows:
            if r["device"] == "gateway":
                continue
            gateways = [g for g in rows if g["device"] == "gateway" and g["event"] == r["event"] and (not g.get("peer") or g["peer"] == r["device"])]
            if not gateways:
                continue
            # Multiple gateway copies of one ID count as one anchor: use their median timestamp.
            gateway_time = statistics.median(g["timestamp"] for g in gateways)
            deltas[r["source_id"]].append((r["timestamp"], r["timestamp"]-gateway_time))
    estimates = {}
    def fit(samples):
        device_times = [x[0] for x in samples]
        raw_offsets = [x[1] for x in samples]
        reference = statistics.median(device_times)
        slopes = []
        for i in range(len(samples)):
            for j in range(i+1, len(samples)):
                dt = device_times[j]-device_times[i]
                if dt:
                    slopes.append((raw_offsets[j]-raw_offsets[i])/dt)
        drift = statistics.median(slopes) if len(samples) >= 3 and slopes else 0.0
        center = statistics.median(offset-drift*(t-reference) for t, offset in samples)
        residuals = [offset-(center+drift*(t-reference)) for t, offset in samples]
        mad = statistics.median(abs(x-statistics.median(residuals)) for x in residuals)
        return {"offset_seconds":center, "drift_seconds_per_second":drift, "drift_ppm":drift*1_000_000,
            "reference_timestamp":reference, "uncertainty_seconds":max(tolerance, 1.4826*mad),
            "anchor_count":len(samples), "residual_range_seconds":max(residuals)-min(residuals) if residuals else 0.0,
            "samples":samples}
    for source, samples in deltas.items():
        samples = sorted(samples)
        model = fit(samples)
        stable = (len(samples) >= 3 and model["residual_range_seconds"] <= max(4*tolerance, max_residual_seconds) and abs(model["drift_ppm"]) <= max_drift_ppm)
        segments = []
        if not stable and len(samples) >= 6:
            candidates = []
            for split in range(3, len(samples)-2):
                left, right = fit(samples[:split]), fit(samples[split:])
                if all(m["residual_range_seconds"] <= max(4*tolerance, max_residual_seconds) and abs(m["drift_ppm"]) <= max_drift_ppm for m in (left, right)):
                    candidates.append((max(left["residual_range_seconds"], right["residual_range_seconds"]), split, left, right))
            if candidates:
                _, split, left, right = min(candidates, key=lambda x:(x[0], abs((x[1]/len(samples))-.5)))
                segments = [{k:v for k, v in m.items() if k != "samples"} | {"start_device_timestamp":m["samples"][0][0], "end_device_timestamp":m["samples"][-1][0]} for m in (left, right)]
                stable = True
                issues.append(f"{source}: clock anchors do not fit a single stable model; step change detected and separate stable segments applied around an inferred boundary")
        estimates[source] = {**{k:v for k, v in model.items() if k != "samples"},
            "uncertainty_seconds":model["uncertainty_seconds"] if stable else None, "max_drift_ppm":max_drift_ppm,
            "max_residual_seconds":max_residual_seconds, "applied":stable, "segments":segments}
        if len(samples) < 3:
            issues.append(f"{source}: only {len(samples)} valid clock anchor(s); offset estimate is diagnostic and was not applied")
        elif not stable:
            issues.append(f"{source}: clock anchors do not fit an allowed stable model (residual range {model['residual_range_seconds']:.3f}s, drift {model['drift_ppm']:+.1f}ppm, limits ±{max_residual_seconds:.3f}s and ±{max_drift_ppm:.0f}ppm); correction was not applied; possible step change or manipulation")
    return estimates


def _event_time(e: dict, offsets: dict[str, dict], tolerance: float) -> tuple[float, float|None, str]:
    """Return (corrected time, uncertainty, time basis) for an event using its source's clock model."""
    if e["device"] == "gateway":
        return e["timestamp"], tolerance, "gateway-clock-assumed"
    model = offsets.get(e["source_id"])
    if model and model.get("applied"):
        segments = model.get("segments", [])
        segment = next((s for s in segments if s["start_device_timestamp"] <= e["timestamp"] <= s["end_device_timestamp"]), None)
        if segment:
            offset = segment["offset_seconds"]+segment["drift_seconds_per_second"]*(e["timestamp"]-segment["reference_timestamp"])
            return e["timestamp"]-offset, segment["uncertainty_seconds"], "device-clock-piecewise-calibrated-to-gateway"
        if segments:
            nearest = min(segments, key=lambda s:min(abs(e["timestamp"]-s["start_device_timestamp"]), abs(e["timestamp"]-s["end_device_timestamp"])))
            offset = nearest["offset_seconds"]+nearest["drift_seconds_per_second"]*(e["timestamp"]-nearest["reference_timestamp"])
            return e["timestamp"]-offset, nearest["uncertainty_seconds"], "device-clock-piecewise-extrapolated-to-gateway"
        delta = e["timestamp"]-model["reference_timestamp"]
        offset = model["offset_seconds"]+model["drift_seconds_per_second"]*delta
        return e["timestamp"]-offset, model["uncertainty_seconds"], "device-clock-calibrated-to-gateway"
    return e["timestamp"], None, "device-clock-uncalibrated"
