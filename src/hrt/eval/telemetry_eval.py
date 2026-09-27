"""Measured Tier-1 telemetry reduction on the live lab capture.

Replays the real Zeek conn.log through the triage engine and, for every alert, compares the bytes
of the raw connection records it summarises with the bytes of the alert JSON actually posted to
the webhook. That is the data the LLM would otherwise have had to read.
"""

from __future__ import annotations

import statistics

from hrt.config import Settings
from hrt.telemetry.zeek import read_conn_log
from hrt.triage.detector import WindowDetector
from hrt.triage.engine import TriageEngine


def run(settings: Settings, fast: bool = False) -> dict:
    path = settings.conn_log
    if not path.exists():
        raise SystemExit(f"{path} not found; run the lab and some attacks first")
    raw = path.read_bytes()
    records = raw.count(b"\n")
    avg_record = len(raw) / max(records, 1)                 # measured, not assumed
    flows = read_conn_log(path)
    engine = TriageEngine(WindowDetector.load(settings.models_dir / "window_detector.joblib"), lambda a: None,
                          settings.window_seconds, settings.alert_cooldown_seconds, origin="replay")
    alerts = engine.replay(flows)
    per_alert = []
    for a in alerts:
        raw_bytes = a.raw_flow_count * avg_record
        alert_bytes = len(a.model_dump_json().encode())
        per_alert.append({"rules": a.detector.rules, "source": str(a.source_ip), "flows": a.raw_flow_count,
                          "raw_bytes": int(raw_bytes), "alert_bytes": alert_bytes,
                          "reduction": round(1 - alert_bytes / raw_bytes, 5) if raw_bytes else None})
    total_alert = sum(p["alert_bytes"] for p in per_alert)
    reductions = [p["reduction"] for p in per_alert if p["reduction"] is not None]
    return {
        "conn_log_bytes": len(raw),
        "records": records,
        "avg_record_bytes": round(avg_record, 1),
        "alerts": per_alert,
        "n_alerts": len(per_alert),
        "median_alert_reduction": round(statistics.median(reductions), 5) if reductions else None,
        "min_alert_reduction": round(min(reductions), 5) if reductions else None,
        # everything Zeek logged (benign included) vs everything Tier 1 forwarded to the LLM
        "whole_log_reduction": round(1 - total_alert / len(raw), 6) if raw else None,
    }
