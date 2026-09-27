"""Fit the Tier-1 window-level Isolation Forest on benign lab traffic only."""

from __future__ import annotations

from hrt.config import Settings
from hrt.telemetry.zeek import read_conn_log
from hrt.triage.detector import WindowDetector
from hrt.triage.features import sliding_windows, window_features
from hrt.triage.rules import evaluate_rules


def train_from_lab(settings: Settings, minimum: int = 50) -> WindowDetector:
    if not settings.conn_log.exists():
        raise SystemExit(f"no conn.log at {settings.conn_log}; run `hrt lab up` and generate benign traffic first")
    flows = read_conn_log(settings.conn_log)
    windows = sliding_windows(flows, settings.window_seconds, settings.window_seconds / 2)
    feats = [window_features(fl, settings.window_seconds) for _, _, fl in windows if fl]
    # Presumed-benign baseline: fit only on windows that trigger no deterministic rule, so an
    # attack burst captured in the same log does not poison the anomaly model.
    benign = [f for f in feats if not evaluate_rules(f)]
    dropped = len(feats) - len(benign)
    if dropped:
        print(f"[train] excluded {dropped} rule-triggering windows from the benign baseline")
    if len(benign) < minimum:
        raise SystemExit(f"only {len(benign)} presumed-benign windows (need >= {minimum}); "
                         f"let benign traffic run longer with `hrt lab up`")
    det = WindowDetector.fit(benign, quantile=settings.benign_score_quantile)
    det.save(settings.models_dir / "window_detector.joblib")
    return det
