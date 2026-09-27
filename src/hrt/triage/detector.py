"""Hybrid Tier-1 detector: deterministic threshold rules OR a PyOD Isolation Forest.

The forest is fitted on **benign traffic only**, and its alert threshold is a high quantile of
the benign scores. That avoids the old code's bug: a fixed ``contamination`` labels about 5% of
every batch anomalous even when all the traffic is benign.

PyOD (and the scikit-learn stack beneath it) is imported lazily, only when a forest is actually
fitted or loaded. The rules-only path therefore runs without any compiled ML extensions, which
keeps live triage working on machines where those extensions can't load (for example, Windows
Smart App Control blocking unsigned Python 3.14 wheels; see docs/DATA_NOTES.md).
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

import joblib
import numpy as np
import pandas as pd

from hrt.models import AlertFeatures, DetectorOutput
from hrt.triage.features import FEATURE_NAMES, feature_vector
from hrt.triage.rules import evaluate_rules

if TYPE_CHECKING:
    from pyod.models.iforest import IForest


def _fit_iforest(X: np.ndarray, seed: int) -> "IForest":
    from pyod.models.iforest import IForest  # lazy: heavy compiled dependency

    model = IForest(n_estimators=200, max_samples=min(256, len(X)), random_state=seed, contamination=0.01)
    model.fit(X)
    return model


class WindowDetector:
    def __init__(self, model: Any = None, threshold: float | None = None, meta: dict | None = None):
        self.model = model
        self.threshold = threshold
        self.meta = meta or {}

    @classmethod
    def fit(cls, benign: list[AlertFeatures], quantile: float = 0.995, seed: int = 42) -> "WindowDetector":
        if len(benign) < 20:
            raise ValueError(f"need at least 20 benign windows to fit, got {len(benign)}")
        X = np.array([feature_vector(f) for f in benign])
        model = _fit_iforest(X, seed)
        scores = model.decision_function(X)
        threshold = float(np.quantile(scores, quantile))
        return cls(model, threshold, {"n_train": len(benign), "quantile": quantile, "features": FEATURE_NAMES})

    def score(self, f: AlertFeatures) -> float | None:
        if self.model is None:
            return None
        return float(self.model.decision_function(np.array([feature_vector(f)]))[0])

    def detect(self, f: AlertFeatures, use_rules: bool = True, use_ml: bool = True) -> DetectorOutput:
        rules = evaluate_rules(f) if use_rules else []
        score = self.score(f) if use_ml else None
        anomalous = score is not None and self.threshold is not None and score > self.threshold
        return DetectorOutput(rules=rules, ml_score=score, ml_threshold=self.threshold, ml_anomaly=anomalous)

    def save(self, path: Path) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"model": self.model, "threshold": self.threshold, "meta": self.meta}, path)

    @classmethod
    def load(cls, path: Path) -> "WindowDetector":
        if not Path(path).exists():
            return cls()  # rules-only until a benign baseline has been trained
        blob = joblib.load(path)
        return cls(blob["model"], blob["threshold"], blob.get("meta"))


# --------------------------------------------------------------------------------------
# Flow-level variant, used on CICIDS2018, where the CSVs have no source IPs to window by
# --------------------------------------------------------------------------------------
FLOW_FEATURES = [
    "log_duration", "log_fwd_bytes", "log_bwd_bytes", "log_fwd_pkts", "log_bwd_pkts",
    "bytes_per_pkt", "syn", "ack", "rst", "udp", "web_port", "auth_port", "log_svc_flows_10s",
]


def flow_matrix(df: pd.DataFrame) -> np.ndarray:
    from hrt.triage.rules import AUTH_PORTS, WEB_PORTS

    pkts = (df["fwd_pkts"] + df["bwd_pkts"]).clip(lower=1)
    return np.column_stack([
        np.log1p(df["duration"]), np.log1p(df["fwd_bytes"]), np.log1p(df["bwd_bytes"]),
        np.log1p(df["fwd_pkts"]), np.log1p(df["bwd_pkts"]),
        np.log1p((df["fwd_bytes"] + df["bwd_bytes"]) / pkts),
        df["syn"].astype(float), df["ack"].astype(float), df["rst"].astype(float),
        (df["proto"] == "udp").astype(float),
        df["dst_port"].isin(WEB_PORTS).astype(float), df["dst_port"].isin(AUTH_PORTS).astype(float),
        np.log1p(df["svc_flows_10s"]),
    ])


class FlowDetector:
    """Unsupervised Isolation Forest fitted on benign flows only.

    `decision_function` is oriented higher = more anomalous (PyOD convention). The alert threshold
    is set purely from benign statistics to hit a target false-positive rate (no labels used), so
    the operating point is chosen the way an unsupervised deployment would.
    """

    def __init__(self, target_fpr: float = 0.05, seed: int = 42):
        self.target_fpr, self.seed = target_fpr, seed
        self.model: IForest | None = None
        self.threshold: float | None = None

    def fit(self, benign: pd.DataFrame) -> "FlowDetector":
        X = flow_matrix(benign)
        self.model = _fit_iforest(X, self.seed)
        # threshold = the (1 - target_fpr) quantile of benign scores -> ~target_fpr benign flagged
        self.threshold = float(np.quantile(self.model.decision_function(X), 1.0 - self.target_fpr))
        return self

    def score(self, df: pd.DataFrame) -> np.ndarray:
        return self.model.decision_function(flow_matrix(df))

    def predict(self, df: pd.DataFrame) -> np.ndarray:
        return (self.score(df) > self.threshold).astype(int)
