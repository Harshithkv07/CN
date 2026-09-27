"""Tier-1 detection evaluation on CICIDS2018 (flow-level, binary benign vs malicious).

Compares three detectors on an identical held-out split:
  * HRT   - Isolation Forest fitted on benign flows only (unsupervised, no labels)
  * SIEM  - emulated static correlation rules (unsupervised)
  * RF    - supervised Random Forest (labelled upper-bound reference)
Also reports the telemetry data-reduction achieved by windowed aggregation.
"""

from __future__ import annotations

import logging

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (average_precision_score, precision_recall_fscore_support, roc_auc_score)
from sklearn.model_selection import train_test_split

from hrt.config import Settings
from hrt.eval import siem_baseline
from hrt.eval.cicids_data import build_sample, load_sample
from hrt.eval.labels import is_malicious
from hrt.triage.detector import FlowDetector, flow_matrix

log = logging.getLogger("hrt.eval.triage")


def _metrics(y_true: np.ndarray, y_pred: np.ndarray, scores: np.ndarray | None) -> dict:
    p, r, f1, _ = precision_recall_fscore_support(y_true, y_pred, average="binary", zero_division=0)
    out = {"precision": round(p, 4), "recall": round(r, 4), "f1": round(f1, 4),
           "accuracy": round(float((y_true == y_pred).mean()), 4), "n": int(len(y_true)),
           "n_malicious": int(y_true.sum())}
    if scores is not None and len(np.unique(y_true)) > 1:
        out["roc_auc"] = round(float(roc_auc_score(y_true, scores)), 4)
        out["pr_auc"] = round(float(average_precision_score(y_true, scores)), 4)
    return out


def run(settings: Settings, fast: bool = False) -> dict:
    try:
        df = load_sample(settings)
    except SystemExit:
        log.info("no sample yet; fetching CICIDS2018 slices ...")
        build_sample(settings)
        df = load_sample(settings)

    df = df.reset_index(drop=True)
    y = df["label"].map(is_malicious).astype(int).to_numpy()
    idx = np.arange(len(df))
    tr, te = train_test_split(idx, test_size=0.3, random_state=42, stratify=y)
    train_df, test_df = df.iloc[tr], df.iloc[te]
    y_test = y[te]

    # HRT: fit Isolation Forest on the benign portion of the training split only (unsupervised).
    # Operating point set to a 5% benign false-positive budget from benign statistics alone.
    benign_train = train_df[train_df["label"].map(is_malicious) == False]  # noqa: E712
    hrt = FlowDetector(target_fpr=0.05).fit(benign_train)
    hrt_scores = hrt.score(test_df)   # PyOD: higher = more anomalous
    hrt_pred = hrt.predict(test_df)

    # SIEM baseline
    siem_pred = siem_baseline.predict(test_df)

    # Supervised RF upper bound
    rf = RandomForestClassifier(n_estimators=120, max_depth=18, n_jobs=-1, random_state=42, class_weight="balanced")
    rf.fit(flow_matrix(train_df), y[tr])
    rf_scores = rf.predict_proba(flow_matrix(test_df))[:, 1]
    rf_pred = (rf_scores >= 0.5).astype(int)

    # per-class recall for HRT (how well each attack family is caught)
    per_class = {}
    for label, grp in test_df.groupby("label"):
        mask = test_df["label"].to_numpy() == label
        if is_malicious(label):
            per_class[label] = {"n": int(mask.sum()), "recall": round(float(hrt_pred[mask].mean()), 4)}
        else:
            per_class[label] = {"n": int(mask.sum()), "false_positive_rate": round(float(hrt_pred[mask].mean()), 4)}

    # Telemetry reduction is *measured* on the real lab capture by `hrt eval telemetry`; CICIDS rows
    # are pre-aggregated CICFlowMeter records, so no byte-level reduction is claimed from them.
    result = {
        "dataset": "CICIDS2018 (stratified sample)",
        "rows": int(len(df)), "classes": sorted(df["label"].unique().tolist()),
        "detectors": {
            "HRT_iforest": _metrics(y_test, hrt_pred, hrt_scores),
            "SIEM_rules": _metrics(y_test, siem_pred, siem_pred.astype(float)),
            "RandomForest_supervised": _metrics(y_test, rf_pred, rf_scores),
        },
        "hrt_per_class": per_class,
    }
    return result
