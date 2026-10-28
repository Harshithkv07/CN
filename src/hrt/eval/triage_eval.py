"""Tier-1 detection evaluation on CICIDS2018 (flow-level, binary benign vs malicious).

Compares three detectors on an identical held-out split:
  * HRT   - Isolation Forest fitted on benign flows only (unsupervised, no labels). Its one
            hyper-parameter that mattered (max_samples) is chosen on a validation split carved out
            of the training data, never on the test split.
  * HRT_hybrid - the Tier-1 design as built: Isolation Forest OR the deterministic flow rules
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
    benign = y_true == 0
    out = {"precision": round(p, 4), "recall": round(r, 4), "f1": round(f1, 4),
           "false_positive_rate": round(float(y_pred[benign].mean()), 4) if benign.any() else None,
           "accuracy": round(float((y_true == y_pred).mean()), 4), "n": int(len(y_true)),
           "n_malicious": int(y_true.sum())}
    if scores is not None and len(np.unique(y_true)) > 1:
        out["roc_auc"] = round(float(roc_auc_score(y_true, scores)), 4)
        out["pr_auc"] = round(float(average_precision_score(y_true, scores)), 4)
    return out


def _f1(y_true, y_pred) -> float:
    return float(precision_recall_fscore_support(y_true, y_pred, average="binary", zero_division=0)[2])


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
    tr, te = train_test_split(idx, test_size=0.3, random_state=42, stratify=y)   # same split as v1
    train_df, test_df = df.iloc[tr], df.iloc[te]
    y_test = y[te]

    # --- model selection on a validation split of the *training* data (test split untouched) ------
    fit_i, val_i = train_test_split(tr, test_size=0.25, random_state=1, stratify=y[tr])
    fit_benign = df.iloc[fit_i][y[fit_i] == 0]
    sweep = {}
    for ms in (256, 512, 1024, 2048):
        det = FlowDetector(target_fpr=0.05, max_samples=ms).fit(fit_benign)
        sweep[str(ms)] = {"val_f1": round(_f1(y[val_i], det.predict(df.iloc[val_i])), 4),
                          "val_recall": round(float(det.predict(df.iloc[val_i])[y[val_i] == 1].mean()), 4)}
    best_ms = int(max(sweep, key=lambda k: sweep[k]["val_f1"]))
    log.info("iforest max_samples sweep (validation): %s -> %d", sweep, best_ms)

    # HRT: Isolation Forest fitted on the benign portion of the training split only (unsupervised).
    # Operating point is a 5% benign false-positive budget set from benign statistics alone.
    benign_train = train_df[train_df["label"].map(is_malicious) == False]  # noqa: E712
    hrt = FlowDetector(target_fpr=0.05, max_samples=best_ms).fit(benign_train)
    hrt_scores = hrt.score(test_df)   # PyOD: higher = more anomalous
    hrt_pred = hrt.predict(test_df)
    v1 = FlowDetector(target_fpr=0.05, n_estimators=200, max_samples=256).fit(benign_train)   # previous setting

    # SIEM baseline, and the hybrid Tier-1 (forest OR rules)
    siem_pred = siem_baseline.predict(test_df)
    hybrid_pred = np.maximum(hrt_pred, siem_pred)

    # Reference only (not part of the pipeline): the best a distance-based unsupervised model reaches
    from pyod.models.knn import KNN

    knn = KNN(n_neighbors=10).fit(flow_matrix(benign_train))
    knn_thr = float(np.quantile(knn.decision_function(flow_matrix(benign_train)), 0.95))
    knn_scores = knn.decision_function(flow_matrix(test_df))
    knn_pred = (knn_scores > knn_thr).astype(int)

    # Supervised RF upper bound
    rf = RandomForestClassifier(n_estimators=120, max_depth=18, n_jobs=-1, random_state=42, class_weight="balanced")
    rf.fit(flow_matrix(train_df), y[tr])
    rf_scores = rf.predict_proba(flow_matrix(test_df))[:, 1]
    rf_pred = (rf_scores >= 0.5).astype(int)

    # per-class recall (how well each attack family is caught) for the forest alone and the hybrid
    per_class = {}
    labels = test_df["label"].to_numpy()
    for label in sorted(set(labels)):
        mask = labels == label
        key = "recall" if is_malicious(label) else "false_positive_rate"
        per_class[label] = {"n": int(mask.sum()), key: round(float(hrt_pred[mask].mean()), 4),
                            f"hybrid_{key}": round(float(hybrid_pred[mask].mean()), 4),
                            f"v1_{key}": round(float(v1.predict(test_df)[mask].mean()), 4)}

    # Telemetry reduction is *measured* on the real lab capture by `hrt eval telemetry`; CICIDS rows
    # are pre-aggregated CICFlowMeter records, so no byte-level reduction is claimed from them.
    result = {
        "dataset": "CICIDS2018 (stratified sample)",
        "rows": int(len(df)), "classes": sorted(df["label"].unique().tolist()),
        "iforest_sweep_validation": sweep, "iforest_max_samples": best_ms,
        "detectors": {
            "HRT_iforest": _metrics(y_test, hrt_pred, hrt_scores),
            "HRT_iforest_v1": _metrics(y_test, v1.predict(test_df), v1.score(test_df)),
            "HRT_hybrid": _metrics(y_test, hybrid_pred, None),
            "SIEM_rules": _metrics(y_test, siem_pred, siem_pred.astype(float)),
            "KNN_reference": _metrics(y_test, knn_pred, knn_scores),
            "RandomForest_supervised": _metrics(y_test, rf_pred, rf_scores),
        },
        "hrt_per_class": per_class,
    }
    return result
