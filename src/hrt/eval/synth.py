"""Synthesise realistic Tier-1 alerts from labelled CICIDS2018 flows for agent evaluation.

The CSVs have no source IPs, so per-attack-family flow groups are aggregated into an
:class:`Alert` with a synthetic TEST-NET attacker address. Documented as synthetic in the report.
"""

from __future__ import annotations

import time

import numpy as np
import pandas as pd

from hrt.eval.cicids_data import SYNTH_ATTACKER
from hrt.eval.labels import CIC_LABELS
from hrt.models import Alert, Flow
from hrt.triage.features import window_features
from hrt.triage.rules import evaluate_rules


def _spacing(rows: pd.DataFrame) -> float:
    """Inter-arrival time taken from the capture itself: CICIDS records, for every flow, how many
    flows hit the same service in that 10 s bucket (svc_flows_10s). A flood therefore arrives
    densely and a slow brute force sparsely, as observed in the real data, not a tuned constant."""
    rate = float(rows["svc_flows_10s"].median()) if "svc_flows_10s" in rows else 20.0
    return min(max(10.0 / max(rate, 1.0), 0.001), 2.0)


def _rows_to_flows(rows: pd.DataFrame, src: str, seed: int = 0) -> list[Flow]:
    # Poisson arrivals (exponential gaps) at the measured mean rate: independent connections have
    # random jitter, unlike a periodic C2 beacon, so perfectly even spacing would be an artifact.
    gaps = np.random.default_rng(seed).exponential(_spacing(rows), size=len(rows))
    ts = time.time() + np.cumsum(gaps)
    flows = []
    for i, r in enumerate(rows.itertuples(index=False)):
        flows.append(Flow(ts=float(ts[i]), src_ip=src, src_port=40000 + i % 20000, dst_ip="10.10.0.10",
                          dst_port=int(r.dst_port), proto=r.proto, duration=float(r.duration),
                          fwd_bytes=int(r.fwd_bytes), bwd_bytes=int(r.bwd_bytes), fwd_pkts=int(r.fwd_pkts),
                          bwd_pkts=int(r.bwd_pkts), syn=bool(r.syn), ack=bool(r.ack), rst=bool(r.rst),
                          label=r.label))
    return flows


def alerts_from_sample(df: pd.DataFrame, per_class: int = 10, group_size: int = 250, seed: int = 7) -> list[tuple[Alert, str]]:
    """Return (alert, cic_label) pairs, `per_class` per malicious family."""
    rng = np.random.default_rng(seed)
    out: list[tuple[Alert, str]] = []
    for label, grp in df.groupby("label"):
        spec = CIC_LABELS.get(label)
        if not spec or not spec["malicious"] or len(grp) < group_size:
            continue
        src = SYNTH_ATTACKER.get(spec["family"], "198.51.100.99")
        for k in range(per_class):
            sample = grp.sample(min(group_size, len(grp)), random_state=int(rng.integers(1 << 30)))
            flows = _rows_to_flows(sample, src, seed=int(rng.integers(1 << 30)))
            feats = window_features(flows, 10.0)
            from hrt.models import DetectorOutput

            alert = Alert(source_ip=src, dst_ips=["10.10.0.10"], first_seen=flows[0].ts, last_seen=flows[-1].ts,
                          detector=DetectorOutput(rules=evaluate_rules(feats), ml_anomaly=True),
                          features=feats, raw_flow_count=len(flows), origin="replay", ground_truth=label)
            out.append((alert, label))
    return out
