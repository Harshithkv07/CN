"""Emulated SIEM-style correlation rules, the Tier-1 detection baseline.

These are the kind of static threshold rules a traditional SIEM (Splunk/QRadar-style) applies to
flow records: per-flow signatures for floods, slow-DoS, brute force and scanning. Honestly
labelled in the report as 'SIEM-style rules', not the commercial products themselves.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from hrt.triage.rules import AUTH_PORTS, WEB_PORTS


def predict(df: pd.DataFrame) -> np.ndarray:
    """Flow-level: 1 = flagged malicious. Mirrors common SIEM signatures on CICFlowMeter fields."""
    total_bytes = df["fwd_bytes"] + df["bwd_bytes"]
    total_pkts = (df["fwd_pkts"] + df["bwd_pkts"]).clip(lower=1)
    dur = df["duration"].clip(lower=1e-6)
    rate = df["svc_flows_10s"]

    syn_no_ack = df["syn"] & ~df["ack"]                        # half-open handshake
    flood = (rate >= 200)                                      # very high per-service flow rate
    slow_dos = df["dst_port"].isin(WEB_PORTS) & (dur >= 20) & (total_bytes / dur < 50)
    brute = df["dst_port"].isin(AUTH_PORTS) & (rate >= 20) & (total_bytes < 20_000)
    scan = syn_no_ack & (df["bwd_pkts"] == 0) & (total_bytes < 200)
    empty = (total_pkts <= 2) & (total_bytes < 100) & (rate >= 50)

    flagged = flood | slow_dos | brute | scan | empty
    return flagged.to_numpy().astype(int)
