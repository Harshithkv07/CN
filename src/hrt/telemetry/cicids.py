"""CSE-CIC-IDS2018 "Processed Traffic Data for ML Algorithms" CSV -> normalised flow frame.

Quirks handled here:
* the day files repeat their header row part-way through;
* ``Flow Duration`` is in microseconds;
* except for Tuesday-20-02 the files have **no IP columns**, so evaluation is flow-level. For
  agent incidents we attach synthetic TEST-NET addresses (see ``hrt.eval.cicids_data``).
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from hrt.models import Flow

CIC_COLUMNS = {
    "Dst Port": "dst_port",
    "Protocol": "proto_num",
    "Timestamp": "timestamp",
    "Flow Duration": "duration_us",
    "Tot Fwd Pkts": "fwd_pkts",
    "Tot Bwd Pkts": "bwd_pkts",
    "TotLen Fwd Pkts": "fwd_bytes",
    "TotLen Bwd Pkts": "bwd_bytes",
    "SYN Flag Cnt": "syn_cnt",
    "ACK Flag Cnt": "ack_cnt",
    "RST Flag Cnt": "rst_cnt",
    "Label": "label",
}
PROTO = {6: "tcp", 17: "udp", 1: "icmp"}


def normalise(raw: pd.DataFrame) -> pd.DataFrame:
    df = raw.rename(columns=lambda c: c.strip()).rename(columns=CIC_COLUMNS)
    df = df[df["label"] != "Label"].copy()  # repeated header rows
    for col in ("dst_port", "proto_num", "duration_us", "fwd_pkts", "bwd_pkts", "fwd_bytes",
                "bwd_bytes", "syn_cnt", "ack_cnt", "rst_cnt"):
        df[col] = pd.to_numeric(df[col], errors="coerce")
    df = df.replace([np.inf, -np.inf], np.nan).dropna(subset=["dst_port", "duration_us", "fwd_pkts"])
    ts = pd.to_datetime(df["timestamp"], format="%d/%m/%Y %H:%M:%S", errors="coerce")
    df = df[ts.notna()].copy()
    # resolution-independent epoch seconds (pandas 3 may parse to "us" instead of "ns")
    df["ts"] = (ts[ts.notna()] - pd.Timestamp("1970-01-01")) / pd.Timedelta(seconds=1)
    out = pd.DataFrame({
        "ts": df["ts"].astype(float),
        "dst_port": df["dst_port"].astype(int),
        "proto": df["proto_num"].fillna(0).astype(int).map(PROTO).fillna("other"),
        "duration": (df["duration_us"].clip(lower=0) / 1e6).astype(float),
        "fwd_bytes": df["fwd_bytes"].fillna(0).clip(lower=0).astype(np.int64),
        "bwd_bytes": df["bwd_bytes"].fillna(0).clip(lower=0).astype(np.int64),
        "fwd_pkts": df["fwd_pkts"].fillna(0).clip(lower=0).astype(np.int64),
        "bwd_pkts": df["bwd_pkts"].fillna(0).clip(lower=0).astype(np.int64),
        "syn": df["syn_cnt"].fillna(0) > 0,
        "ack": df["ack_cnt"].fillna(0) > 0,
        "rst": df["rst_cnt"].fillna(0) > 0,
        "label": df["label"].astype(str).str.strip(),
    })
    # Service-level context computed on the *full* day before sampling: how many flows hit the
    # same destination port within the same 10 s bucket (a standard SOC rate feature).
    bucket = (out["ts"] // 10).astype(np.int64)
    out["svc_flows_10s"] = out.groupby([out["dst_port"], bucket])["ts"].transform("size").astype(np.int64)
    return out.reset_index(drop=True)


def frame_to_flows(df: pd.DataFrame, src_ip: str, dst_ip: str) -> list[Flow]:
    return [
        Flow(ts=r.ts, src_ip=src_ip, src_port=0, dst_ip=dst_ip, dst_port=int(r.dst_port),
             proto=r.proto, duration=r.duration, fwd_bytes=int(r.fwd_bytes), bwd_bytes=int(r.bwd_bytes),
             fwd_pkts=int(r.fwd_pkts), bwd_pkts=int(r.bwd_pkts), syn=bool(r.syn), ack=bool(r.ack),
             rst=bool(r.rst), label=r.label)
        for r in df.itertuples(index=False)
    ]
