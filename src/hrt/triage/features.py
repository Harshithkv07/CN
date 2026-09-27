"""Aggregate one source's flows inside a time window into :class:`AlertFeatures`.

This is where the telemetry blind spot gets closed: thousands of connection records collapse into
about twenty numbers, which is what the LLM sees.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence

import numpy as np

from hrt.models import AlertFeatures, Flow
from hrt.telemetry.zeek import REJECT_STATES


def _rejected(f: Flow) -> bool:
    if f.conn_state:
        return f.conn_state in REJECT_STATES
    return f.rst and not f.ack  # CICIDS rows carry no conn_state


def window_features(flows: Sequence[Flow], window_seconds: float) -> AlertFeatures:
    n = len(flows)
    if n == 0:
        raise ValueError("empty window")
    tcp = [f for f in flows if f.proto == "tcp"]
    ports = Counter(f.dst_port for f in flows)
    dominant_count = ports.most_common(1)[0][1]
    syn = sum(f.syn for f in tcp)
    ack = sum(f.ack for f in tcp)
    half_open = sum(f.syn and not f.ack for f in tcp)
    ts = sorted(f.ts for f in flows)
    span = ts[-1] - ts[0]
    iat_cv = 0.0
    if n >= 3:
        gaps = np.diff(ts)
        mean_gap = float(gaps.mean())
        iat_cv = float(gaps.std() / mean_gap) if mean_gap > 0 else 0.0
    fwd = sum(f.fwd_bytes for f in flows)
    return AlertFeatures(
        window_seconds=round(window_seconds, 2),
        n_flows=n,
        n_tcp=len(tcp),
        n_udp=sum(f.proto == "udp" for f in flows),
        n_dst_hosts=len({f.dst_ip for f in flows}),
        n_dst_ports=len(ports),
        top_dst_ports=[p for p, _ in ports.most_common(5)],
        dominant_port_share=round(dominant_count / n, 4),
        syn_count=syn,
        ack_count=ack,
        syn_ack_ratio=round(syn / max(ack, 1), 3),
        half_open_frac=round(half_open / max(len(tcp), 1), 4),
        rej_frac=round(sum(_rejected(f) for f in flows) / n, 4),
        flows_per_s=round(n / max(span, 1.0), 3),
        mean_duration_s=round(sum(f.duration for f in flows) / n, 4),
        fwd_bytes=int(fwd),
        bwd_bytes=int(sum(f.bwd_bytes for f in flows)),
        mean_fwd_bytes=round(fwd / n, 2),
        iat_cv=round(min(iat_cv, 50.0), 4),
    )


FEATURE_NAMES = [
    "log_flows", "log_dst_hosts", "log_dst_ports", "dominant_port_share", "log_syn_ack_ratio",
    "half_open_frac", "rej_frac", "log_flows_per_s", "log_mean_duration", "log_mean_fwd_bytes",
    "log_fwd_bytes", "log_bwd_bytes", "udp_frac", "iat_cv",
]


def feature_vector(f: AlertFeatures) -> list[float]:
    l1p = math.log1p
    return [
        l1p(f.n_flows), l1p(f.n_dst_hosts), l1p(f.n_dst_ports), f.dominant_port_share,
        l1p(f.syn_ack_ratio), f.half_open_frac, f.rej_frac, l1p(f.flows_per_s),
        l1p(f.mean_duration_s), l1p(f.mean_fwd_bytes), l1p(f.fwd_bytes), l1p(f.bwd_bytes),
        f.n_udp / max(f.n_flows, 1), min(f.iat_cv, 5.0),
    ]


def sliding_windows(flows: Iterable[Flow], window: float, step: float) -> list[tuple[str, float, list[Flow]]]:
    """(src_ip, window_end, flows) for every source and every ``step`` seconds (training / offline)."""
    by_src: dict[str, list[Flow]] = defaultdict(list)
    for f in flows:
        by_src[f.src_ip].append(f)
    out = []
    for src, fl in by_src.items():
        fl.sort(key=lambda x: x.ts)
        tss = np.array([x.ts for x in fl])
        end = tss[0] + window
        while end <= tss[-1] + step:
            lo, hi = np.searchsorted(tss, end - window, "left"), np.searchsorted(tss, end, "right")
            if hi > lo:
                out.append((src, float(end), fl[lo:hi]))
            end += step
    return out
