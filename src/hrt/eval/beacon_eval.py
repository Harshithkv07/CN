"""C2 beaconing evaluation (improvement item 1).

The 10 s window used by the other Tier-1 rules can only see a beacon that checks in about once a
second. This suite replays simulated implant traffic through the real :class:`TriageEngine` and
measures the long-window rule against:

* beacon period (1 s - 2 min) x jitter (0 - 50 %): detection, and how long after the first
  beacon the alert fires;
* the previous behaviour (10 s window only), for before/after;
* benign traffic that must **not** alert: Poisson web browsing, a client with sleep 2-6 s jitter (the
  lab's benign.sh), scan and flood traffic; plus one known limitation, a perfectly periodic monitoring
  agent, which is indistinguishable from a beacon on timing alone.

The traffic is simulated (no real malware), so this measures the rule, not a real implant.
"""

from __future__ import annotations

import numpy as np

from hrt.config import Settings
from hrt.models import Alert, Flow
from hrt.triage.detector import WindowDetector
from hrt.triage.engine import TriageEngine
from hrt.triage.rules import BEACON_MAX_CV, BEACON_MAX_FWD_BYTES, BEACON_MAX_GAP_RATIO, BEACON_MIN_FLOWS

VICTIM = "10.10.0.10"
ATTACKER = "10.10.0.66"
WINDOW = 900.0
T0 = 1_700_000_000.0


def _flow(ts: float, src: str, dport: int = 80, fwd: int = 180, dst: str = VICTIM, i: int = 0) -> Flow:
    return Flow(ts=ts, src_ip=src, src_port=40000 + i % 20000, dst_ip=dst, dst_port=dport, proto="tcp",
                duration=0.05, fwd_bytes=fwd, bwd_bytes=420, fwd_pkts=4, bwd_pkts=3, syn=True, ack=True,
                rst=False, conn_state="SF")


def beacon_flows(period: float, jitter: float, duration: float, seed: int, src: str = ATTACKER) -> list[Flow]:
    """An implant that checks in every `period` s, each wait scaled by uniform(1-jitter, 1+jitter)."""
    rng = np.random.default_rng(seed)
    t, out, i = T0 + rng.uniform(0, period), [], 0
    while t < T0 + duration:
        out.append(_flow(t, src, i=i, fwd=int(rng.integers(120, 400))))
        t += period * (1 + rng.uniform(-jitter, jitter))
        i += 1
    return out


def poisson_browsing(rate: float, duration: float, seed: int, src: str) -> list[Flow]:
    rng = np.random.default_rng(seed)
    t, out, i = T0, [], 0
    while t < T0 + duration:
        t += rng.exponential(1 / rate)
        out.append(_flow(t, src, dport=int(rng.choice([80, 443])), fwd=int(rng.integers(200, 1800)), i=i))
        i += 1
    return out


def benign_sh_client(duration: float, seed: int, src: str) -> list[Flow]:
    """docker/attacker/benign.sh: curl, then sleep uniform(2, 6) s -> CV about 0.29."""
    rng = np.random.default_rng(seed)
    t, out, i = T0, [], 0
    while t < T0 + duration:
        out.append(_flow(t, src, i=i, fwd=int(rng.integers(150, 300))))
        t += rng.uniform(2, 6)
        i += 1
    return out


def _engine(window_beacon: float, sink) -> TriageEngine:
    return TriageEngine(WindowDetector(), sink, window_seconds=10.0, cooldown_seconds=120.0, origin="replay",
                        beacon_window_seconds=window_beacon)


def _run(flows: list[Flow], beacon_window: float) -> list[Alert]:
    alerts: list[Alert] = []
    _engine(beacon_window, alerts.append).replay(flows)
    return alerts


def _beacon_alert(alerts: list[Alert], src: str) -> Alert | None:
    return next((a for a in alerts if str(a.source_ip) == src and "BEACONING" in a.detector.rules), None)


def run(settings: Settings, fast: bool = False) -> dict:
    periods = [1, 5, 10, 30, 60, 120]
    jitters = [0.0, 0.1, 0.2, 0.3, 0.5]
    trials = 3 if fast else 8
    matrix, before = {}, {}
    for period in periods:
        duration = max(900.0, period * 14)
        for jitter in jitters:
            hits, hits_old, delays = 0, 0, []
            for s in range(trials):
                flows = beacon_flows(period, jitter, duration, seed=1000 * period + 10 * int(jitter * 10) + s)
                a = _beacon_alert(_run(flows, WINDOW), ATTACKER)
                hits += a is not None
                if a is not None:
                    delays.append(a.last_seen - flows[0].ts)
                hits_old += _beacon_alert(_run(flows, 0.0), ATTACKER) is not None
            matrix[f"{period}s/{int(jitter * 100)}%"] = {
                "period_s": period, "jitter": jitter, "detected": round(hits / trials, 3),
                "median_seconds_to_alert": round(float(np.median(delays)), 1) if delays else None}
            before[f"{period}s/{int(jitter * 100)}%"] = round(hits_old / trials, 3)

    # --- traffic that must not alert -------------------------------------------------------------
    benign_dur = 1800.0
    cases: dict[str, list[Flow]] = {}
    mix: list[Flow] = []
    for k in range(6):
        mix += poisson_browsing(0.15, benign_dur, seed=50 + k, src=f"10.10.0.{51 + k}")
    cases["6 clients, Poisson web browsing (30 min)"] = mix
    cases["client with sleep 2-6 s (lab benign.sh)"] = benign_sh_client(benign_dur, 7, "10.10.0.50")
    scan = [_flow(T0 + 60 + i * 0.01, "203.0.113.9", dport=p, fwd=0, i=i) for i, p in enumerate(range(1, 1025))]
    cases["TCP SYN scan, 1024 ports"] = scan
    flood = [_flow(T0 + 60 + i * 0.002, "203.0.113.20", fwd=0, i=i) for i in range(30000)]
    cases["constant-rate SYN flood, 500/s"] = flood
    # statistical false-alarm rate over many independent client-hours (a single run is anecdote)
    n_hours = 20 if fast else 100
    fp_rate = {}
    for name, make in (("Poisson web client", lambda sd: poisson_browsing(0.15, 3600, sd, "10.10.0.51")),
                       ("client with sleep 2-6 s", lambda sd: benign_sh_client(3600, sd, "10.10.0.50"))):
        n_alert = sum(any("BEACONING" in a.detector.rules for a in _run(make(5000 + k), WINDOW)) for k in range(n_hours))
        fp_rate[name] = {"client_hours": n_hours, "hours_with_a_beacon_alert": n_alert,
                         "false_alarm_rate_per_client_hour": round(n_alert / n_hours, 4)}
    benign_fp = {}
    for name, flows in cases.items():
        alerts = _run(flows, WINDOW)
        benign_fp[name] = {"flows": len(flows), "beacon_alerts": sum("BEACONING" in a.detector.rules for a in alerts)}
    periodic = [_flow(T0 + 30 * i, "10.10.0.77", i=i, fwd=150) for i in range(60)]
    limitation = {"perfectly periodic monitoring agent (30 s)": {
        "flows": len(periodic), "beacon_alerts": sum("BEACONING" in a.detector.rules for a in _run(periodic, WINDOW))}}

    return {
        "window_seconds": WINDOW, "trials_per_cell": trials, "benign_false_alarm_rate": fp_rate,
        "rule": {"min_flows": BEACON_MIN_FLOWS, "max_iat_cv": BEACON_MAX_CV, "max_gap_ratio": BEACON_MAX_GAP_RATIO,
                 "max_fwd_bytes": BEACON_MAX_FWD_BYTES, "single_dst_and_port": True, "max_flows_per_s": 2.0},
        "detection": matrix, "detection_10s_window_only": before,
        "benign_false_alarms": benign_fp, "known_limitation": limitation,
        "note": "Simulated implant traffic through the real TriageEngine; not real malware.",
    }
