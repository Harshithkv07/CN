"""Deterministic, explainable threshold rules for Tier 1.

Each rule also yields ATT&CK tactic hints. Tier 2 uses those to shrink the vector search
space (hierarchical RAG).
"""

from __future__ import annotations

from collections.abc import Callable

from hrt.models import AlertFeatures

AUTH_PORTS = {21, 22, 23, 25, 110, 143, 389, 445, 1433, 3306, 3389, 5432, 5900}
WEB_PORTS = {80, 443, 8000, 8080, 8443}


def _dominant_port(f: AlertFeatures) -> int | None:
    return f.top_dst_ports[0] if f.top_dst_ports else None


# name -> (ATT&CK tactic hints, human description, predicate)
RULES: dict[str, tuple[tuple[str, ...], str, Callable[[AlertFeatures], bool]]] = {
    "PORT_SCAN": (
        ("discovery", "reconnaissance"),
        "many distinct destination ports probed, mostly half-open or rejected",
        lambda f: f.n_dst_ports >= 15 and (f.half_open_frac >= 0.5 or f.rej_frac >= 0.5),
    ),
    "HOST_SWEEP": (
        ("discovery", "reconnaissance"),
        "the same port probed across many hosts",
        lambda f: f.n_dst_hosts >= 10 and f.dominant_port_share >= 0.8,
    ),
    "SYN_FLOOD": (
        ("impact",),
        "high SYN/ACK half-open ratio concentrated on few ports",
        lambda f: f.n_tcp >= 100 and f.syn_ack_ratio >= 10 and f.dominant_port_share >= 0.5,
    ),
    "CONN_FLOOD": (
        ("impact",),
        "very high connection rate against one service",
        lambda f: f.n_flows >= 200 and f.flows_per_s >= 50 and f.dominant_port_share >= 0.5,
    ),
    "UDP_FLOOD": (
        ("impact",),
        "high-rate UDP traffic from one source",
        lambda f: f.n_udp >= 200 and f.n_udp / max(f.n_flows, 1) >= 0.8,
    ),
    "BRUTE_FORCE": (
        ("credential-access",),
        "repeated short sessions against an authentication service",
        lambda f: _dominant_port(f) in AUTH_PORTS
        and f.n_flows * f.dominant_port_share >= 10
        and f.mean_fwd_bytes < 20_000,
    ),
    "SLOW_DOS": (
        ("impact",),
        "many long-lived, low-throughput sessions held open against a web service",
        lambda f: _dominant_port(f) in WEB_PORTS
        and f.n_flows >= 20
        and f.mean_duration_s >= 20
        and f.mean_fwd_bytes / max(f.mean_duration_s, 1e-6) < 50,
    ),
    "BEACONING": (
        ("command-and-control",),
        "periodic small connections to one host and port (regular inter-arrival times)",
        lambda f: f.n_flows >= 8 and f.iat_cv <= 0.25 and f.mean_fwd_bytes <= 2_000 and f.flows_per_s <= 5
        and f.n_dst_hosts == 1 and f.n_dst_ports <= 2 and f.dominant_port_share >= 0.8,
    ),
    "EXFILTRATION": (
        ("exfiltration",),
        "unusually large outbound transfer",
        lambda f: f.fwd_bytes >= 50_000_000,
    ),
}


# Long-window C2 beacon rule. The 10 s window used by the other rules only ever holds a beacon that
# checks in about once a second; real implants wait 5-120 s. TriageEngine keeps a small per
# (source, destination, port) history of tiny connections and applies this rule to it.
BEACON_MIN_FLOWS = 6
BEACON_MAX_CV = 0.15         # inter-arrival coefficient of variation; uniform jitter of +-j gives ~0.58*j
BEACON_MAX_GAP_RATIO = 1.6   # longest gap / shortest gap; a jittery human-ish client spreads far wider
BEACON_MAX_FWD_BYTES = 2_000


def beaconing_long(f: AlertFeatures) -> bool:
    return (f.n_flows >= BEACON_MIN_FLOWS and f.iat_cv <= BEACON_MAX_CV and f.mean_fwd_bytes <= BEACON_MAX_FWD_BYTES
            and f.n_dst_hosts == 1 and f.n_dst_ports == 1
            and f.flows_per_s <= 2.0)      # slower than 2/s: a regular flood is the flood rules' job


def evaluate_rules(f: AlertFeatures) -> list[str]:
    hits = [name for name, (_, _, pred) in RULES.items() if pred(f)]
    # a port scan also produces a high SYN/ACK ratio; keep the more specific label only
    if "PORT_SCAN" in hits and "SYN_FLOOD" in hits:
        hits.remove("SYN_FLOOD")
    return hits


def tactics_for(rule_names: list[str]) -> list[str]:
    seen: list[str] = []
    for name in rule_names:
        for t in RULES[name][0]:
            if t not in seen:
                seen.append(t)
    return seen


def describe(rule_names: list[str]) -> list[str]:
    return [f"{n}: {RULES[n][1]}" for n in rule_names]
