"""Long-window C2 beacon detection in TriageEngine."""

from hrt.eval.beacon_eval import ATTACKER, T0, _flow, _run, beacon_flows, benign_sh_client, poisson_browsing
from hrt.triage.engine import TriageEngine
from hrt.triage.detector import WindowDetector


def _beacon_alerts(alerts):
    return [a for a in alerts if "BEACONING" in a.detector.rules]


def test_slow_beacon_is_detected_only_with_the_long_window():
    flows = beacon_flows(period=30, jitter=0.1, duration=1800, seed=1)
    assert _beacon_alerts(_run(flows, 900.0))
    assert not _beacon_alerts(_run(flows, 0.0)), "a 30 s beacon never fills the 10 s window"


def test_alert_names_source_and_single_destination():
    a = _beacon_alerts(_run(beacon_flows(10, 0.0, 600, seed=2), 900.0))[0]
    assert str(a.source_ip) == ATTACKER and [str(d) for d in a.dst_ips] == ["10.10.0.10"]
    assert a.features.n_dst_ports == 1 and a.features.iat_cv < 0.01


def test_poisson_browsing_does_not_alert():
    flows = [f for k in range(4) for f in poisson_browsing(0.15, 1800, 10 + k, f"10.10.0.{51 + k}")]
    assert not _beacon_alerts(_run(flows, 900.0))


def test_heavily_jittered_client_does_not_alert():
    assert not _beacon_alerts(_run(benign_sh_client(1800, 4, "10.10.0.50"), 900.0))


def test_scan_does_not_look_like_beacon(scan_flows):
    assert not _beacon_alerts(_run(scan_flows, 900.0))


def test_constant_rate_flood_is_not_a_beacon():
    flood = [_flow(T0 + i * 0.002, "203.0.113.20", fwd=0, i=i) for i in range(20000)]
    assert not _beacon_alerts(_run(flood, 900.0))


def test_beacon_state_is_bounded():
    eng = TriageEngine(WindowDetector(), lambda a: None, beacon_window_seconds=900.0)
    eng.replay([_flow(T0 + i * 0.001, "203.0.113.20", fwd=0, i=i) for i in range(5000)])
    assert all(len(d) <= 64 for d in eng.beacons.values())


def test_one_alert_per_implant_per_five_minutes():
    alerts = _beacon_alerts(_run(beacon_flows(period=8, jitter=0.05, duration=600, seed=3), 900.0))
    assert len(alerts) == 2      # 600 s of beaconing: first alert after six check-ins, the next only after 300 s
