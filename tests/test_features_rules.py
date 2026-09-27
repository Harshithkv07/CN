from hrt.triage.features import feature_vector, window_features
from hrt.triage.rules import evaluate_rules, tactics_for


def test_scan_features(scan_flows):
    f = window_features(scan_flows, 10.0)
    assert f.n_dst_ports >= 30
    assert f.half_open_frac == 1.0
    assert f.syn_ack_ratio >= 10
    assert len(feature_vector(f)) == 14


def test_port_scan_rule_fires(scan_alert):
    assert "PORT_SCAN" in scan_alert.detector.rules
    assert "discovery" in tactics_for(scan_alert.detector.rules)


def test_beaconing_not_on_scan(scan_flows):
    # a wide scan hits many ports, so the C2 beaconing rule must not fire
    f = window_features(scan_flows, 10.0)
    assert "BEACONING" not in evaluate_rules(f)


def test_brute_force_rule():
    from hrt.models import Flow
    from hrt.triage.features import window_features as wf

    base = 1_700_000_000.0
    flows = [Flow(ts=base + i * 0.1, src_ip="203.0.113.5", src_port=40000 + i, dst_ip="10.10.0.10",
                  dst_port=22, proto="tcp", duration=0.2, fwd_bytes=800, bwd_bytes=600, fwd_pkts=6,
                  bwd_pkts=5, syn=True, ack=True, rst=False, conn_state="SF") for i in range(25)]
    assert "BRUTE_FORCE" in evaluate_rules(wf(flows, 10.0))
