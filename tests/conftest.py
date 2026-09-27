import time

import pytest

from hrt.models import Alert, AlertFeatures, DetectorOutput, Flow


@pytest.fixture
def scan_flows():
    base = 1_700_000_000.0
    return [Flow(ts=base + i * 0.01, src_ip="203.0.113.9", src_port=40000 + i, dst_ip="10.10.0.10",
                 dst_port=p, proto="tcp", duration=0.001, fwd_bytes=0, bwd_bytes=0, fwd_pkts=1, bwd_pkts=0,
                 syn=True, ack=False, rst=True, conn_state="REJ")
            for i, p in enumerate(range(1, 40))]


@pytest.fixture
def benign_flows():
    import random

    random.seed(3)
    base = 1_700_000_000.0
    out = []
    for i in range(500):
        out.append(Flow(ts=base + i * 0.4, src_ip=f"10.10.0.{50 + i % 6}", src_port=random.randint(1024, 65535),
                        dst_ip="10.10.0.10", dst_port=random.choice([80, 443]), proto="tcp",
                        duration=random.uniform(0.05, 1.8), fwd_bytes=random.randint(200, 1800),
                        bwd_bytes=random.randint(200, 4000), fwd_pkts=random.randint(2, 9),
                        bwd_pkts=random.randint(2, 9), syn=True, ack=True, rst=False, conn_state="SF"))
    return out


@pytest.fixture
def scan_alert(scan_flows):
    from hrt.triage.features import window_features
    from hrt.triage.rules import evaluate_rules

    f = window_features(scan_flows, 10.0)
    return Alert(source_ip="203.0.113.9", dst_ips=["10.10.0.10"], first_seen=scan_flows[0].ts,
                 last_seen=scan_flows[-1].ts, detector=DetectorOutput(rules=evaluate_rules(f), ml_anomaly=True),
                 features=f, raw_flow_count=len(scan_flows), origin="test")
