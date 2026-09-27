import pandas as pd

from hrt.rag.query import behaviour_query, candidate_tactics, service_name
from hrt.telemetry.cicids import normalise


def test_behaviour_query_mentions_ports_and_pattern(scan_alert):
    q = behaviour_query(scan_alert)
    assert "port" in q.lower()
    assert "port scan" in q.lower()
    assert candidate_tactics(scan_alert)  # non-empty


def test_service_name():
    assert service_name(22) == "SSH"
    assert service_name(443) == "HTTPS"
    assert "9999" in service_name(9999)


def test_cicids_normalise_handles_repeated_headers_and_units():
    raw = pd.DataFrame({
        "Dst Port": ["80", "Dst Port", "22"],
        "Protocol": ["6", "Protocol", "6"],
        "Timestamp": ["14/02/2018 08:31:01", "Timestamp", "14/02/2018 08:31:02"],
        "Flow Duration": ["1000000", "Flow Duration", "2000000"],   # microseconds
        "Tot Fwd Pkts": ["5", "Tot Fwd Pkts", "3"],
        "Tot Bwd Pkts": ["4", "Tot Bwd Pkts", "2"],
        "TotLen Fwd Pkts": ["500", "TotLen Fwd Pkts", "0"],
        "TotLen Bwd Pkts": ["400", "TotLen Bwd Pkts", "0"],
        "SYN Flag Cnt": ["1", "SYN Flag Cnt", "1"],
        "ACK Flag Cnt": ["1", "ACK Flag Cnt", "0"],
        "RST Flag Cnt": ["0", "RST Flag Cnt", "0"],
        "Label": ["Benign", "Label", "SSH-Bruteforce"],
    })
    out = normalise(raw)
    assert len(out) == 2                       # header row dropped
    assert out.iloc[0]["duration"] == 1.0      # microseconds -> seconds
    assert out.iloc[0]["proto"] == "tcp"
    assert set(out["label"]) == {"Benign", "SSH-Bruteforce"}
