import json

from hrt.telemetry.zeek import parse_conn_record, parse_line


def test_parse_conn_syn_only():
    rec = {"ts": 1.0, "id.orig_h": "203.0.113.9", "id.orig_p": 44000, "id.resp_h": "10.10.0.10",
           "id.resp_p": 22, "proto": "tcp", "history": "S", "conn_state": "S0", "duration": 0.0}
    f = parse_conn_record(rec)
    assert f.syn and not f.ack and f.proto == "tcp" and f.dst_port == 22


def test_parse_conn_full_handshake():
    rec = {"ts": 2.0, "id.orig_h": "10.10.0.50", "id.resp_h": "10.10.0.10", "id.resp_p": 80,
           "proto": "tcp", "history": "ShADadfF", "orig_bytes": 100, "resp_bytes": 500}
    f = parse_conn_record(rec)
    assert f.syn and f.ack and f.fwd_bytes == 100 and f.bwd_bytes == 500


def test_parse_line_skips_ipv6_and_junk():
    assert parse_line("not json") is None
    assert parse_line(json.dumps({"id.orig_h": "::1", "id.resp_h": "10.0.0.1"})) is None


def test_missing_fields_default():
    f = parse_conn_record({"id.orig_h": "1.2.3.4", "id.resp_h": "5.6.7.8"})
    assert f.duration == 0.0 and f.fwd_bytes == 0
