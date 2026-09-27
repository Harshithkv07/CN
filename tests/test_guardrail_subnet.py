from ipaddress import ip_network

from hrt.guardrail.policy import parse
from hrt.guardrail.subnet import check_subnets, overlaps

PROTECTED = ["10.10.0.0/24", "203.0.113.10/32", "127.0.0.0/8", "0.0.0.0/32"]


def test_overlap_bitwise():
    assert overlaps(ip_network("10.10.0.9/32"), ip_network("10.10.0.0/24"))
    assert overlaps(ip_network("203.0.0.0/8"), ip_network("203.0.113.10/32"))
    assert not overlaps(ip_network("8.8.8.8/32"), ip_network("10.10.0.0/24"))


def test_block_attacker_ok():
    c = check_subnets(parse("iptables -I INPUT 1 -s 203.0.113.9 -j DROP"), PROTECTED, "203.0.113.9")
    assert c.passed


def test_block_internal_lan_refused():
    c = check_subnets(parse("iptables -I INPUT 1 -s 10.10.0.50 -j DROP"), PROTECTED, "203.0.113.9")
    assert not c.passed and "protected subnet" in c.detail


def test_block_all_refused():
    c = check_subnets(parse("iptables -I INPUT 1 -s 0.0.0.0/0 -j DROP"), PROTECTED, "203.0.113.9")
    assert not c.passed


def test_broad_prefix_refused():
    c = check_subnets(parse("iptables -I INPUT 1 -s 203.0.0.0/8 -j DROP"), PROTECTED, "203.0.113.9")
    assert not c.passed


def test_wrong_target_ip_refused():
    c = check_subnets(parse("iptables -I INPUT 1 -s 8.8.8.8 -j DROP"), PROTECTED, "203.0.113.9")
    assert not c.passed and "alert source" in c.detail


def test_protected_source_non_retryable():
    # if the alerting source itself is inside a protected subnet, a human must decide
    c = check_subnets(parse("iptables -I INPUT 1 -s 10.10.0.10 -j DROP"), PROTECTED, "10.10.0.10")
    assert not c.passed and not c.retryable
