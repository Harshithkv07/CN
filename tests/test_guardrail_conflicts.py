from hrt.guardrail.conflicts import check_conflicts, parse_ruleset
from hrt.guardrail.policy import parse

BASELINE = [
    "-A INPUT -i lo -j ACCEPT",
    "-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
    "-A INPUT -p tcp --dport 80 -j ACCEPT",
]


def test_duplicate_detected():
    rs = parse_ruleset([*BASELINE, "-A INPUT -s 203.0.113.9 -j DROP"])
    c = check_conflicts(parse("iptables -A INPUT -s 203.0.113.9 -j DROP"), rs)
    assert not c.passed and c.detail.startswith("duplicate") and not c.retryable


def test_shadowed_append_after_accept():
    rs = parse_ruleset(BASELINE)
    # appending a DROP with no port after an ACCEPT dport 80 means port-80 traffic is shadowed
    c = check_conflicts(parse("iptables -A INPUT -s 203.0.113.9 -j DROP"), rs)
    assert not c.passed and "shadowed" in c.detail


def test_insert_at_top_ok():
    rs = parse_ruleset(BASELINE)
    c = check_conflicts(parse("iptables -I INPUT 1 -s 203.0.113.9 -j DROP"), rs)
    assert c.passed


def test_established_accept_not_shadowing():
    rs = parse_ruleset(["-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"])
    c = check_conflicts(parse("iptables -A INPUT -s 203.0.113.9 -j DROP"), rs)
    assert c.passed
