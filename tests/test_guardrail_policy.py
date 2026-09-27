import pytest

from hrt.guardrail.policy import PolicyError, parse


def test_valid_block_rule():
    p = parse("iptables -I INPUT 1 -s 203.0.113.9 -j DROP")
    assert p.op == "-I" and p.chain == "INPUT" and p.target == "DROP" and p.position == 1
    assert p.restore_line == "-I INPUT 1 -s 203.0.113.9 -j DROP"


@pytest.mark.parametrize("rule", [
    "iptables -A INPUT -s 203.0.113.9 -j DROP; rm -rf /",
    "iptables -A INPUT -s 203.0.113.9 -j DROP | nc x 1",
    "iptables -A INPUT -s 203.0.113.9 -j DROP $(reboot)",
    "iptables -A INPUT -s 203.0.113.9 -j DROP && iptables -F",
])
def test_shell_metacharacters_rejected(rule):
    with pytest.raises(PolicyError):
        parse(rule)


@pytest.mark.parametrize("rule", [
    "iptables -F",
    "iptables -P INPUT DROP",
    "iptables -X",
    "iptables -A INPUT -s 203.0.113.9 -j ACCEPT",
    "iptables -A INPUT -j DROP",                    # unscoped
    "iptables -t nat -A PREROUTING -s 203.0.113.9 -j DROP",
    "iptables -A INPUT ! -s 203.0.113.9 -j DROP",   # negation
    "echo hi",
])
def test_disallowed_rules(rule):
    with pytest.raises(PolicyError):
        parse(rule)


def test_argv_has_no_shell():
    p = parse("iptables -I INPUT 1 -s 203.0.113.9 -p tcp --dport 22 -j DROP")
    assert p.argv[0] == "iptables" and "-s" in p.argv and "203.0.113.9" in p.argv
