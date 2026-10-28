"""Static Snort/Suricata signature gate."""

import pytest

from hrt.guardrail.snort import check_snort, parse_snort, render_snort, snort_sid

PROTECTED = ["10.10.0.1/32", "10.10.0.10/32", "10.10.0.50/32", "127.0.0.0/8"]
SRC = "203.0.113.9"
GOOD = f'drop ip {SRC} any -> $HOME_NET any (msg:"HRT block"; classtype:attempted-recon; sid:1000042; rev:1;)'


def _ok(rule, src=SRC):
    return check_snort(rule, src, PROTECTED)


def test_rendered_rule_passes_its_own_gate():
    rule = render_snort(SRC, ["PORT_SCAN"], "T1046")
    assert _ok(rule).passed
    assert f"sid:{snort_sid(SRC)}" in rule and rule.startswith(f"drop ip {SRC} ")


def test_render_is_deterministic():
    assert render_snort(SRC, ["SYN_FLOOD"], "T1499") == render_snort(SRC, ["SYN_FLOOD"], "T1499")


def test_valid_reject_tcp():
    assert _ok(f'reject tcp {SRC} any -> $HOME_NET 22 (msg:"ssh"; sid:1000043; rev:2;)').passed


@pytest.mark.parametrize("rule", [
    GOOD.replace("drop", "alert", 1),                    # detection-only action
    GOOD.replace(SRC, "any", 1),                         # unscoped source
    GOOD.replace(SRC, "!" + SRC, 1),                     # negation
    GOOD.replace(SRC, "10.10.0.10", 1),                  # the protected server
    GOOD.replace(SRC, "10.10.0.0/24", 1),                # covers protected assets
    GOOD.replace(SRC, "8.8.8.8", 1),                     # not the alert's source
    GOOD.replace("sid:", 'content:"x"; sid:'),           # option outside the allowlist
    GOOD.replace("1000042", "2001219"),                  # sid outside the local range
    GOOD.replace(" sid:1000042;", ""),                   # no sid
    GOOD.replace("HRT block", "$(reboot)"),              # subshell in msg
    GOOD.replace("HRT block", "a|b"),                    # pipe in msg
    GOOD.replace("->", "<>"),                            # bidirectional
    GOOD[:-1],                                           # unterminated
    GOOD.replace("$HOME_NET any", "$HOME_NET 99999"),    # port out of range
    "",
])
def test_rejected(rule):
    assert not _ok(rule).passed


def test_parse_returns_options():
    action, net, opts = parse_snort(GOOD)
    assert action == "drop" and str(net) == f"{SRC}/32" and opts["sid"] == "1000042"
