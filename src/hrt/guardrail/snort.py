"""Snort/Suricata signature support for Tier 3.

The brief allows the mitigation to be "a Snort signature or an iptables drop rule". The iptables rule
stays the primary, kernel-verified action. This module adds the second form: a ``drop`` signature for
an inline IPS, rendered from the verified decision and checked by the same kind of deterministic
gate (an allowlist parser, not a regex).

There is no Snort binary in the lab, so this stage is a **static** check (grammar, allowed options,
source scoping, protected-subnet overlap). It does not prove Snort will load the rule.
"""

from __future__ import annotations

import re
from ipaddress import IPv4Address, IPv4Network, ip_network

from hrt.guardrail.policy import ParsedRule
from hrt.guardrail.subnet import check_subnets
from hrt.models import GuardrailCheck

ACTIONS = {"drop", "reject", "sdrop"}            # blocking actions only; `alert`/`pass` are not mitigations
PROTOS = {"ip", "tcp", "udp", "icmp"}
OPTION_KEYS = {"msg", "sid", "rev", "classtype", "priority", "flow", "flags", "threshold", "detection_filter",
               "reference", "metadata"}
LOCAL_SID = range(1_000_000, 2_000_000)           # the reserved local-rule SID range
_MSG_OK = re.compile(r"^[A-Za-z0-9 _.:/()\-]{1,120}$")
_VALUE_OK = re.compile(r"^[A-Za-z0-9 _.:,/\-]{1,80}$")
_PORT = re.compile(r"^(any|\d{1,5}(:\d{0,5})?|:\d{1,5})$")
_HEADER = re.compile(r"^(\w+)\s+(\w+)\s+(\S+)\s+(\S+)\s+->\s+(\S+)\s+(\S+)$")

CLASSTYPES = {"PORT_SCAN": "attempted-recon", "HOST_SWEEP": "attempted-recon", "SYN_FLOOD": "attempted-dos",
              "CONN_FLOOD": "attempted-dos", "UDP_FLOOD": "attempted-dos", "SLOW_DOS": "attempted-dos",
              "BRUTE_FORCE": "attempted-user", "BEACONING": "trojan-activity", "EXFILTRATION": "policy-violation"}


class SnortError(ValueError):
    pass


def snort_sid(source_ip: str) -> int:
    """Deterministic local SID, so re-rendering the same block never creates a second signature."""
    return 1_000_000 + int(IPv4Address(source_ip)) % 900_000


def render_snort(source_ip: str, rules: list[str], technique_id: str = "") -> str:
    """Render the signature for a verified block decision. Only validated values are interpolated."""
    src = str(IPv4Address(source_ip))
    label = "+".join(rules) if rules else "ANOMALY"
    msg = f"HRT-Agent block {technique_id} {label} from {src}".replace("  ", " ")
    cls = CLASSTYPES.get(rules[0], "misc-attack") if rules else "misc-attack"
    return (f'drop ip {src} any -> $HOME_NET any (msg:"{msg}"; classtype:{cls}; '
            f"sid:{snort_sid(src)}; rev:1;)")


def _options(body: str) -> list[tuple[str, str]]:
    out, i, n = [], 0, len(body)
    while i < n:
        while i < n and body[i] in " ;":
            i += 1
        if i >= n:
            break
        j = body.find(":", i)
        k = body.find(";", i)
        if k == -1:
            raise SnortError("option list must end with ';'")
        if j == -1 or j > k:
            key, val = body[i:k].strip(), ""
            i = k + 1
        else:
            key = body[i:j].strip()
            if body[j + 1: j + 2] == '"':           # quoted string value
                end = body.find('"', j + 2)
                if end == -1 or body[end + 1: end + 2] != ";":
                    raise SnortError(f"unterminated or badly closed string in option '{key}'")
                val = body[j + 1: end + 1]
                i = end + 2
            else:
                val = body[j + 1: k].strip()
                i = k + 1
        out.append((key, val))
    return out


def _address(token: str) -> IPv4Network:
    if token.startswith("!"):
        raise SnortError("negated addresses are not allowed")
    try:
        net = ip_network(token, strict=False)
    except ValueError as exc:
        raise SnortError(f"'{token}' is not a valid IPv4 address or CIDR; the source must be explicit") from exc
    if net.version != 4:
        raise SnortError("only IPv4 signatures are supported")
    return net


def parse_snort(rule: str) -> tuple[str, IPv4Network, dict[str, str]]:
    rule = (rule or "").strip()
    if not rule:
        raise SnortError("empty rule")
    if any(c in rule for c in "\n\r\0`|{}\\") or "$(" in rule:
        raise SnortError("rule contains characters that are not allowed in a signature")
    if "(" not in rule or not rule.endswith(")"):
        raise SnortError("rule must have the form: action proto src sport -> dst dport (options;)")
    head, _, body = rule.partition("(")
    m = _HEADER.match(head.strip())
    if not m:
        raise SnortError("rule header must be: action proto src sport -> dst dport")
    action, proto, src, sport, dst, dport = m.groups()
    if action not in ACTIONS:
        raise SnortError(f"action '{action}' is not a blocking action; use drop or reject")
    if proto not in PROTOS:
        raise SnortError(f"protocol '{proto}' is not allowed")
    src_net = _address(src)
    if dst not in ("any", "$HOME_NET"):
        _address(dst)
    for p in (sport, dport):
        if not _PORT.match(p):
            raise SnortError(f"port expression '{p}' is not allowed")
        for part in p.split(":"):
            if part.isdigit() and int(part) > 65535:
                raise SnortError(f"port {part} is out of range")
    opts: dict[str, str] = {}
    for key, val in _options(body[:-1]):
        if key not in OPTION_KEYS:
            raise SnortError(f"option '{key}' is not in the allowed option set")
        if key in opts:
            raise SnortError(f"option '{key}' appears twice")
        if key == "msg":
            if not (val.startswith('"') and val.endswith('"') and _MSG_OK.match(val[1:-1])):
                raise SnortError("msg must be a quoted string of letters, digits and . _ : / ( ) -")
        elif not _VALUE_OK.match(val):
            raise SnortError(f"value of option '{key}' contains disallowed characters")
        opts[key] = val
    if "sid" not in opts or not opts["sid"].isdigit():
        raise SnortError("rule needs a numeric sid")
    if int(opts["sid"]) not in LOCAL_SID:
        raise SnortError("sid must be in the local range 1000000-1999999")
    if "msg" not in opts:
        raise SnortError("rule needs a msg")
    return action, src_net, opts


def check_snort(rule: str, alert_source: str | None, protected: list[str], min_prefix: int = 24) -> GuardrailCheck:
    """Static gate for a signature: grammar, allowed options, then the same subnet guardrail as iptables."""
    try:
        action, src, opts = parse_snort(rule)
    except SnortError as exc:
        return GuardrailCheck(stage="snort", passed=False, detail=str(exc))
    probe = ParsedRule(op="-I", chain="INPUT", position=1, target="DROP", sources=[src])
    sub = check_subnets(probe, protected, alert_source, min_prefix)
    if not sub.passed:
        return GuardrailCheck(stage="snort", passed=False, detail=sub.detail, retryable=sub.retryable)
    return GuardrailCheck(stage="snort", passed=True,
                          detail=f"{action} signature for {src} (sid {opts['sid']}) is within policy; static check only")
