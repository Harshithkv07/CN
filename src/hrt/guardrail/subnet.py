"""Stage 2: the subnet guardrail. Stops self-inflicted denial of service, using bitwise AND.

Two CIDR blocks A and B overlap iff they agree on every bit of the *shorter* mask::

    m = mask(min(prefix_A, prefix_B))
    overlap  <=>  (addr_A & m) == (addr_B & m)

Any block rule whose address overlaps a protected subnet (internal LAN, the protected server,
gateways, loopback) is refused. So are rules broader than ``min_prefix``, and rules that don't
target the source named in the alert.
"""

from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network, ip_network

from hrt.guardrail.policy import ParsedRule
from hrt.models import GuardrailCheck


def overlaps(a: IPv4Network, b: IPv4Network) -> bool:
    m = int(a.netmask) if a.prefixlen <= b.prefixlen else int(b.netmask)
    return (int(a.network_address) & m) == (int(b.network_address) & m)


def contains(net: IPv4Network, ip: IPv4Address) -> bool:
    return (int(ip) & int(net.netmask)) == int(net.network_address)


def _hex(x: int) -> str:
    return f"0x{x:08x}"


def check_subnets(rule: ParsedRule, protected: list[str], alert_source: str | None, min_prefix: int = 24) -> GuardrailCheck:
    nets = [ip_network(p, strict=False) for p in protected]
    targets = rule.destinations if rule.chain == "OUTPUT" else rule.sources
    alert_ip = IPv4Address(alert_source) if alert_source else None
    alert_protected = alert_ip is not None and any(contains(n, alert_ip) for n in nets)

    for t in targets:
        for p in nets:
            if overlaps(t, p):
                m = int(t.netmask) if t.prefixlen <= p.prefixlen else int(p.netmask)
                return GuardrailCheck(
                    stage="subnet", passed=False, retryable=not alert_protected,
                    detail=(f"{t} overlaps protected subnet {p}: ({_hex(int(t.network_address))} & {_hex(m)}) == "
                            f"({_hex(int(p.network_address))} & {_hex(m)}). Blocking it would cause a "
                            f"self-inflicted denial of service."
                            + (" The alerting source itself is protected, so a human must decide." if alert_protected else "")))
        if t.prefixlen < min_prefix:
            return GuardrailCheck(stage="subnet", passed=False,
                                  detail=f"{t} is broader than /{min_prefix}; block the single attacking host instead")
    if alert_ip is not None and not any(contains(t, alert_ip) for t in targets):
        return GuardrailCheck(stage="subnet", passed=False,
                              detail=f"rule targets {', '.join(map(str, targets))} but the alert source is {alert_ip}")
    return GuardrailCheck(stage="subnet", passed=True,
                          detail=f"{', '.join(map(str, targets))} is outside all {len(nets)} protected subnets")
