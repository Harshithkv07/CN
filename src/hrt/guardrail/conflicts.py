"""Stage 3: conflict checking against the ruleset already on the firewall.

* **Duplicate:** an existing block rule already covers this source, so there's nothing to deploy.
* **Shadowed:** an earlier ACCEPT rule in the same chain matches overlapping traffic, so an
  appended DROP would never fire for that traffic. The agent is told to insert (-I) instead.
"""

from __future__ import annotations

import shlex

from hrt.guardrail.policy import ParsedRule, PolicyError, parse_tokens
from hrt.guardrail.subnet import overlaps
from hrt.models import GuardrailCheck


def parse_ruleset(lines: list[str]) -> list[ParsedRule]:
    """Parse the filter-table rules of an iptables-restore file or `iptables -S` output."""
    rules = []
    for line in lines:
        line = line.strip()
        if not line.startswith(("-A ", "-I ")):
            continue
        try:
            rules.append(parse_tokens(shlex.split(line), block_only=False))
        except PolicyError:
            continue
    return rules


def _ports_overlap(a: set[int] | None, b: set[int] | None) -> bool:
    return a is None or b is None or bool(a & b)


def _proto_overlap(a: str | None, b: str | None) -> bool:
    return a in (None, "all") or b in (None, "all") or a == b


def _addr_overlap(a: list, b: list) -> bool:
    if not a or not b:  # unspecified address matches everything
        return True
    return any(overlaps(x, y) for x in a for y in b)


def _iface_overlap(existing: ParsedRule, cand: ParsedRule) -> bool:
    """Interfaces can overlap only if the earlier rule is unconstrained or names the same one.
    A candidate with no -i is 'any interface', so a specific -i on the existing rule (e.g. lo)
    does NOT cover it."""
    if existing.in_iface is None:
        return True
    return existing.in_iface == cand.in_iface


def _covers(existing: ParsedRule, cand: ParsedRule) -> bool:
    if not existing.sources or not cand.sources:
        return False
    return all(any(e.prefixlen <= c.prefixlen and overlaps(e, c) for e in existing.sources) for c in cand.sources) \
        and existing.protocol in (None, "all", cand.protocol) \
        and (existing.dports is None or (cand.dports is not None and cand.dports <= existing.dports))


def _has_ctstate(rule: ParsedRule) -> bool:
    return any(t in ("--ctstate", "--state") for t in rule.tokens)


def check_conflicts(cand: ParsedRule, ruleset: list[ParsedRule]) -> GuardrailCheck:
    chain_rules = [r for r in ruleset if r.chain == cand.chain]
    for idx, r in enumerate(chain_rules, 1):
        if r.target in ("DROP", "REJECT") and _covers(r, cand):
            return GuardrailCheck(stage="conflict", passed=False, retryable=False,
                                  detail=f"duplicate: already covered by existing rule #{idx} '{r.restore_line}'")
    ahead = chain_rules if cand.op == "-A" else chain_rules[: max((cand.position or 1) - 1, 0)]
    notes = []
    for idx, r in enumerate(ahead, 1):
        if r.target != "ACCEPT":
            continue
        if not (_addr_overlap(r.sources, cand.sources) and _proto_overlap(r.protocol, cand.protocol)
                and _ports_overlap(r.dports, cand.dports) and _iface_overlap(r, cand)):
            continue
        if _has_ctstate(r):
            notes.append(f"rule #{idx} accepts established sessions first")
            continue
        return GuardrailCheck(
            stage="conflict", passed=False,
            detail=(f"shadowed: earlier rule #{idx} '{r.restore_line}' in {cand.chain} ACCEPTs overlapping traffic, "
                    f"so this {cand.op} rule would never match it. Insert it at the top with "
                    f"'iptables -I {cand.chain} 1 ...' instead."))
    return GuardrailCheck(stage="conflict", passed=True,
                          detail="no duplicate or shadowing rule" + (f" ({'; '.join(notes)})" if notes else ""))
