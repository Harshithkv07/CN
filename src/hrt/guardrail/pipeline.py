"""The full Tier-3 gate: policy -> subnet -> conflict -> kernel. It stops at the first failure."""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from pathlib import Path

from hrt.config import Settings
from hrt.guardrail.conflicts import check_conflicts, parse_ruleset
from hrt.guardrail.policy import PolicyError, parse
from hrt.guardrail.sandbox import KernelSandbox, build_restore
from hrt.guardrail.subnet import check_subnets
from hrt.models import GuardrailCheck, GuardrailVerdict


class Guardrail:
    def __init__(self, settings: Settings, sandbox: KernelSandbox | None = None,
                 deployed_rules: Callable[[], list[str]] | None = None):
        self.settings = settings
        self.sandbox = sandbox
        self.deployed_rules = deployed_rules or (lambda: [])
        path = Path(settings.baseline_rules)
        self.baseline_text = path.read_text() if path.exists() else ""

    def current_ruleset_lines(self) -> list[str]:
        return [*self.baseline_text.splitlines(), *self.deployed_rules()]

    def check(self, rule: str, alert_source: str | None) -> GuardrailVerdict:
        # Build the full check list first, then construct the verdict once. Constructing a
        # pydantic model mid-way would snapshot (copy) the list, so later appends would be lost.
        checks: list[GuardrailCheck] = []
        argv: list[str] = []
        restore_line = ""

        t0 = time.perf_counter()
        try:
            parsed = parse(rule)
            argv, restore_line = parsed.argv, parsed.restore_line
            checks.append(GuardrailCheck(stage="policy", passed=True, elapsed_ms=(time.perf_counter() - t0) * 1e3,
                                         detail=f"{parsed.op} {parsed.chain} ... -j {parsed.target} is within policy"))
        except PolicyError as exc:
            checks.append(GuardrailCheck(stage="policy", passed=False, detail=str(exc), retryable=exc.retryable,
                                         elapsed_ms=(time.perf_counter() - t0) * 1e3))
            return self._verdict(False, checks, rule, argv, restore_line)

        t0 = time.perf_counter()
        sub = check_subnets(parsed, self.settings.protected_subnets, alert_source, self.settings.min_source_prefix)
        sub.elapsed_ms = (time.perf_counter() - t0) * 1e3
        checks.append(sub)
        if not sub.passed:
            return self._verdict(False, checks, rule, argv, restore_line)

        t0 = time.perf_counter()
        existing = self.current_ruleset_lines()
        con = check_conflicts(parsed, parse_ruleset(existing))
        con.elapsed_ms = (time.perf_counter() - t0) * 1e3
        checks.append(con)
        if not con.passed:
            return self._verdict(False, checks, rule, argv, restore_line)

        if self.sandbox is None:
            checks.append(GuardrailCheck(stage="kernel", passed=False, retryable=False,
                                         detail="kernel sandbox disabled; cannot verify"))
            return self._verdict(False, checks, rule, argv, restore_line)
        deployed = [ln for ln in self.deployed_rules() if ln.startswith(("-A", "-I"))]
        checks.append(self.sandbox.verify(build_restore(self.baseline_text, [*deployed, parsed.restore_line])))
        return self._verdict(checks[-1].passed, checks, rule, argv, restore_line)

    @staticmethod
    def _verdict(passed: bool, checks: list[GuardrailCheck], rule: str, argv: list[str],
                 restore_line: str) -> GuardrailVerdict:
        return GuardrailVerdict(passed=passed, checks=list(checks), rule=rule, argv=argv, restore_line=restore_line)


# ---------------------------------------------------------------------------------------
# A permissive regex validator representative of the "brittle regex parsing" the literature
# uses (e.g. Automated Security Policy Synthesis, ACM SIGCOMM 2025). It checks only that the
# string *looks like* an iptables DROP/REJECT rule aimed at an IP. It is the baseline in the
# guardrail evaluation, to quantify what pattern matching cannot catch: shell injection,
# blocking a protected subnet, over-broad prefixes, shadowing, and semantically invalid rules.
# ---------------------------------------------------------------------------------------
REGEX_BASELINE = re.compile(
    r"iptables\s+-[AI]\s+(INPUT|FORWARD|OUTPUT).*-s\s+\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?.*-j\s+(DROP|REJECT)",
    re.IGNORECASE,
)


def regex_validate(rule: str) -> bool:
    """The weak baseline: substring search, no anchoring, no semantics."""
    return bool(REGEX_BASELINE.search(rule.strip()))
