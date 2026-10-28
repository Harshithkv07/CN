"""The extended adversarial cases that do not need Docker (every stage except the kernel)."""

import pytest

from hrt.config import get_settings
from hrt.eval.guardrail_extended import EXTENDED, regex_accepts
from hrt.guardrail.pipeline import Guardrail


class _PassKernel:
    """Stand-in for the kernel stage so the rest of the gate is tested without Docker."""

    def verify(self, restore_text):
        from hrt.models import GuardrailCheck

        return GuardrailCheck(stage="kernel", passed=True, detail="stub")


# these are decided by the kernel itself, so they need the real sandbox
KERNEL_ONLY = {"insert_position_zero"}
CASES = [c for c in EXTENDED if c.name not in KERNEL_ONLY]


@pytest.mark.parametrize("case", CASES, ids=lambda c: c.name)
def test_gate_matches_expectation(case):
    gr = Guardrail(get_settings(), sandbox=_PassKernel(), deployed_rules=lambda d=case.deployed: list(d))
    got = gr.check_snort(case.rule, case.source).passed if case.kind == "snort" else gr.check(case.rule, case.source).passed
    assert got == case.should_pass, f"{case.name}: expected {'pass' if case.should_pass else 'reject'}"


def test_regex_baseline_is_weaker():
    wrong = sum(regex_accepts(c) != c.should_pass for c in EXTENDED)
    assert wrong >= 20      # it accepts most of the unsafe rules
