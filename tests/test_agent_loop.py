"""Analyst self-correction with a FakeLLM and a stubbed retriever/sandbox (no Docker, no model)."""

from __future__ import annotations

from hrt.agent.analyst import AnalystAgent, extract_json, normalise_id
from hrt.config import get_settings
from hrt.guardrail.pipeline import Guardrail
from hrt.llm.fake import FakeLLM
from hrt.models import GuardrailCheck, RetrievalTrace, RetrievedDoc, Status


class StubRetriever:
    def retrieve(self, alert, top_k=5, hierarchical=True):
        docs = [RetrievedDoc(mitre_id="T1046", name="Network Service Discovery", tactics=["discovery"], score=0.7),
                RetrievedDoc(mitre_id="T1595", name="Active Scanning", tactics=["reconnaissance"], score=0.6)]
        return RetrievalTrace(query="q", candidate_tactics=["discovery"], candidates=40, total_docs=800,
                              search_space_reduction=0.95, docs=docs), ["T1046 ...", "T1595 ..."]

    def known(self, tid):
        return tid in {"T1046", "T1595"}

    def name_of(self, tid):
        return "Network Service Discovery"


class FakeSandbox:
    def verify(self, restore_text):
        return GuardrailCheck(stage="kernel", passed="203.0.113.9" in restore_text, detail="fake")


def _mit(tid="T1046", rule="iptables -I INPUT 1 -s 203.0.113.9 -j DROP"):
    return ('{"incident_summary":"s","evidence":["e"],"attack_type":"scan","mitre_technique_id":"%s",'
            '"mitre_technique_name":"n","mitre_tactic":"discovery","confidence":0.8,'
            '"recommended_actions":["b"],"iptables_rule":"%s"}') % (tid, rule)


def _agent(replies):
    s = get_settings()
    gr = Guardrail(s, sandbox=FakeSandbox(), deployed_rules=lambda: [])
    return AnalystAgent(FakeLLM(replies=replies), gr, StubRetriever(), use_rag=True, max_attempts=3)


def test_extract_json_from_fence():
    assert extract_json('```json\n{"a":1}\n```') == '{"a":1}'


def test_normalise_id():
    assert normalise_id("t1046") == "T1046"
    assert normalise_id("technique T1110.001 maybe") == "T1110.001"


def test_first_try_success(scan_alert):
    inc = _agent([_mit()]).analyze(scan_alert)
    assert inc.status == Status.SAFE and len(inc.attempts) == 1 and inc.grounded


def test_policy_then_correct(scan_alert):
    bad = _mit(rule="iptables INPUT -s 203.0.113.9 -j DROP")  # missing -A/-I
    inc = _agent([bad, _mit()]).analyze(scan_alert)
    assert inc.status == Status.SAFE and len(inc.attempts) == 2
    assert inc.attempts[0].verdict.failure.stage == "policy"


def test_ungrounded_then_correct(scan_alert):
    inc = _agent([_mit(tid="T1499"), _mit(tid="T1046")]).analyze(scan_alert)
    assert inc.status == Status.SAFE
    assert "grounding" in inc.attempts[0].error


def test_escalates_on_persistent_subnet_block(scan_alert):
    bad = _mit(rule="iptables -I INPUT 1 -s 10.10.0.0/24 -j DROP")
    inc = _agent([bad, bad, bad]).analyze(scan_alert)
    assert inc.status == Status.ESCALATED and "subnet" in inc.escalation_reason


def test_schema_error_then_correct(scan_alert):
    inc = _agent(["not json at all", _mit()]).analyze(scan_alert)
    assert inc.status == Status.SAFE
    assert "schema" in inc.attempts[0].error
