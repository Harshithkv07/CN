"""Probe: what does the no-RAG agent actually answer for technique / tactic? (one alert per label)"""
import json, logging
from hrt.config import Settings
from hrt.eval.cicids_data import load_sample
from hrt.eval.synth import alerts_from_sample
from hrt.eval.labels import CIC_LABELS
from hrt.agent.analyst import AnalystAgent
from hrt.guardrail.pipeline import Guardrail
from hrt.guardrail.sandbox import KernelSandbox
from hrt.llm import make_llm
from hrt.rag.retriever import Retriever

logging.basicConfig(level=logging.WARNING)
s = Settings()
alerts = alerts_from_sample(load_sample(s), per_class=3)
seen, pick = set(), []
for a, lab in alerts:
    if lab not in seen:
        seen.add(lab); pick.append((a, lab))
cat = Retriever(s)
sb = KernelSandbox(s)
agent = AnalystAgent(make_llm(s), Guardrail(s, sb if sb.available() else None, lambda: []), None,
                     use_rag=False, max_attempts=s.max_attempts)
for a, lab in pick:
    inc = agent.analyze(a)
    print(f"== {lab}  expected tactic={CIC_LABELS[lab]['tactic']} techniques={CIC_LABELS[lab]['techniques']}  -> {inc.status}")
    for at in inc.attempts:
        m = at.mitigation
        if m:
            print(f"   attempt {at.number}: id={m.mitre_technique_id!r} known={cat.known(m.mitre_technique_id)} "
                  f"name={m.mitre_technique_name!r} tactic={m.mitre_tactic!r} attack_type={m.attack_type!r}")
        if at.error:
            print(f"   attempt {at.number} error: {at.error[:150]}")
        if at.verdict and at.verdict.failure:
            print(f"   attempt {at.number} guardrail: {at.verdict.failure.stage}: {at.verdict.failure.detail[:150]}")
    if inc.escalation_reason:
        print("   escalated:", inc.escalation_reason[:200])
