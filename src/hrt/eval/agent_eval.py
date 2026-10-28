"""Incident-accuracy evaluation: does the agent attribute the right technique and produce a valid rule?

Runs each synthesised alert through the analyst in three modes:
  * rag_hier - hierarchical RAG (tactic prefilter + vector search) [the system]
  * rag_flat - flat vector search over all techniques (ablation of the hierarchy)
  * no_rag   - no retrieval; the LLM attributes from parametric memory (hallucination ablation)
Metrics: technique accuracy, tactic accuracy, grounding rate, invalid-ID rate, rule-validity and
escalation rates, and retrieval Recall@k.
"""

from __future__ import annotations

import logging

from hrt.agent.analyst import AnalystAgent
from hrt.config import Settings
from hrt.eval.labels import CIC_LABELS, technique_ok
from hrt.eval.synth import alerts_from_sample
from hrt.guardrail.pipeline import Guardrail
from hrt.guardrail.sandbox import KernelSandbox
from hrt.llm import make_llm
from hrt.models import Status
from hrt.rag.retriever import Retriever

log = logging.getLogger("hrt.eval.agent")


def _recall_at_k(retriever: Retriever, alerts, table) -> dict:
    hits = {1: 0, 3: 0, 5: 0}
    total = 0
    for alert, label in alerts:
        spec = table.get(label)
        if not spec:
            continue
        total += 1
        trace, _ = retriever.retrieve(alert, top_k=5, hierarchical=True)
        ranked = [d.mitre_id for d in trace.docs]
        for k in hits:
            if any(technique_ok(label, mid, table) for mid in ranked[:k]):
                hits[k] += 1
    return {f"recall@{k}": round(v / total, 4) if total else 0.0 for k, v in hits.items()}


def _norm_tactic(t: str) -> str:
    return (t or "").strip().lower().replace("_", "-").replace(" ", "-")


def _run_mode(agent: AnalystAgent, alerts, table, catalog: Retriever) -> dict:
    """`catalog` is used to check technique-ID validity in *every* mode, including no-RAG, where
    measuring hallucinated IDs is the whole point of the ablation."""
    tech_ok = tac_ok = grounded = invalid = safe = escalated = 0
    latencies = []
    details = []
    for alert, label in alerts:
        inc = agent.analyze(alert)
        m = inc.mitigation
        row = {"label": label, "status": str(inc.status), "attempts": len(inc.attempts)}
        if m:
            row.update(technique=m.mitre_technique_id, known=catalog.known(m.mitre_technique_id),
                       tactic=m.mitre_tactic, technique_ok=technique_ok(label, m.mitre_technique_id, table))
            if row["technique_ok"]:
                tech_ok += 1
            if _norm_tactic(m.mitre_tactic) == _norm_tactic(table[label]["tactic"]):
                tac_ok += 1
            if not row["known"]:
                invalid += 1
        details.append(row)
        if inc.grounded:
            grounded += 1
        if inc.status in (Status.SAFE, Status.DEPLOYED):
            safe += 1
        elif inc.status == Status.ESCALATED:
            escalated += 1
        if "verified" in inc.times and "analysis_started" in inc.times:
            latencies.append(inc.times["verified"] - inc.times["analysis_started"])
    n = len(alerts)
    latencies.sort()
    return {
        "n": n,
        "technique_accuracy": round(tech_ok / n, 4),
        "tactic_accuracy": round(tac_ok / n, 4),
        "grounding_rate": round(grounded / n, 4),
        "invalid_id_rate": round(invalid / n, 4),
        "rule_valid_rate": round(safe / n, 4),
        "escalation_rate": round(escalated / n, 4),
        "median_latency_s": round(latencies[len(latencies) // 2], 2) if latencies else None,
        "median_attempts": sorted(r["attempts"] for r in details)[n // 2] if details else None,
        "details": details,
    }


def run(settings: Settings, fast: bool = False, hard: bool = False, per_class: int | None = None,
        modes: list[str] | None = None) -> dict:
    """`hard=True` uses the extra CICIDS classes (Bot, Infiltration, web attacks, ...) that the Tier-1 rules
    rarely flag, so retrieval has to work without a tactic prefilter. `modes` limits which of
    rag_hier / rag_flat / no_rag run (each costs minutes per incident on CPU)."""
    from hrt.eval.cicids_data import build_sample, load_hard_sample, load_sample

    if hard:
        df = load_hard_sample(settings)
    else:
        try:
            df = load_sample(settings)
        except SystemExit:
            build_sample(settings)
            df = load_sample(settings)

    per_class = per_class or (3 if fast else (4 if hard else 10))
    alerts = alerts_from_sample(df, per_class=per_class, group_size=150 if hard else 250)
    log.info("evaluating agent on %d synthesised incidents (%d families)",
             len(alerts), len({l for _, l in alerts}))

    retriever = Retriever(settings)
    sandbox = KernelSandbox(settings)
    guardrail = Guardrail(settings, sandbox if sandbox.available() else None, lambda: [])
    if not sandbox.available():
        log.warning("kernel sandbox unavailable; guardrail will report kernel stage as failed")
    llm = make_llm(settings)

    wanted = set(modes or [])
    modes = {
        "rag_hier": AnalystAgent(llm, guardrail, retriever, use_rag=True, hierarchical=True,
                                 top_k=settings.retrieval_top_k, max_attempts=settings.max_attempts),
        "rag_flat": AnalystAgent(llm, guardrail, retriever, use_rag=True, hierarchical=False,
                                 top_k=settings.retrieval_top_k, max_attempts=settings.max_attempts),
        "no_rag": AnalystAgent(llm, guardrail, None, use_rag=False, max_attempts=settings.max_attempts),
    }
    results = {}
    for name, agent in modes.items():
        if wanted and name not in wanted:
            continue
        log.info("mode %s ...", name)
        results[name] = _run_mode(agent, alerts, CIC_LABELS, retriever)
        log.info("mode %s done: %s", name, {k: v for k, v in results[name].items() if k != "details"})
    results["retrieval"] = {
        "hierarchical": _recall_at_k(retriever, alerts, CIC_LABELS),
        "avg_search_space_reduction": _avg_reduction(retriever, alerts),
    }
    results["meta"] = {"llm": llm.name, "incidents": len(alerts), "per_class": per_class, "hard": hard,
                       "dataset": "cicids_hard (Bot, Infiltration, web attacks, ...)" if hard else "cicids_sample",
                       "classes": sorted({l for _, l in alerts}), "max_attempts": settings.max_attempts}
    return results


def _avg_reduction(retriever: Retriever, alerts) -> float:
    vals = [retriever.retrieve(a, top_k=5, hierarchical=True)[0].search_space_reduction for a, _ in alerts]
    return round(sum(vals) / len(vals), 4) if vals else 0.0
