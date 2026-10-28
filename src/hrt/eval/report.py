"""Assemble results/*.json into results/summary.md plus PNG charts (matplotlib, no seaborn)."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from hrt.config import Settings

log = logging.getLogger("hrt.eval.report")
NAVY, BLUE, PURPLE, GREEN, RED, AMBER = "#0b1120", "#5b8cff", "#9d7bff", "#34d399", "#f87171", "#fbbf24"


def _load(results_dir: Path, name: str) -> dict | None:
    p = results_dir / f"{name}.json"
    if not p.exists():
        return None
    return json.loads(p.read_text())["result"]


def _style(ax, title: str) -> None:
    ax.set_title(title, color="#e6edf7", fontsize=12, pad=10)
    ax.set_facecolor("#131c31")
    for s in ax.spines.values():
        s.set_color("#243049")
    ax.tick_params(colors="#8598b8")
    ax.yaxis.label.set_color("#8598b8")
    ax.xaxis.label.set_color("#8598b8")


def _chart_triage(res: dict, out: Path) -> str | None:
    import matplotlib.pyplot as plt

    d = res["detectors"]
    pairs = [("HRT_iforest_v1", "IForest\n(before)"), ("HRT_iforest", "IForest\n(tuned)"), ("SIEM_rules", "SIEM\nrules"),
             ("RandomForest_supervised", "RandomForest\n(supervised)")]
    pairs = [(n, l) for n, l in pairs if n in d]
    names, labels = [n for n, _ in pairs], [l for _, l in pairs]
    metrics = ["precision", "recall", "f1"]
    fig, ax = plt.subplots(figsize=(7, 4.2), facecolor=NAVY)
    x = range(len(names))
    w = 0.25
    for i, m in enumerate(metrics):
        vals = [d[n].get(m, 0) for n in names]
        ax.bar([xi + (i - 1) * w for xi in x], vals, w, label=m.upper(),
               color=[BLUE, PURPLE, GREEN][i])
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels)
    ax.set_ylim(0, 1.05)
    ax.legend(facecolor="#131c31", edgecolor="#243049", labelcolor="#e6edf7")
    _style(ax, "Tier-1 detection on CICIDS2018 (benign vs malicious)")
    fig.tight_layout()
    p = out / "chart_triage.png"
    fig.savefig(p, dpi=130, facecolor=NAVY)
    plt.close(fig)
    return p.name


def _chart_guardrail(res: dict, out: Path) -> str | None:
    import matplotlib.pyplot as plt

    cats = list(res["by_category"].keys())
    hrt = [res["by_category"][c]["hrt_correct"] / res["by_category"][c]["n"] for c in cats]
    reg = [res["by_category"][c]["regex_correct"] / res["by_category"][c]["n"] for c in cats]
    fig, ax = plt.subplots(figsize=(8, 4.2), facecolor=NAVY)
    x = range(len(cats))
    ax.bar([xi - 0.2 for xi in x], hrt, 0.4, label="HRT guardrail", color=GREEN)
    ax.bar([xi + 0.2 for xi in x], reg, 0.4, label="regex baseline", color=RED)
    ax.set_xticks(list(x))
    ax.set_xticklabels(cats, rotation=20, ha="right")
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("accuracy")
    ax.legend(facecolor="#131c31", edgecolor="#243049", labelcolor="#e6edf7")
    _style(ax, "Rule verification accuracy by category")
    fig.tight_layout()
    p = out / "chart_guardrail.png"
    fig.savefig(p, dpi=130, facecolor=NAVY)
    plt.close(fig)
    return p.name


def _chart_agent(res: dict, out: Path) -> str | None:
    import matplotlib.pyplot as plt

    modes = [m for m in ("no_rag", "rag_flat", "rag_hier") if m in res]
    labels = {"no_rag": "No RAG", "rag_flat": "Flat RAG", "rag_hier": "Hierarchical RAG"}
    metrics = ["technique_accuracy", "grounding_rate", "invalid_id_rate"]
    colors = [BLUE, GREEN, RED]
    fig, ax = plt.subplots(figsize=(7.5, 4.2), facecolor=NAVY)
    x = range(len(modes))
    w = 0.25
    for i, m in enumerate(metrics):
        ax.bar([xi + (i - 1) * w for xi in x], [res[md][m] for md in modes], w,
               label=m.replace("_", " "), color=colors[i])
    ax.set_xticks(list(x))
    ax.set_xticklabels([labels[m] for m in modes])
    ax.set_ylim(0, 1.05)
    ax.legend(facecolor="#131c31", edgecolor="#243049", labelcolor="#e6edf7")
    _style(ax, "Incident attribution: effect of RAG grounding")
    fig.tight_layout()
    p = out / "chart_agent.png"
    fig.savefig(p, dpi=130, facecolor=NAVY)
    plt.close(fig)
    return p.name


def _chart_async(res: dict, out: Path) -> str | None:
    import matplotlib.pyplot as plt

    rates = sorted(res["rates"].keys(), key=int)
    inline = [res["rates"][r]["inline"]["max_accept_lag_s"] for r in rates]
    asyncl = [res["rates"][r]["async"]["max_accept_lag_s"] for r in rates]
    fig, ax = plt.subplots(figsize=(7, 4.2), facecolor=NAVY)
    ax.plot([int(r) for r in rates], inline, "o-", color=RED, label="inline LLM (ingest blocks)")
    ax.plot([int(r) for r in rates], asyncl, "o-", color=GREEN, label="async webhook + queue")
    ax.set_xlabel("alert arrival rate (per second)")
    ax.set_ylabel("max ingest lag (s)")
    ax.legend(facecolor="#131c31", edgecolor="#243049", labelcolor="#e6edf7")
    _style(ax, "Ingest lag vs load (nodal-delay experiment)")
    fig.tight_layout()
    p = out / "chart_async.png"
    fig.savefig(p, dpi=130, facecolor=NAVY)
    plt.close(fig)
    return p.name


def _chart_live(res: dict, out: Path) -> str | None:
    import matplotlib.pyplot as plt

    summ = res.get("summary", {})
    if not summ:
        return None
    kinds = list(summ.keys())
    means = [summ[k]["mean_s"] for k in kinds]
    fig, ax = plt.subplots(figsize=(6.5, 4), facecolor=NAVY)
    ax.bar(kinds, means, color=BLUE)
    ax.axhline(300, color=AMBER, linestyle="--", label="5 min target")
    ax.set_ylabel("mean time-to-response (s)")
    ax.legend(facecolor="#131c31", edgecolor="#243049", labelcolor="#e6edf7")
    _style(ax, "End-to-end response time on the live lab")
    fig.tight_layout()
    p = out / "chart_live.png"
    fig.savefig(p, dpi=130, facecolor=NAVY)
    plt.close(fig)
    return p.name


def build(settings: Settings) -> Path:
    out = settings.results_dir
    out.mkdir(parents=True, exist_ok=True)
    L = ["# HRT-Agent - Evaluation Results", "",
         "Generated by `hrt report` from the JSON in this directory. "
         "All numbers are measured on this machine (CPU-only, local Llama via Ollama).", ""]

    triage = _load(out, "triage")
    if triage:
        L += ["## 1. Tier-1 detection (CICIDS2018)", "",
              f"Stratified sample: {triage['rows']:,} flows, {len(triage['classes'])} classes.", "",
              "| Detector | Precision | Recall | F1 | False-positive rate | ROC-AUC |", "|---|---|---|---|---|---|"]
        for name, m in triage["detectors"].items():
            L.append(f"| {name} | {m['precision']} | {m['recall']} | {m['f1']} | {m.get('false_positive_rate','-')} | "
                     f"{m.get('roc_auc','-')} |")
        sw = triage.get("iforest_sweep_validation")
        if sw:
            L += ["", "Isolation Forest `max_samples` sweep on a validation split of the training data "
                  "(the test split is not used for the choice): " + "; ".join(
                      f"{k}: recall {v['val_recall']}, F1 {v['val_f1']}" for k, v in sw.items())
                  + f". Chosen: {triage.get('iforest_max_samples')}. The earlier setting (256) caught only about half "
                  "of the attacks at the same 5% benign false-positive budget.",
                  "", "The supervised Random Forest scores about 1.0, so these four attack families are easy to separate: "
                  "read the ranking of the methods, not the absolute numbers."]
        L += ["", f"![triage]({_chart_triage(triage, out)})", ""]

    tele = _load(out, "telemetry")
    if tele:
        L += ["## 1b. Telemetry reduction (measured on the lab capture)", "",
              f"{tele['records']:,} Zeek records ({tele['conn_log_bytes']:,} B, {tele['avg_record_bytes']} B/record) "
              f"produced {tele['n_alerts']} alerts.", "",
              "| Alert rules | Flows summarised | Raw bytes | Alert JSON bytes | Reduction |", "|---|---|---|---|---|"]
        for a in tele["alerts"]:
            L.append(f"| {', '.join(a['rules'])} | {a['flows']:,} | {a['raw_bytes']:,} | {a['alert_bytes']:,} | "
                     f"{a['reduction'] * 100:.2f}% |")
        L += ["", f"Median per-alert reduction **{tele['median_alert_reduction'] * 100:.2f}%**; everything Zeek logged "
              f"(benign included) vs everything forwarded to the LLM: **{tele['whole_log_reduction'] * 100:.3f}%** smaller.", ""]

    guard = _load(out, "guardrail")
    if guard:
        L += ["## 2. Tier-3 rule verification", "",
              f"{guard['n_cases']} adversarial cases. **HRT guardrail accuracy: {guard['hrt_accuracy']*100:.0f}%**, "
              f"**regex baseline: {guard['regex_accuracy']*100:.0f}%**.", "",
              *([f"Original suite ({guard['core']['n']} cases): HRT {guard['core']['hrt_accuracy']*100:.0f}%, regex "
                 f"{guard['core']['regex_accuracy']*100:.0f}%. Extended suite ({guard['extended']['n']} cases: IPv6 and "
                 f"address encodings, CIDR overlap, ordering, conflicts with deployed rules, option smuggling, Snort "
                 f"signatures): HRT {guard['extended']['hrt_accuracy']*100:.0f}%, regex "
                 f"{guard['extended']['regex_accuracy']*100:.0f}%. Snort signatures alone ({guard['snort']['n']}): HRT "
                 f"{guard['snort']['hrt_accuracy']*100:.0f}%, regex {guard['snort']['regex_accuracy']*100:.0f}%. "
                 f"HRT accepted {len(guard.get('hrt_false_accepts', []))} unsafe rules and rejected "
                 f"{len(guard.get('hrt_false_rejects', []))} safe ones.", ""] if "core" in guard else []),
              f"The regex baseline accepted {guard['regex_false_accept_count']} unsafe rules.", "",
              "Caveat: the cases were written by the same team that wrote the gate, so this shows coverage of known "
              "tricks, not an independent audit.", "",
              f"![guardrail]({_chart_guardrail(guard, out)})", ""]

    agent = _load(out, "agent")
    if agent and "rag_hier" in agent:
        L += ["## 3. Incident attribution & RAG ablation", "",
              f"LLM: `{agent['meta']['llm']}`, {agent['meta']['incidents']} synthesised incidents.", "",
              "| Mode | Technique acc. | Tactic acc. | Grounding | Invalid-ID | Rule-valid | Escalation |",
              "|---|---|---|---|---|---|---|"]
        for md in ("no_rag", "rag_flat", "rag_hier"):
            if md in agent:
                m = agent[md]
                L.append(f"| {md} | {m['technique_accuracy']} | {m['tactic_accuracy']} | {m['grounding_rate']} | "
                         f"{m['invalid_id_rate']} | {m['rule_valid_rate']} | {m['escalation_rate']} |")
        ret = agent.get("retrieval", {})
        rk = ret.get("hierarchical") or {}
        labels = sorted({d["label"] for md in ("rag_hier", "rag_flat", "no_rag")
                         for d in agent.get(md, {}).get("details", [])})
        L += ["", "Median analysis latency (s): " + ", ".join(
                  f"{md} {agent[md]['median_latency_s']}" for md in ("rag_hier", "rag_flat", "no_rag") if md in agent)
              + ".", ""]
        att = {md: [d["attempts"] for d in agent[md].get("details", [])] for md in ("rag_hier", "rag_flat", "no_rag")
               if md in agent}
        if any(att.values()):
            L += ["LLM attempts per incident (the guardrail feeds each rejection back): " + "; ".join(
                      f"{md} " + ", ".join(f"{a} attempt{'s' if a > 1 else ''} x{v.count(a)}" for a in sorted(set(v)))
                      for md, v in att.items() if v) + ".", ""]
        L += [
              "Hierarchical retrieval: " + ", ".join(f"{k} {v}" for k, v in rk.items())
              + f"; the tactic prefilter shrinks the search space by "
              f"{ret.get('avg_search_space_reduction', 0)*100:.1f}% on average.", "",
              "Scoring: a technique counts as correct when it (or its parent technique) is in the accepted set "
              "for the true CICIDS label (`eval/labels.py`); tactics are compared after case/space normalisation. "
              "Invalid-ID = the cited ID is not in the local ATT&CK catalogue."
              + (f" Classes: {', '.join(labels)}." if labels else ""), ""]
        if (out / "agent_probe_norag.txt").exists():
            L += ["What the no-RAG model actually answered, attempt by attempt, is in "
                  "[`agent_probe_norag.txt`](agent_probe_norag.txt).", ""]
        L += [f"![agent]({_chart_agent(agent, out)})", ""]


    # ---- additional suites -------------------------------------------------------------------
    extra_runs = [("agent_hard", "Harder CICIDS classes (Bot, Infiltration, DoS variants)"),
                  ("agent_qwen", "Second model (Qwen 2.5 3B), standard classes"),
                  ("agent_hard_qwen", "Second model (Qwen 2.5 3B), harder classes")]
    loaded = [(t, _load(out, k)) for k, t in extra_runs]
    loaded = [(t, r) for t, r in loaded if r and any(m in r for m in ("rag_hier", "rag_flat", "no_rag"))]
    if loaded:
        L += ["## 3b. Harder classes and a second model", ""]
        for title, r in loaded:
            L += [f"**{title}**: `{r['meta']['llm']}`, {r['meta']['incidents']} incidents, classes: "
                  f"{', '.join(r['meta']['classes'])}.", "",
                  "| Mode | Technique acc. | Tactic acc. | Grounding | Invalid-ID | Rule-valid | Escalation | Median s |",
                  "|---|---|---|---|---|---|---|---|"]
            for md in ("no_rag", "rag_flat", "rag_hier"):
                if md in r:
                    m = r[md]
                    L.append(f"| {md} | {m['technique_accuracy']} | {m['tactic_accuracy']} | {m['grounding_rate']} | "
                             f"{m['invalid_id_rate']} | {m['rule_valid_rate']} | {m['escalation_rate']} | {m['median_latency_s']} |")
            L.append("")

    v1 = None
    p1 = out / "v1" / "agent.json"
    if p1.exists():
        v1 = json.loads(p1.read_text())["result"]
    if v1 and agent and "rag_hier" in v1 and "rag_hier" in agent:
        L += ["## 3c. Latency: before and after the prompt fix", "",
              "The model used to omit `-I`, then append with `-A` behind an ACCEPT rule, so two of three attempts were "
              "wasted. The prompt now shows the exact rule form.", "",
              "| Mode | Median seconds before | after | Median LLM calls before | after |", "|---|---|---|---|---|"]
        for md in ("rag_hier", "rag_flat", "no_rag"):
            if md in v1 and md in agent:
                L.append(f"| {md} | {v1[md]['median_latency_s']} | {agent[md]['median_latency_s']} | "
                         f"{v1[md]['median_attempts']} | {agent[md]['median_attempts']} |")
        L.append("")

    beacon = _load(out, "beacon")
    if beacon:
        L += ["## 3d. C2 beaconing", "",
              f"Simulated implant traffic through the real Tier-1 engine, {beacon['trials_per_cell']} trials per cell, "
              f"{int(beacon['window_seconds'])} s history per source/destination/port. Rule: {beacon['rule']}.", "",
              "| Beacon period / jitter | Detected | Median seconds to alert | Old 10 s window only |", "|---|---|---|---|"]
        for k, v in beacon["detection"].items():
            L.append(f"| {k} | {v['detected']} | {v['median_seconds_to_alert']} | {beacon['detection_10s_window_only'][k]} |")
        L += ["", "False alarms: " + "; ".join(f"{k}: {v['hours_with_a_beacon_alert']}/{v['client_hours']} client-hours"
                                              for k, v in beacon["benign_false_alarm_rate"].items())
              + ". " + "; ".join(f"{k}: {v['beacon_alerts']} alert(s) from {v['flows']:,} flows"
                                 for k, v in {**beacon["benign_false_alarms"], **beacon["known_limitation"]}.items()) + ".", "",
              beacon.get("note", ""), ""]

    inj = _load(out, "injection")
    if inj:
        t, o, lv = inj["telemetry_path"], inj["obedient_llm_path"], inj.get("live_llm_path", {})
        L += ["## 3e. Prompt injection and RAG poisoning", "",
              f"- Telemetry path: {t['payload_reached_prompt']} of {t['payloads']} payloads placed in log fields reached the prompt.",
              f"- Obedient-LLM path (worst case): {o['harmful_rules_accepted']} of {o['payloads']} harmful rules accepted.",
              *([f"- Live model ({lv.get('llm')}): followed the injection in {lv['fenced']['model_followed_injection']}/"
                 f"{lv['fenced']['n']} cases with the fenced prompt and {lv['unfenced']['model_followed_injection']}/"
                 f"{lv['unfenced']['n']} with an unfenced one; harmful rules accepted after the guardrail: "
                 f"{lv['fenced']['harmful_accepted_after_guardrail']} and {lv['unfenced']['harmful_accepted_after_guardrail']}."]
                if "fenced" in lv else ["- Live-model path was not run."]),
              "", "Limits: " + " ".join(inj.get("limits", [])), ""]

    asy = _load(out, "async")
    if asy:
        L += ["## 4. Async orchestration (nodal delay)", "",
              f"Inference {asy['llm_seconds']}s/incident, {asy['workers']} async workers.", "",
              "| Rate (/s) | Inline max ingest lag | Async max ingest lag | Inline overloaded |",
              "|---|---|---|---|"]
        for r in sorted(asy["rates"], key=int):
            row = asy["rates"][r]
            L.append(f"| {r} | {row['inline']['max_accept_lag_s']}s | {row['async']['max_accept_lag_s']}s | "
                     f"{row['inline']['overloaded']} |")
        L += ["", f"![async]({_chart_async(asy, out)})", ""]

    live = _load(out, "live")
    if live and live.get("summary"):
        L += ["## 5. End-to-end response time (live lab)", "",
              "| Attack | Runs | Mean (s) | Min | Max | < 5 min |", "|---|---|---|---|---|---|"]
        for k, v in live["summary"].items():
            L.append(f"| {k} | {v['runs']} | {v['mean_s']} | {v['min_s']} | {v['max_s']} | {'yes' if v['under_5min'] else 'NO'} |")
        chart = _chart_live(live, out)
        if chart:
            L += ["", f"![live]({chart})", ""]

    if not any([triage, tele, guard, agent, asy, live]):
        L += ["_No result files found. Run `hrt eval all` first._", ""]

    path = out / "summary.md"
    path.write_text("\n".join(L), encoding="utf-8")
    log.info("wrote %s", path)
    return path
