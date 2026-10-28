// Evidence section: every chart is drawn from the JSON the evaluation suites wrote to results/.
import { $, $$, esc, fmt, pct, bytes, secs, reduced } from "./util.js";
import { groupedBars, hbars, lines, heat, key, table } from "./charts.js";

const C = { t0: "var(--t0)", t1: "var(--info)", t2: "var(--t2)", t3: "var(--t3)", ok: "var(--ok)", bad: "var(--bad)", warn: "var(--warn)" };
const R = (all, name) => all?.[name]?.result;
const card = (cls, title, src, body, take) =>
  `<article class="card ev ${cls}"><h3>${title}</h3><div class="src">${src}</div>${body}${take ? `<p class="take">${take}</p>` : ""}</article>`;

export function renderEvidence(all) {
  const root = $("#ev-grid");
  if (!all || !Object.keys(all).length) { root.innerHTML = `<div class="empty">No result files found in <code>results/</code>. Run <code>hrt eval all</code>.</div>`; return; }
  const parts = [tier1(all), telemetry(all), rag(all), latency(all), beacon(all), guardrail(all), injection(all), asyncq(all), live(all)].filter(Boolean);
  root.innerHTML = parts.join("");
  if (!reduced() && window.ScrollTrigger) {
    $$(".ev", root).forEach((el) => gsap.from(el, { opacity: 0, y: 28, duration: 0.7, ease: "power3.out", scrollTrigger: { trigger: el, start: "top 88%", once: true } }));
    $$(".ev svg.chart rect", root).forEach((r) => {
      if (r.getAttribute("rx") === "7" && r.getAttribute("fill") === "var(--surface-3)") return;
      gsap.from(r, { scaleY: 0, transformOrigin: "50% 100%", duration: 0.8, ease: "power3.out", scrollTrigger: { trigger: r, start: "top 95%", once: true } });
    });
  }
}

function tier1(all) {
  const t = R(all, "triage"); if (!t) return "";
  const d = t.detectors, rows = [["HRT_iforest_v1", "Isolation Forest\n(before)"], ["HRT_iforest", "Isolation Forest\n(tuned)"], ["SIEM_rules", "SIEM-style\nrules"], ["RandomForest_supervised", "Random Forest\n(supervised)"]].filter(([k]) => d[k]);
  const chart = groupedBars({ groups: rows.map(([k, l]) => ({ label: l, values: [d[k].precision, d[k].recall, d[k].f1] })), series: [{ name: "Precision", color: C.t1 }, { name: "Recall", color: C.t2 }, { name: "F1", color: C.t3 }], max: 1, label: "Tier-1 detection precision recall F1" });
  const sweep = t.iforest_sweep_validation ? Object.entries(t.iforest_sweep_validation).map(([k, v]) => `<tr><td>${k}</td><td class="num">${pct(v.val_recall, 1)}</td><td class="num">${fmt(v.val_f1, 3)}</td></tr>`).join("") : "";
  const take = `Raising the Isolation Forest's <code>max_samples</code> from 256 to ${t.iforest_max_samples} lifted recall from ${pct(d.HRT_iforest_v1?.recall, 0)} to ${pct(d.HRT_iforest?.recall, 0)} at the same ~5% false-positive budget. The value was chosen on a validation split, not the test set. The supervised forest scores near 1.0, so these attack families are easy: read the ranking, not the absolute figures.`;
  return card("", "Tier 1 · detection on CICIDS2018", `results/triage.json · ${fmt(t.rows)} flows · flow-level`, key([["Precision", C.t1], ["Recall", C.t2], ["F1", C.t3]]) + chart +
    (sweep ? `<details><summary>Validation sweep over max_samples</summary><table class="tbl"><thead><tr><th>max_samples</th><th>val recall</th><th>val F1</th></tr></thead><tbody>${sweep}</tbody></table></details>` : ""), take);
}

function telemetry(all) {
  const t = R(all, "telemetry"); if (!t) return "";
  const rows = t.alerts.map((a, i) => [esc(a.rules.join(" + ")), fmt(a.flows), bytes(a.raw_bytes), bytes(a.alert_bytes), pct(a.reduction, 2)]);
  const body = `<div style="display:grid;grid-template-columns:1fr auto;gap:12px;align-items:end;margin-bottom:12px"><div><div class="k">Whole capture → forwarded to the LLM</div><div class="big" style="--c:var(--t1)">${pct(t.whole_log_reduction, 3)}</div></div><div class="muted" style="text-align:right;font-size:.84rem">${fmt(t.records)} records<br>${bytes(t.conn_log_bytes)} → ${t.n_alerts} alerts</div></div>` +
    table(["Rules", "Flows", "Raw", "Alert", "Reduction"], rows, [1, 2, 3, 4]);
  return card("", "Tier 1 · telemetry reduction", "results/telemetry.json · real Zeek capture from the lab", body, `Median per-alert reduction is ${pct(t.median_alert_reduction, 2)}; the smallest was ${pct(t.min_alert_reduction, 1)} (a 25-flow brute force, where there is little to compress).`);
}

function agentRuns(all) {
  const names = [["agent", "Llama · 4 classes"], ["agent_hard", "Llama · harder"], ["agent_qwen", "Qwen · 4 classes"], ["agent_hard_qwen", "Qwen · harder"]];
  return names.filter(([k]) => R(all, k)).map(([k, label]) => [k, label, R(all, k)]);
}
const MODE = { no_rag: "No RAG", rag_flat: "Flat RAG", rag_hier: "Hierarchical RAG" };

function rag(all) {
  const runs = agentRuns(all); if (!runs.length) return "";
  const [, , first] = runs[0];
  const modes = ["no_rag", "rag_flat", "rag_hier"].filter((m) => first[m]);
  const chart = groupedBars({ groups: modes.map((m) => ({ label: MODE[m], values: [first[m].technique_accuracy, first[m].invalid_id_rate, first[m].rule_valid_rate] })), series: [{ name: "Correct technique", color: C.t3 }, { name: "Invented technique ID", color: C.bad }, { name: "Verified rule", color: C.t1 }], max: 1, label: "RAG ablation" });
  const rows = runs.flatMap(([, label, r]) => ["no_rag", "rag_flat", "rag_hier"].filter((m) => r[m]).map((m) => [esc(label), MODE[m], fmt(r[m].n), pct(r[m].technique_accuracy, 0), pct(r[m].invalid_id_rate, 0), pct(r[m].rule_valid_rate, 0), secs(r[m].median_latency_s)]));
  const ret = first.retrieval?.hierarchical;
  const take = `Without retrieval the model cited a technique that does not exist in ${pct(first.no_rag?.invalid_id_rate, 0)} of incidents. With it, 0. Flat and hierarchical retrieval tie on accuracy here; the hierarchy's measured gain is a ${pct(first.retrieval?.avg_search_space_reduction, 0)} smaller search space${ret ? ` at recall@1 ${fmt(ret["recall@1"], 2)}` : ""}.`;
  return card("wide", "Tier 2 · does retrieval stop hallucination?", `results/${runs.map(([k]) => k).join(".json, ")}.json`, `<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:22px" class="rag-cols">
    <div>${key([["Correct technique", C.t3], ["Invented technique ID", C.bad], ["Verified rule", C.t1]])}${chart}</div>
    <div style="overflow:auto">${table(["Run", "Mode", "n", "Correct", "Invented", "Rule ok", "Time"], rows, [2, 3, 4, 5, 6])}</div></div>`, take);
}

function latency(all) {
  const v1 = R(all, "v1_agent"), v2 = R(all, "agent"); if (!v1 || !v2) return "";
  const rows = [];
  for (const m of ["rag_hier", "rag_flat", "no_rag"]) {
    if (!(v1[m] && v2[m])) continue;
    const row = (tag, r, color) => ({ label: `${MODE[m]} · ${tag}`, value: r.median_latency_s, color, text: `${secs(r.median_latency_s)} · ${r.median_attempts} LLM call${r.median_attempts > 1 ? "s" : ""}` });
    rows.push(row("before", v1[m], C.t0), row("after", v2[m], C.t3));
  }
  if (!rows.length) return "";
  const a = v1.rag_hier?.median_latency_s, b = v2.rag_hier?.median_latency_s;
  return card("", "Tier 2 · latency per incident", "results/v1/agent.json vs results/agent.json", key([["Before prompt fix", C.t0], ["After", C.t3]]) + hbars({ rows, label: "Median analysis time" }),
    a && b ? `The first two attempts used to fail for a fixable reason: the model omitted <code>-I</code>, then appended with <code>-A</code> behind an ACCEPT rule. Showing the exact rule form in the prompt cut the median from ${secs(a)} to ${secs(b)}.` : "");
}

function guardrail(all) {
  const g = R(all, "guardrail"); if (!g) return "";
  const cats = Object.entries(g.by_category), nice = { valid: "valid", injection: "injection", self_dos: "self-DoS", destructive: "destructive", wrong_target: "wrong\ntarget", invalid_syntax: "invalid\nsyntax", encoding: "encoding", ordering: "ordering", conflict: "conflict", snort: "Snort" };
  const chart = groupedBars({ groups: cats.map(([c, v]) => ({ label: nice[c] || c, values: [v.hrt_correct / v.n, v.regex_correct / v.n] })), series: [{ name: "HRT guardrail", color: C.t3 }, { name: "Regex validator", color: C.bad }], max: 1, h: 250, label: "Guardrail accuracy by category" });
  const take = `${g.n_cases} adversarial cases. HRT: ${pct(g.hrt_accuracy, 0)} correct, ${(g.hrt_false_accepts || []).length} unsafe rules accepted. A regex validator accepted ${g.regex_false_accept_count}. The cases were written by the same team as the gate, so this shows coverage of known tricks, not an independent audit.`;
  return card("wide", "Tier 3 · the guardrail against a regex baseline", "results/guardrail.json", key([["HRT guardrail", C.t3], ["Regex validator", C.bad]]) + chart, take);
}

function beacon(all) {
  const b = R(all, "beacon"); if (!b) return "";
  const periods = [...new Set(Object.values(b.detection).map((d) => d.period_s))], jit = [...new Set(Object.values(b.detection).map((d) => d.jitter))];
  const cell = (p, j) => b.detection[`${p}s/${Math.round(j * 100)}%`];
  const values = periods.map((p) => jit.map((j) => cell(p, j)?.detected ?? 0));
  const text = periods.map((p) => jit.map((j) => { const c = cell(p, j); return c ? `${Math.round(c.detected * 100)}%` : ""; }));
  const fp = b.benign_false_alarm_rate || {}, lim = Object.values(b.known_limitation || {})[0];
  const body = `<div class="k">Detection rate · beacon period (rows) × jitter (columns)</div>` + heat({ rowLabels: periods.map((p) => `${p} s`), colLabels: jit.map((j) => `±${Math.round(j * 100)}%`), values, text }) +
    `<dl class="kv" style="margin-top:14px">${Object.entries(fp).map(([k, v]) => `<dt>False alarms · ${esc(k)}</dt><dd>${pct(v.false_alarm_rate_per_client_hour, 0)} of client-hours</dd>`).join("")}${lim ? `<dt>Perfectly periodic 30 s monitor</dt><dd>${lim.beacon_alerts} alerts (a known limit)</dd>` : ""}</dl>`;
  return card("", "Tier 1 · C2 beacon detection", "results/beacon.json · simulated implant traffic", body, `The old 10-second window only saw a beacon every second or faster. The 15-minute rule catches 5 s to 2 min beacons up to about ±20% jitter and misses heavily jittered ones. Time to alert is five check-ins.`);
}

function injection(all) {
  const i = R(all, "injection"); if (!i) return "";
  const t = i.telemetry_path, o = i.obedient_llm_path, l = i.live_llm_path || {};
  const box = (big, text) => `<div class="score"><b>${big}</b><span>${text}</span></div>`;
  const liveF = l.fenced, liveU = l.unfenced;
  const body = `<div class="scoreboard">${box(`${t.payload_reached_prompt} / ${t.payloads}`, "payloads that reached the prompt from log fields")}${box(`${o.harmful_rules_accepted} / ${o.payloads}`, "harmful rules accepted from a fully obedient LLM")}${liveF ? box(`${liveF.model_followed_injection} vs ${liveU?.model_followed_injection ?? "–"}`, `real model followed the injection: fenced vs unfenced prompt (n=${liveF.n})`) : box("–", "live-model test not run")}</div>`;
  return card("wide", "Security · prompt injection and RAG poisoning", "results/injection.json", body, `Layer by layer: log text never reaches the prompt; if the model is hijacked anyway, grounding and the four gates reject the rules. Open risk: injected text can still steer which <em>retrieved</em> technique is cited (see Limits).`);
}

function asyncq(all) {
  const a = R(all, "async"); if (!a) return "";
  const rates = Object.keys(a.rates).map(Number).sort((x, y) => x - y);
  const get = (m) => rates.map((r) => [r, a.rates[r][m].max_accept_lag_s]);
  const ymax = Math.max(...get("inline").map((p) => p[1]), 1);
  return card("", "Orchestration · inline vs asynchronous", "results/async.json", key([["Inline (blocks on the LLM)", C.bad], ["Async workers", C.t3]]) + lines({ series: [{ name: "Inline", color: C.bad, points: get("inline") }, { name: "Async", color: C.t3, points: get("async") }], xTicks: rates, yMax: Math.ceil(ymax / 200) * 200, fmtY: (v) => `${Math.round(v)} s`, xLabel: "alert rate (per second)", label: "Ingest lag" }),
    `Telemetry ingestion never waits on the model when alerts are handed to workers. Inline, the lag grows to ${secs(ymax)} at ${rates.at(-1)}/s; with workers it stays at 0 s. Analysis itself still queues (${a.llm_seconds} s per incident in this simulation).`);
}

function live(all) {
  const l = R(all, "live"); if (!l) return "";
  const rows = Object.entries(l.summary).map(([k, v]) => ({ label: { scan: "Port scan", synflood: "SYN flood", sshbf: "SSH brute force", beacon: "C2 beacon" }[k] || k, value: v.mean_s, color: v.under_5min ? C.t3 : C.bad, text: `${secs(v.mean_s)} (${v.runs} runs)` }));
  return card("", "End to end · first malicious packet to verified rule", "results/live.json · live Docker lab", hbars({ rows, max: l.target_seconds, ref: { value: l.target_seconds, label: "5 min target" }, label: "End-to-end response time" }),
    `Measured on CPU with a 3B model in the live lab. All attacks finished inside the five-minute target.`);
}

export const LIMITS = [
  "Detection is evaluated at flow level on four CICIDS2018 attack families that a supervised forest separates almost perfectly. The ranking of methods is informative; the absolute scores are not a promise for other networks.",
  "The guardrail test cases were written by the same team that wrote the gate. A perfect score shows coverage of known tricks, not an independent audit. The Snort check is static: no Snort engine loads the signature.",
  "Attribution can still be steered. Grounding checks that the cited technique was retrieved, not that it is the right one, so injected text can move the answer among the retrieved candidates.",
  "Beacon detection uses simulated traffic. Heavily jittered implants are missed, and a perfectly periodic benign monitor looks like a beacon.",
  "One small local model is the subject of most results; a second small model is the only cross-check. The pipeline responds in minutes on CPU: it is a near-real-time responder, not an inline packet filter.",
];
