// Incident queue + the five-step story of one incident.
import { $, $$, esc, fmt, pct, bytes, secs, ICON, RULE_TEXT, STATUS, reduced, toast } from "./util.js";
import { state, on, approve, reject } from "./state.js";

let selected = null, userPicked = false, gateData = null;
const sigs = new Map();           // step key -> last rendered signature, so only changed steps animate
const lg = (v, max) => Math.max(0, Math.min(1, Math.log10(1 + v) / Math.log10(1 + max)));
const chip = (txt, cls = "") => `<span class="chip ${cls}">${esc(txt)}</span>`;
const GATES = [
  ["policy", "Policy", "Allowlist parser: one -A/-I, DROP/REJECT, no shell characters"],
  ["subnet", "Subnet", "Bitwise AND against protected networks"],
  ["conflict", "Conflict", "Duplicate, or shadowed by an earlier ACCEPT?"],
  ["kernel", "Kernel", "iptables-restore --test in a throwaway container"],
];
const DONE = ["SAFE", "DEPLOYED", "ESCALATED", "REJECTED", "DUPLICATE", "ERROR"];

export function initIncidents() {
  on((kind, p) => {
    if (kind === "mode") { selected = null; userPicked = false; sigs.clear(); renderList(); renderStory(true); }
    if (kind === "incident:new") {
      if (!userPicked) selected = p.incident_id;
      renderList();
      if (selected === p.incident_id) renderStory(true);
    }
    if (kind === "incident:update") { renderList(); if (selected === p.incident_id) renderStory(); }
  });
  $("#inc-ul").addEventListener("click", (e) => {
    const b = e.target.closest("button[data-id]");
    if (!b) return;
    selected = b.dataset.id; userPicked = true; renderList(); renderStory(true);
  });
  $("#story-trace").addEventListener("click", async (e) => {
    const g = e.target.closest("[data-gate]");
    if (g) { showGate(g.dataset.gate); return; }
    const cp = e.target.closest("[data-copy]");
    if (cp) {
      try { await navigator.clipboard.writeText(cp.dataset.copy); toast("Copied"); } catch { toast("Copy failed"); }
      return;
    }
    const act = e.target.closest("[data-act]");
    if (act && selected) {
      if (state.mode === "replay") { toast("Approval is disabled in replay mode"); return; }
      act.disabled = true;
      try { await (act.dataset.act === "approve" ? approve(selected) : reject(selected)); }
      catch { toast("Request failed"); act.disabled = false; }
    }
  });
  renderList();
  renderStory(true);
}

function renderList() {
  const incs = [...state.incidents.values()].reverse();
  $("#inc-count").textContent = incs.length;
  $("#inc-empty").style.display = incs.length ? "none" : "";
  $("#inc-ul").innerHTML = incs.map((i) => {
    const [label, cls] = STATUS[i.status] || [i.status, ""];
    const rules = i.alert.detector.rules.join(" + ") || "ML anomaly";
    return `<li><button class="inc-item" data-id="${i.incident_id}" ${i.incident_id === selected ? 'aria-current="true"' : ""}>
      <span class="inc-top"><span class="inc-ip">${esc(i.alert.source_ip)}</span>${chip(label, cls)}</span>
      <span class="inc-sub"><span>${esc(rules)}</span>${i.mitigation ? `<span class="mono">${esc(i.mitigation.mitre_technique_id)}</span>` : ""}</span></button></li>`;
  }).join("");
}

// ------------------------------------------------------------------ story
function renderStory(force = false) {
  const root = $("#story-trace");
  const inc = state.incidents.get(selected);
  if (!inc) {
    root.dataset.for = "";
    root.innerHTML = `<div class="card step"><div class="empty">Select an incident to see its trace.<br><span class="muted">Start an attack or replay a recorded run above.</span></div></div>`;
    sigs.clear();
    return;
  }
  if (force || root.dataset.for !== inc.incident_id) {
    root.dataset.for = inc.incident_id;
    sigs.clear();
    root.innerHTML = skeleton();
  }
  const reached = [
    true,
    !!inc.retrieval || inc.attempts.length > 0,
    inc.attempts.length > 0,
    inc.attempts.some((a) => a.verdict) || !!inc.verdict,
    DONE.includes(inc.status),
  ];
  const steps = [["s1", step1], ["s2", step2], ["s3", step3], ["s4", step4], ["s5", step5]];
  const lastReached = reached.lastIndexOf(true);
  steps.forEach(([key, fn], idx) => {
    const card = $(`#${key}`, root);
    const body = $(".step-body", card);
    card.classList.toggle("pending", !reached[idx]);
    card.classList.toggle("active", idx === lastReached && !DONE.includes(inc.status));
    if (!reached[idx]) return;
    const out = fn(inc);
    const sig = JSON.stringify(out.sig);
    if (sigs.get(key) === sig) return;
    sigs.set(key, sig);
    body.innerHTML = out.html;
    $(".step-h .chip", card)?.remove();
    if (out.chip) $(".step-h", card).insertAdjacentHTML("beforeend", out.chip);
    animateIn(card, key);
  });
}

function skeleton() {
  const mk = (id, n, c, title, why) => `<article class="card step pending" id="${id}" style="--c:${c}"><div class="step-h"><span class="step-n">${n}</span><h3>${title}</h3></div><p class="why">${why}</p><div class="step-body"></div></article>`;
  return mk("s1", 1, "var(--t1)", "Tier 1 · What the sensor saw", "Thousands of connection records are collapsed into about twenty numbers. Only this summary, never raw packets or log text, goes to the model.")
    + mk("s2", 2, "var(--t2)", "Tier 2 · What was retrieved", "Rule hits choose the ATT&amp;CK tactics to search, so the vector search covers a fraction of the knowledge base.")
    + mk("s3", 3, "var(--t2)", "Tier 2 · What the model said", "A local LLM must answer in a fixed JSON schema and cite one retrieved technique. A rejected answer goes back to it with the reason.")
    + mk("s4", 4, "var(--t3)", "Tier 3 · Does the rule pass the gate?", "The model is treated as an unreliable author. Four deterministic checks run in order and stop at the first failure.")
    + mk("s5", 5, "var(--t3)", "Outcome · What happens next", "A verified rule is not applied until an analyst approves it.");
}

function animateIn(card, key) {
  if (reduced()) return;
  const body = $(".step-body", card);
  gsap.from(body, { opacity: 0, y: 10, duration: 0.45, ease: "power2.out", clearProps: "opacity,transform" });
  const fills = $$(".fill", body);
  if (fills.length) gsap.fromTo(fills, { width: 0 }, { width: (i, t) => t.dataset.w, duration: 0.9, ease: "power3.out", stagger: 0.05, delay: 0.1 });
  const segs = $$(".wf-seg", body);
  if (segs.length) gsap.from(segs, { scaleX: 0, transformOrigin: "left", duration: 0.7, ease: "power3.out", stagger: 0.08 });
  if (key === "s4") {
    gsap.from($$(".gate", body), { opacity: 0, y: 12, scale: 0.96, duration: 0.4, ease: "back.out(1.6)", stagger: 0.18, clearProps: "opacity,transform" });
    gsap.from($$(".gate .mark", body), { scale: 0, rotation: -40, duration: 0.35, ease: "back.out(2.4)", stagger: 0.18, delay: 0.25 });
  }
}

// ---- step 1: telemetry
function step1(inc) {
  const a = inc.alert, f = a.features, d = a.detector;
  const rows = [
    ["Distinct ports probed", lg(f.n_dst_ports, 1000), fmt(f.n_dst_ports)],
    ["Flows in the window", lg(f.n_flows, 100000), fmt(f.n_flows)],
    ["Half-open TCP", f.half_open_frac, pct(f.half_open_frac, 0)],
    ["SYN : ACK ratio", lg(f.syn_ack_ratio, 1000), fmt(f.syn_ack_ratio, 1)],
    ["Rejected / reset", f.rej_frac, pct(f.rej_frac, 0)],
    ["Flows per second", lg(f.flows_per_s, 1000), fmt(f.flows_per_s, 1)],
    ["Dominant port share", f.dominant_port_share, pct(f.dominant_port_share, 0)],
    ["Timing regularity", 1 - Math.min(f.iat_cv, 1), `CV ${fmt(f.iat_cv, 2)}`],
  ];
  const alertBytes = JSON.stringify(a).length, raw = a.raw_bytes || 0;
  const ml = d.ml_score != null && d.ml_threshold != null
    ? `<div><div class="k">Isolation Forest</div><dl class="kv"><dt>Anomaly score</dt><dd>${fmt(d.ml_score, 3)}</dd><dt>Threshold</dt><dd>${fmt(d.ml_threshold, 3)}</dd><dt>Verdict</dt><dd>${d.ml_anomaly ? "anomalous" : "normal"}</dd></dl></div>` : "";
  const html = `<div class="cols">
    <div><div class="k">Rules that fired</div><div class="chips">${d.rules.length ? d.rules.map((r) => chip(r, "t1")).join("") : chip("no rule: ML anomaly only")}</div>
      <div style="margin-top:10px;display:grid;gap:4px">${d.rules.map((r) => `<span class="muted" style="font-size:.84rem"><b style="color:var(--text-2)">${esc(r)}</b>: ${esc(RULE_TEXT[r] || "")}</span>`).join("")}</div>
      <div class="k" style="margin-top:16px">Source and targets</div>
      <dl class="kv"><dt>Source</dt><dd>${esc(a.source_ip)}</dd><dt>Target(s)</dt><dd>${esc(a.dst_ips.join(", ") || "–")}</dd><dt>Window</dt><dd>${fmt(f.window_seconds)} s</dd></dl>
    </div>
    <div><div class="k">Behaviour summary</div><div class="bars">${rows.map(([l, w, v]) => `<div class="bar"><span class="lab">${l}</span><span class="track"><span class="fill" data-w="${Math.round(w * 100)}%" style="width:${Math.round(w * 100)}%;--c:var(--t1)"></span></span><span class="val">${v}</span></div>`).join("")}</div></div>
    <div>${ml}<div class="k" style="margin-top:${ml ? 16 : 0}px">Telemetry reduction</div>
      <div class="big" style="--c:var(--t1)">${raw ? pct(1 - alertBytes / raw, 3) : "–"}</div>
      <p class="muted" style="font-size:.84rem;margin-top:6px">${raw ? `${bytes(raw)} of raw records (${fmt(a.raw_flow_count)} flows) became a ${bytes(alertBytes)} alert.` : `${fmt(a.raw_flow_count)} flows became a ${bytes(alertBytes)} alert.`}</p></div>
  </div>`;
  return { html, sig: [a.alert_id, d.rules, d.ml_score], chip: chip(`${fmt(a.raw_flow_count)} flows → 1 alert`, "t1") };
}

// ---- step 2: retrieval
function step2(inc) {
  const r = inc.retrieval;
  if (!r) return { html: `<p class="muted">Retrieval did not run (no knowledge base is loaded), so the model answers from memory alone.</p>`, sig: "none", chip: chip("RAG off", "warn") };
  const share = Math.max(2, Math.round((r.candidates / r.total_docs) * 100));
  const html = `<div class="cols">
    <div><div class="k">Tactic prefilter (from Tier-1 rules)</div><div class="chips">${r.candidate_tactics.length ? r.candidate_tactics.map((t) => chip(t, "t2")).join("") : chip("none: searching everything")}</div>
      <div class="k" style="margin-top:16px">Search space removed</div>
      <div class="big" style="--c:var(--t2)">${pct(r.search_space_reduction, 1)}</div>
      <p class="muted" style="font-size:.84rem;margin:4px 0 8px">${fmt(r.candidates)} of ${fmt(r.total_docs)} techniques searched</p>
      <div class="track"><span class="fill" data-w="${share}%" style="width:${share}%;--c:var(--t2)"></span></div>
      <details><summary>Query sent to the vector store</summary><div class="qbox" style="margin-top:8px">${esc(r.query)}</div></details>
    </div>
    <div style="grid-column: span 2"><div class="k">Retrieved techniques (cosine similarity)</div>
      ${r.docs.map((d) => { const w = Math.round(Math.max(0, d.score) * 100); return `<div class="doc"><span class="id">${esc(d.mitre_id)}</span><span class="nm">${esc(d.name)}<small>${esc(d.tactics.join(", "))}</small><span class="track"><span class="fill" data-w="${w}%" style="width:${w}%;--c:var(--t2)"></span></span></span><span class="sc">${d.score.toFixed(2)}</span></div>`; }).join("")}
      ${r.cves?.length ? `<div class="k" style="margin-top:14px">Known-exploited CVEs for the targeted service (patch context only)</div><div class="chips">${r.cves.map((c) => chip(`${c.cve} · ${c.product}`)).join("")}</div>` : ""}
    </div></div>`;
  return { html, sig: [r.query, r.docs.map((d) => d.mitre_id)], chip: chip(`${fmt(r.seconds, 2)} s`, "t2") };
}

// ---- step 3: the model, and the retry loop
function step3(inc) {
  const n = inc.attempts.length;
  const accepted = ["SAFE", "DEPLOYED"].includes(inc.status);
  const html = `<div style="display:grid;gap:12px">` + inc.attempts.map((at, i) => {
    const m = at.mitigation, failed = at.verdict && !at.verdict.passed ? at.verdict.checks.find((c) => !c.passed) : null;
    const rej = !!at.error || !!failed;
    const why = at.error || (failed ? `${failed.stage}: ${failed.detail}` : "");
    const isLast = i === n - 1, ok = isLast && !rej && accepted;
    const arrow = rej && (!isLast || inc.status === "ANALYZING")
      ? `<div class="loop-arrow">${ICON.loop}<span>The verifier's reason is appended to the conversation and the model tries again.</span></div>` : "";
    return `<div class="attempt ${rej ? "rejected" : ok ? "accepted" : ""}">
      <div class="att-h"><b>Attempt ${at.number}</b>${chip(`${fmt(at.llm_seconds, 1)} s`)}${chip(`${fmt(at.prompt_chars)} prompt chars`)}${rej ? chip("rejected", "bad") : ok ? chip("accepted", "ok") : chip("in review")}</div>
      ${m ? `<div class="cols" style="gap:10px 18px"><dl class="kv"><dt>Technique</dt><dd>${esc(m.mitre_technique_id)} ${esc(m.mitre_technique_name || "")}</dd><dt>Tactic</dt><dd>${esc(m.mitre_tactic)}</dd><dt>Attack type</dt><dd>${esc(m.attack_type)}</dd><dt>Confidence</dt><dd>${fmt(m.confidence, 2)}</dd></dl>
        <div><div class="k">Summary</div><p style="font-size:.88rem;color:var(--text-2)">${esc(m.incident_summary)}</p></div></div>
        <div><div class="k">Proposed rule</div><div class="code" style="padding-right:14px">${esc(m.iptables_rule)}</div></div>` : `<div class="json">${esc(at.raw_output.slice(0, 600))}</div>`}
      ${rej ? `<div class="feedback">${ICON.cross.replace("<svg", '<svg width="16" height="16" style="flex:none"')}<span><b>Sent back to the model:</b> ${esc(why)}</span></div>` : ""}
      <details><summary>Raw model output</summary><div class="json" style="margin-top:8px">${esc(at.raw_output)}</div></details>
    </div>${arrow}`;
  }).join("") + `</div>`;
  const tot = inc.attempts.reduce((s, a) => s + a.llm_seconds, 0);
  return { html, sig: [inc.status, inc.attempts.map((a) => [a.number, a.error, a.verdict?.passed, a.mitigation?.iptables_rule])], chip: chip(`${n} attempt${n > 1 ? "s" : ""} · ${fmt(tot, 1)} s`, n > 1 ? "warn" : "t2") };
}

// ---- step 4: the gate
function step4(inc) {
  const v = [...inc.attempts].reverse().find((a) => a.verdict)?.verdict || inc.verdict;
  if (!v) return { html: "", sig: "x" };
  const by = Object.fromEntries(v.checks.map((c) => [c.stage, c]));
  const failed = v.checks.find((c) => !c.passed);
  gateData = by;
  const html = `<div class="gates">${GATES.map(([k, name, sub], i) => {
    const c = by[k], cls = c ? (c.passed ? "pass" : "fail") : "skip";
    return `<button class="gate ${cls}" data-gate="${k}" style="text-align:left;cursor:pointer;color:inherit;font:inherit" aria-label="${name} check: ${c ? (c.passed ? "passed" : "failed") : "not run"}">
      <span class="g-n">Gate ${i + 1}</span><span class="g-t">${name}</span><span class="g-s">${sub}</span><span class="g-ms">${c ? fmt(c.elapsed_ms, 1) + " ms" : "not reached"}</span>
      ${c ? `<span class="mark">${c.passed ? ICON.check : ICON.cross}</span>` : ""}</button>`;
  }).join("")}</div><div class="gate-detail" id="gate-detail" aria-live="polite">${gateText(failed || v.checks.at(-1))}</div>`;
  return { html, sig: v.checks.map((c) => [c.stage, c.passed]), chip: chip(v.passed ? "all gates passed" : `stopped at ${failed?.stage}`, v.passed ? "ok" : "bad") };
}
const gateText = (c) => c ? `<b>${esc(c.stage)}</b>: ${esc(c.detail)}${c.retryable === false ? " <span class='chip warn'>not retryable: a human decides</span>" : ""}` : "";
function showGate(k) {
  const c = gateData?.[k];
  $("#gate-detail").innerHTML = c ? gateText(c) : `<b>${esc(k)}</b>: not reached. An earlier gate stopped the rule.`;
}

// ---- step 5: outcome
function step5(inc) {
  const m = inc.mitigation, ok = ["SAFE", "DEPLOYED"].includes(inc.status), [label] = STATUS[inc.status] || [inc.status];
  const ordered = Object.entries(inc.times || {}).sort((a, b) => a[1] - b[1]);
  const t0 = ordered[0]?.[1] ?? 0, span = Math.max((ordered.at(-1)?.[1] ?? 0) - t0, 0.001);
  const segs = [];
  for (let i = 1; i < ordered.length; i++) {
    const [k, tv] = ordered[i], tp = ordered[i - 1][1];
    if (k === "finished" || k === "rejected") continue;
    const llm = /^llm_(\d+)$/.exec(k);
    const name = llm ? `LLM call ${llm[1]}` : ({ analysis_started: "Queue wait", retrieved: "Retrieval", verified: "Guardrail", deployed: "Approval + deploy" }[k] || k);
    segs.push({ name, from: tp - t0, dur: tv - tp, c: llm ? "var(--t2)" : (k === "verified" || k === "deployed") ? "var(--t3)" : "var(--t1)" });
  }
  const buttons = inc.status === "SAFE"
    ? `<div class="actions"><button class="btn ok sm" data-act="approve">Approve and deploy</button><button class="btn bad sm" data-act="reject">Reject</button></div>` : "";
  const icon = ok ? ICON.check.replace("<svg", '<svg width="22" height="22" style="color:var(--ok);flex:none"') : ICON.warn.replace("<svg", '<svg style="color:var(--warn);flex:none"');
  const html = `<div class="verdict ${ok ? "safe" : "esc"}">${icon}
      <div><h4>${esc(label)}</h4><span class="muted" style="font-size:.85rem">${inc.escalation_reason ? esc(inc.escalation_reason.slice(0, 240)) : inc.status === "DEPLOYED" ? "Every gate passed, an analyst approved it, and it was applied to the firewall." : ok ? "Every gate passed. A human decides whether it is applied." : ""}</span></div>${buttons}</div>
    <div class="cols">
      <div>${ok && m ? `<div class="k">iptables rule (kernel-verified)</div><div class="code">${esc(m.iptables_rule)}<button class="btn sm copy" data-copy="${esc(m.iptables_rule)}">Copy</button></div>` : ""}
        ${inc.snort_rule ? `<div class="k" style="margin-top:14px">Snort drop signature <span class="muted" style="text-transform:none;letter-spacing:0">(${esc(inc.snort_source)}; static check)</span></div><div class="code">${esc(inc.snort_rule)}<button class="btn sm copy" data-copy="${esc(inc.snort_rule)}">Copy</button></div>` : ""}
        ${inc.deploy_output ? `<div class="k" style="margin-top:14px">Deployment output</div><div class="json">${esc(inc.deploy_output)}</div>` : ""}</div>
      <div><div class="k">Where the time went · ${secs(span)} end to end</div><div class="wf">${segs.map((s) => `<div class="wf-row"><span class="muted">${esc(s.name)}</span><span class="wf-track"><span class="wf-seg" style="left:${(s.from / span) * 100}%;width:${Math.max((s.dur / span) * 100, 0.8)}%;--c:${s.c}"></span></span><span class="mono muted" style="text-align:right">${secs(s.dur)}</span></div>`).join("")}</div></div>
    </div>`;
  return { html, sig: [inc.status, inc.deploy_output, inc.snort_rule, ordered.length], chip: chip(secs(span), ok ? "ok" : "warn") };
}
