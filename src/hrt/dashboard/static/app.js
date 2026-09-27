"use strict";
const $ = (id) => document.getElementById(id);
const incidents = new Map();
let selected = null;

const fmtBytes = (n) => {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB"]; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
};
const esc = (s) => String(s ?? "").replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));

function pill(id, on, label) {
  const el = $(id); el.className = "pill " + (on ? "on" : "off");
  el.textContent = label || el.textContent;
}

async function refreshSummary() {
  try {
    const s = await (await fetch("/api/summary")).json();
    pill("pill-rag", s.rag, s.rag ? "RAG ready" : "RAG off");
    pill("pill-sandbox", s.sandbox, s.sandbox ? "sandbox up" : "sandbox down");
    pill("pill-deploy", true); $("pill-deploy").className = "pill " + (s.auto_deploy ? "off" : "on");
    $("pill-deploy").textContent = s.auto_deploy ? "auto-deploy" : "gated";
    renderFirewall(s.firewall_rules || []);
    if (s.stats) applyStats(s.stats);
  } catch (e) { /* server starting */ }
}

function applyStats(st) {
  $("m-flows").textContent = (st.flows_total || 0).toLocaleString("en-US");
  $("m-alerts").textContent = (st.alerts_total || 0).toLocaleString("en-US");
  const raw = st.raw_bytes_total || 0, comp = st.alert_bytes_total || 0;
  // floor (not round) so a 99.996% reduction is never displayed as an impossible 100%
  const red = raw && comp ? Math.floor(10000 * (1 - comp / raw)) / 100 : null;
  $("m-reduction").textContent = red === null ? "--" : `${red.toFixed(2)}%`;
  $("m-reduction").title = `${fmtBytes(raw)} raw -> ${fmtBytes(comp)} in alerts`;
}

function recount() {
  let dep = 0, esc_ = 0;
  for (const i of incidents.values()) { if (i.status === "DEPLOYED") dep++; if (i.status === "ESCALATED") esc_++; }
  $("m-incidents").textContent = incidents.size;
  $("m-deployed").textContent = dep;
  $("m-escalated").textContent = esc_;
}

function renderFirewall(rules) {
  const blocks = rules.filter((r) => /(-A|-I)\s/.test(r) && /-j\s+(DROP|REJECT)/.test(r));
  $("firewall").textContent = blocks.length ? blocks.join("\n") : "(no block rules deployed)";
}

function upsert(inc) {
  incidents.set(inc.incident_id, inc);
  renderList();
  if (selected === inc.incident_id) renderDetail(inc);
  recount();
}

function renderList() {
  const list = $("incident-list");
  const items = [...incidents.values()].sort((a, b) => b.alert.detected_at - a.alert.detected_at);
  if (!items.length) { list.innerHTML = '<div class="empty">Waiting for alerts&hellip;</div>'; return; }
  list.innerHTML = "";
  for (const inc of items) {
    const rules = inc.alert.detector.rules || [];
    const ml = inc.alert.detector.ml_anomaly ? '<span class="tag">ML</span>' : "";
    const d = document.createElement("div");
    d.className = "card" + (selected === inc.incident_id ? " sel" : "");
    d.onclick = () => { selected = inc.incident_id; renderList(); renderDetail(inc); };
    d.innerHTML = `<div class="row1"><span class="ip">${esc(inc.alert.source_ip)}</span>
      <span class="status s-${inc.status}">${inc.status}</span></div>
      <div class="rules">${rules.map((r) => `<span class="tag">${esc(r)}</span>`).join("")}${ml}</div>`;
    list.appendChild(d);
  }
}

function tier(title, right, bodyHtml) {
  return `<div class="tier"><h3>${title}<span class="sub">${right || ""}</span></h3><div class="body">${bodyHtml}</div></div>`;
}

function renderDetail(inc) {
  const a = inc.alert, f = a.features, det = a.detector;
  const t1 = `<div class="kv">
    <b>source</b><span class="mono">${esc(a.source_ip)}</span>
    <b>flows / window</b><span>${a.raw_flow_count} in ${f.window_seconds}s</span>
    <b>dst ports/hosts</b><span>${f.n_dst_ports} ports, ${f.n_dst_hosts} hosts</span>
    <b>SYN/ACK ratio</b><span>${f.syn_ack_ratio} (half-open ${(f.half_open_frac*100).toFixed(0)}%)</span>
    <b>rate</b><span>${f.flows_per_s}/s, rej ${(f.rej_frac*100).toFixed(0)}%</span>
    <b>rules</b><span>${(det.rules||[]).join(", ") || "-"}</span>
    <b>ML</b><span>${det.ml_anomaly ? `anomaly (score ${det.ml_score?.toFixed(3)} > ${det.ml_threshold?.toFixed(3)})` : "-"}</span>
  </div>`;

  let t2 = '<div class="sub">RAG disabled or pending.</div>';
  if (inc.retrieval) {
    const r = inc.retrieval;
    const docs = r.docs.map((d) => `<div class="doc"><span class="score">${d.score.toFixed(2)}</span>
      <b>${esc(d.mitre_id)}</b> ${esc(d.name)} <span class="sub">[${esc((d.tactics||[]).join(", "))}]</span></div>`).join("");
    t2 = `<div class="kv"><b>tactic prefilter</b><span>${esc((r.candidate_tactics||[]).join(", ") || "none")}</span>
      <b>search space</b><span>${r.candidates} / ${r.total_docs} techniques (${(r.search_space_reduction*100).toFixed(1)}% reduction)</span></div>
      <div style="margin-top:8px">${docs}</div>`;
  }

  const m = inc.mitigation;
  let t3 = '<div class="sub">No mitigation produced yet.</div>';
  if (m) {
    const v = inc.verdict;
    const checks = v ? v.checks.map((c) => `<div class="check">
      <span class="badge ${c.passed ? "p" : "f"}">${c.passed ? "✓" : "✕"}</span>
      <div><span class="cs">${esc(c.stage)}</span> <span class="sub">${c.elapsed_ms ? c.elapsed_ms.toFixed(0)+"ms" : ""}</span>
      <div>${esc(c.detail)}</div></div></div>`).join("") : "";
    const atts = inc.attempts.map((at) => `<span class="att ${at.error ? "bad" : "ok"}" title="${esc(at.error||"passed")}">#${at.number} ${at.llm_seconds}s</span>`).join("");
    const canAct = inc.status === "SAFE";
    t3 = `<div class="kv"><b>attack</b><span>${esc(m.attack_type)}</span>
      <b>technique</b><span class="mono">${esc(m.mitre_technique_id)} ${esc(m.mitre_technique_name)}</span>
      <b>tactic</b><span>${esc(m.mitre_tactic)}</span>
      <b>grounded</b><span>${inc.grounded ? "yes (in retrieved set)" : "no"}</span>
      <b>confidence</b><span>${m.confidence}</span></div>
      <div class="sub" style="margin-top:8px">${esc(m.incident_summary)}</div>
      <div class="rule">${esc(m.iptables_rule)}</div>
      <div class="attempts">${atts}</div>
      ${checks ? `<div style="margin-top:10px">${checks}</div>` : ""}
      ${inc.escalation_reason ? `<div class="banner">Escalated: ${esc(inc.escalation_reason)}</div>` : ""}
      ${inc.deploy_output ? `<div class="sub" style="margin-top:8px">deploy: ${esc(inc.deploy_output)}</div>` : ""}
      <div class="actions">
        <button class="primary" ${canAct ? "" : "disabled"} onclick="act('${inc.incident_id}','approve')">Approve &amp; deploy</button>
        <button class="ghost" ${canAct ? "" : "disabled"} onclick="act('${inc.incident_id}','reject')">Reject</button>
      </div>`;
  }

  const took = inc.times && inc.times.verified && inc.times.queued
    ? `${(inc.times.verified - inc.times.queued).toFixed(1)}s to verify` : "";
  $("detail").innerHTML = `<div class="tiers">
    ${tier("Tier 1 &middot; Telemetry triage", "", t1)}
    ${tier("Tier 2 &middot; RAG intelligence", inc.retrieval ? inc.retrieval.seconds + "s" : "", t2)}
    ${tier("Tier 3 &middot; Guardrail &amp; sandbox", took, t3)}
  </div>`;
}

async function act(id, what) {
  const inc = await (await fetch(`/api/incidents/${id}/${what}`, { method: "POST" })).json();
  upsert(inc);
  refreshSummary();
}
window.act = act;

function connect() {
  const es = new EventSource("/api/stream");
  es.onopen = () => pill("pill-stream", true, "stream live");
  es.onerror = () => pill("pill-stream", false, "stream lost");
  es.onmessage = (e) => {
    const { kind, payload } = JSON.parse(e.data);
    if (kind === "incident") upsert(payload);
    else if (kind === "stats") applyStats(payload);
  };
}

async function boot() {
  for (const inc of await (await fetch("/api/incidents")).json()) incidents.set(inc.incident_id, inc);
  // deep link: /#latest opens the newest incident's three-tier trace (handy for demos/screenshots)
  if (location.hash === "#latest" && incidents.size) {
    const newest = [...incidents.values()].sort((a, b) => b.alert.detected_at - a.alert.detected_at)[0];
    selected = newest.incident_id;
    renderDetail(newest);
  }
  renderList(); recount(); refreshSummary();
  // ?snapshot renders a static view (no live stream / polling), e.g. for headless screenshots
  if (!new URLSearchParams(location.search).has("snapshot")) {
    connect();
    setInterval(refreshSummary, 4000);
  } else {
    pill("pill-stream", true, "snapshot");
  }
}
boot();
