// Current-incident panel (four columns), firewall rules and the event feed.
import { $, esc, fmt, pct, bytes, secs, RULE_TEXT, toast } from "./util.js";
import { state, on, approve, reject } from "./state.js";

let selected = null, picked = false, pulse = false;
const snap = new Map();                 // incident id -> what the feed has already reported

export const setPulse = (v) => { pulse = v; render(); };
export function log(text, kind = "") {
  const ul = $("#feed"), li = document.createElement("li");
  if (kind) li.className = kind;
  li.innerHTML = `<time>${new Date().toLocaleTimeString("en-GB")}</time><span>${esc(text)}</span>`;
  ul.prepend(li);
  while (ul.children.length > 40) ul.lastElementChild.remove();
  if (window.gsap) gsap.from(li, { opacity: 0, y: -6, duration: 0.25 });
}

export function initPanel() {
  on((kind, p) => {
    if (kind === "mode") { selected = null; picked = false; snap.clear(); $("#feed").innerHTML = ""; render(); }
    if (kind === "incident:new") { if (!picked) selected = p.incident_id; report(p); render(); }
    if (kind === "incident:update") { report(p); render(); }
    if (kind === "summary") firewall();
  });
  $("#tabs").addEventListener("click", (e) => { const b = e.target.closest("[data-id]"); if (b) { selected = b.dataset.id; picked = true; render(); } });
  $("#cols").addEventListener("click", async (e) => {
    const a = e.target.closest("[data-act]"); if (!a || !selected) return;
    if (state.mode === "replay") { toast("Approval is disabled in replay mode"); return; }
    a.disabled = true;
    try { await (a.dataset.act === "approve" ? approve(selected) : reject(selected)); } catch { toast("Request failed"); a.disabled = false; }
  });
  render();
}

// ---- turn state changes into one-line events
function report(inc) {
  const s = snap.get(inc.incident_id) ?? { attempts: 0, status: "", retrieved: false, verdicts: 0 };
  const ip = inc.alert.source_ip;
  if (!snap.has(inc.incident_id)) log(`ALERT ${ip}: ${inc.alert.detector.rules.join(" + ") || "ML anomaly"} (${fmt(inc.alert.raw_flow_count)} flows → 1 alert)`, "threat");
  if (inc.retrieval && !s.retrieved) { s.retrieved = true; log(`Tier 2: searched ${fmt(inc.retrieval.candidates)} of ${fmt(inc.retrieval.total_docs)} ATT&CK techniques (−${pct(inc.retrieval.search_space_reduction, 0)})`, "reason"); }
  while (s.attempts < inc.attempts.length) {
    const a = inc.attempts[s.attempts++];
    if (a.mitigation) log(`LLM attempt ${a.number}: ${a.mitigation.mitre_technique_id} → ${a.mitigation.iptables_rule}`, "reason");
    const f = a.verdict && !a.verdict.passed ? a.verdict.checks.find((c) => !c.passed) : null;
    if (a.error) log(`Rejected (${a.error.split(":")[0]}): ${a.error.slice(0, 70)}`, "threat");
    else if (f) log(`Tier 3 gate "${f.stage}" rejected: ${f.detail.slice(0, 70)}`, "threat");
    else if (a.verdict?.passed) log("Tier 3: all four gates passed", "pass");
  }
  if (inc.status !== s.status) {
    s.status = inc.status;
    if (inc.status === "SAFE") log("Verified rule is waiting for the analyst", "ok");
    if (inc.status === "DEPLOYED") log(`Rule deployed: ${ip} is blocked`, "ok");
    if (inc.status === "ESCALATED") log("No safe rule: escalated to a human", "threat");
    if (inc.status === "REJECTED") log("Analyst rejected the rule", "");
  }
  snap.set(inc.incident_id, s);
}

function firewall() {
  const rules = (state.summary?.firewall_rules || []).filter((r) => /(-A|-I)\s/.test(r) && /-j\s+(DROP|REJECT)/.test(r));
  const dep = [...state.incidents.values()].filter((i) => i.status === "DEPLOYED" && i.mitigation).map((i) => i.mitigation.iptables_rule);
  const all = [...new Set([...rules, ...dep])].slice(-4);
  $("#rules").innerHTML = all.length ? all.map((r) => `<li>${esc(r)}</li>`).join("") : `<li class="empty">none yet</li>`;
}

// ---- the four columns
function render() {
  const incs = [...state.incidents.values()];
  $("#tabs").innerHTML = incs.slice(-5).map((i) => `<button class="tab" data-id="${i.incident_id}" ${i.incident_id === selected ? 'aria-current="true"' : ""}>${esc(i.alert.source_ip)} · ${esc(i.alert.detector.rules[0] || "ML")}</button>`).join("");
  firewall();
  const inc = state.incidents.get(selected), st = $("#status"), cols = $("#cols");
  if (!inc) {
    st.style.display = "none";
    cols.innerHTML = `<div class="empty" style="grid-column:1/-1;align-self:center">No incident yet. Launch an attack from the controls, or replay a recorded run.</div>`;
    return;
  }
  const [label, cls] = ({ QUEUED: ["queued", "busy"], ANALYZING: ["analysing", "busy"], SAFE: ["verified", "ok"], DEPLOYED: ["deployed", "ok"], ESCALATED: ["escalated", "esc"], REJECTED: ["rejected", "bad"], DUPLICATE: ["already blocked", ""], ERROR: ["error", "bad"] }[inc.status] || [inc.status, ""]);
  st.style.display = ""; st.className = `status ${cls}`; st.textContent = label;
  cols.innerHTML = c1(inc) + c2(inc) + c3(inc) + c4(inc);
}

function c1(inc) {
  const a = inc.alert, f = a.features, d = a.detector, alertBytes = JSON.stringify(a).length, raw = a.raw_bytes || 0;
  return `<div class="col c1 on"><h4>1 · Tier 1 triage</h4>
    <div class="big">${fmt(a.raw_flow_count)} <span style="font-size:.45em;color:var(--muted)">flows → 1</span></div>
    <div class="chips">${(d.rules.length ? d.rules : ["ML anomaly"]).map((r) => `<span class="chip t1">${esc(r)}</span>`).join("")}</div>
    <p>${esc(d.rules.map((r) => RULE_TEXT[r]).filter(Boolean)[0] || "Statistically unusual for this source")}</p>
    <p class="mono" style="font-size:.7rem">${fmt(f.n_dst_ports)} ports · ${fmt(f.flows_per_s, 1)} flows/s · ${(f.half_open_frac * 100).toFixed(0)}% half-open${raw ? ` · ${bytes(raw)} → ${bytes(alertBytes)}` : ""}</p></div>`;
}

function c2(inc) {
  const r = inc.retrieval, last = inc.attempts.at(-1), m = last?.mitigation || inc.mitigation, on_ = !!r || !!m;
  const docs = (r?.docs || []).slice(0, 3).map((d) => `<div class="doc"><span>${esc(d.mitre_id)}</span><i style="width:${Math.round(Math.max(0, d.score) * 100)}%"></i><span>${d.score.toFixed(2)}</span></div>`).join("");
  return `<div class="col c2 ${on_ ? "on" : ""}"><h4>2 · Tier 2 reasoning</h4>
    ${r ? `<div class="big">−${pct(r.search_space_reduction, 0)}</div><p>search space: ${fmt(r.candidates)} of ${fmt(r.total_docs)} techniques (${esc(r.candidate_tactics.join(", ") || "all")})</p>${docs}` : `<p>retrieving ATT&CK techniques…</p>`}
    ${m ? `<p><b style="color:var(--text)">${esc(m.mitre_technique_id)}</b> ${esc(m.mitre_technique_name || "")} · attempt ${inc.attempts.length}/3</p>` : ""}</div>`;
}

function c3(inc) {
  const at = inc.attempts.filter((a) => a.verdict).at(-1) || null, v = at?.verdict || inc.verdict, by = Object.fromEntries((v?.checks || []).map((c) => [c.stage, c]));
  const bad = inc.attempts.find((a) => a.error), failed = v?.checks.find((c) => !c.passed);
  const names = [["policy", "POLICY"], ["subnet", "SUBNET"], ["conflict", "CONFLICT"], ["kernel", "KERNEL"]];
  return `<div class="col c3 ${v || bad ? "on" : ""}"><h4>3 · Tier 3 guardrail</h4>
    <div class="gates">${names.map(([k, n]) => { const c = by[k]; return `<div class="gate ${c ? (c.passed ? "pass" : "fail") : ""}"><span>${n}</span><span>${c ? (c.passed ? "✓" : "✕") : "·"}</span></div>`; }).join("")}</div>
    ${failed ? `<p class="note bad">${esc(failed.stage)}: ${esc(failed.detail.slice(0, 110))}</p><p class="note">The reason goes back to the model.</p>` : v?.passed ? `<p class="note">Every check passed, including a real <code>iptables-restore --test</code> in a throwaway container (${fmt(by.kernel?.elapsed_ms, 0)} ms).</p>` : bad ? `<p class="note bad">${esc(bad.error.slice(0, 110))}</p>` : `<p class="note">waiting for a proposed rule…</p>`}</div>`;
}

function c4(inc) {
  const m = inc.mitigation, t = Object.values(inc.times || {}), span = t.length ? Math.max(...t) - Math.min(...t) : 0;
  const done = ["SAFE", "DEPLOYED", "ESCALATED", "REJECTED"].includes(inc.status);
  const btn = inc.status === "SAFE" ? `<div class="actions"><button class="btn go ${pulse ? "pulse" : ""}" data-act="approve">Approve and deploy</button><button class="btn" data-act="reject">Reject</button></div>` : "";
  return `<div class="col c4 ${done ? "on" : ""}"><h4>4 · Outcome</h4>
    ${m && ["SAFE", "DEPLOYED"].includes(inc.status) ? `<div class="rule">${esc(m.iptables_rule)}</div>` : `<p>${done ? esc((inc.escalation_reason || "").slice(0, 140)) : "no verified rule yet"}</p>`}
    ${inc.snort_rule && ["SAFE", "DEPLOYED"].includes(inc.status) ? `<p class="mono" style="font-size:.66rem;color:var(--muted)">${esc(inc.snort_rule.slice(0, 78))}…</p>` : ""}
    ${btn}${done ? `<p class="mono" style="font-size:.72rem;color:var(--muted)">${secs(span)} end to end</p>` : ""}</div>`;
}
