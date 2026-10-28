// The guided demo: caption steps driven by what the pipeline actually does. Live (lab up) it launches a port scan;
// otherwise it replays a recorded incident with the waiting compressed. Steps wait for each other, so a caption is
// never shown before the thing it describes has happened.
import { $, esc, fmt, pct, secs } from "./util.js";
import { state, on, api, launch, setMode, approve } from "./state.js";
import { startReplay, stopReplay } from "./replay.js";
import { setPulse, log } from "./panel.js";

const TOTAL = 8, DWELL = 4200;
let active = false, queue = [], seen = {}, t0 = 0, shownAt = 0, clock = 0, drain = 0, autoTimer = 0, baseline = [];
export const isDemo = () => active;

function caption(n, html) {
  const cap = $("#caption");
  cap.classList.remove("idle");
  $("#cap-step").textContent = `step ${n} / ${TOTAL}`;
  $("#cap-say").innerHTML = html;
  if (window.gsap) gsap.fromTo("#cap-say", { opacity: 0, y: 8 }, { opacity: 1, y: 0, duration: 0.4 });
  shownAt = Date.now();
}
function say(id, n, html) {
  if (!active || seen[id]) return;
  seen[id] = true;
  if (queue.length >= 2) queue.splice(0, queue.length - 1);            // never fall far behind: keep only the newest
  queue.push([n, html]);
  pump();
}
function pump() {
  if (!queue.length || Date.now() - shownAt < DWELL) return;
  const [n, html] = queue.shift();
  caption(n, html);
}

function onEvent(kind, p) {
  if (!active) return;
  if (kind === "stats") {
    const r = p.flows_per_s || 0;
    if (baseline.length < 4) baseline.push(r);
    const base = baseline.reduce((a, b) => a + b, 0) / Math.max(baseline.length, 1);
    if (r >= Math.max(30, base * 3)) say("spike", 2, `An attacker at <b>10.10.0.66</b> starts probing ports. Flows per second jump from about ${fmt(base)} to <b>${fmt(r)}</b>.`);
  }
  if (kind === "incident:new") {
    const a = p.alert;
    say("alert", 3, `<b>Tier 1</b> collapses ${fmt(a.raw_flow_count)} flows into one alert of ${fmt(JSON.stringify(a).length)} bytes (${a.detector.rules.join(" + ") || "anomaly"}). Raw packets never reach the language model.`);
  }
  if (kind === "incident:new" || kind === "incident:update") {
    const inc = p;
    if (inc.retrieval) say("rag", 4, `<b>Tier 2</b> uses the rule's tactic hints to search only ${fmt(inc.retrieval.candidates)} of ${fmt(inc.retrieval.total_docs)} ATT&amp;CK techniques (${pct(inc.retrieval.search_space_reduction, 0)} fewer), then asks a local LLM.`);
    const a1 = inc.attempts[0];
    if (a1?.mitigation) say("llm", 5, `The model names <b>${esc(a1.mitigation.mitre_technique_id)} ${esc(a1.mitigation.mitre_technique_name || "")}</b> and proposes <b>${esc(a1.mitigation.iptables_rule)}</b>. Its answer is untrusted until Tier 3 checks it.`);
    const bad = inc.attempts.find((a) => a.error || (a.verdict && !a.verdict.passed));
    if (bad) {
      const f = bad.verdict?.checks.find((c) => !c.passed);
      say("reject", 6, `<b>Tier 3 rejected</b> attempt ${bad.number}${f ? ` at the ${esc(f.stage)} gate` : ""}. The exact reason is fed back and the model tries again: nothing unsafe reaches the firewall.`);
    }
    if (inc.verdict?.passed) say("gates", 6, `<b>Tier 3</b> runs four deterministic checks: policy, subnet maths, conflicts, and a real <b>iptables dry run</b> in a throwaway container. All pass.`);
    if (inc.status === "SAFE") {
      say("safe", 7, `A <b>verified rule</b> is waiting for the analyst. Nothing is applied until a human approves${state.mode === "live" ? " (the demo approves in 8 seconds)" : ""}.`);
      setPulse(true);
      if (state.mode === "live" && !autoTimer) autoTimer = setTimeout(() => approve(inc.incident_id).catch(() => {}), 8000);
    }
    if (inc.status === "DEPLOYED") {
      const t = Object.values(inc.times || {}), span = t.length ? Math.max(...t) - Math.min(...t) : 0;
      setPulse(false);
      say("done", 8, `<b>Rule deployed.</b> The attacker is blocked and legitimate traffic is untouched. First packet to verified rule: <b>${secs(span)}</b>, on a CPU-only laptop.`);
      finishSoon();
    }
    if (inc.status === "ESCALATED") {
      say("done", 8, `<b>No safe rule after 3 attempts, so it escalates to a human.</b> The guardrail never lets an unsafe rule through, even when the model fails.`);
      finishSoon();
    }
  }
}
let off = null;
function finishSoon() { setTimeout(() => { if (active) { active = false; end(false); $("#cap-say").innerHTML += " <span style='color:var(--muted);font-weight:500'>Demo complete.</span>"; } }, 12000); }

function end(reset = true) {
  clearInterval(clock); clearInterval(drain); clearTimeout(autoTimer); autoTimer = 0;
  setPulse(false);
  $("#btn-demo").textContent = "Run 2–3 min demo"; $("#btn-demo").classList.remove("stop"); $("#btn-demo").classList.add("demo");
  if (reset) { stopReplay(); $("#caption").classList.add("idle"); $("#cap-step").textContent = "ready"; $("#cap-say").innerHTML = "Press <b>Run 2–3 min demo</b> to watch one attack travel through the pipeline."; $("#cap-tm").textContent = ""; }
}

export async function toggleDemo(note = () => {}) {
  if (active) { active = false; end(true); return; }
  active = true; queue = []; seen = {}; baseline = []; t0 = Date.now(); shownAt = 0;
  const btn = $("#btn-demo"); btn.textContent = "Stop demo"; btn.classList.remove("demo"); btn.classList.add("stop");
  clock = setInterval(() => { const s = Math.floor((Date.now() - t0) / 1000); $("#cap-tm").textContent = `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`; }, 1000);
  drain = setInterval(pump, 400);
  if (!off) off = on(onEvent);
  caption(1, `Normal operation: Zeek records every connection and <b>Tier 1</b> watches 10-second windows per source. Watch the traffic panel.`);
  const live = !!state.summary?.sandbox;
  if (live) {
    try {
      await api("/api/reset", { method: "POST" });
      setMode("live");
      setTimeout(() => active && launch("scan").catch(() => { note("Could not start the attack; switching to the recorded run."); fallback(note); }), 5000);
      return;
    } catch { /* fall through to replay */ }
  }
  fallback(note);
}
async function fallback(note) {
  stopReplay();
  const ok = await startReplay(note, { budget: 70 });
  if (!ok) { active = false; end(true); note("No recording and no lab: nothing to demo."); }
}
