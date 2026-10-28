// The pipeline lane: six stages with live counters. A dot travels along a connector when an incident really crosses it.
import { $, fmt, reduced } from "./util.js";
import { state, on } from "./state.js";

const STAGES = [
  { id: "net", cls: "t0", name: "Traffic", tag: "WIRE", color: "#6f747c" },
  { id: "zeek", cls: "t0", name: "Zeek sensor", tag: "SENSOR", color: "#6f747c" },
  { id: "t1", cls: "t1", name: "Triage", tag: "TIER 1", color: "#c8523d" },
  { id: "t2", cls: "t2", name: "Reasoning", tag: "TIER 2", color: "#8fa3b8" },
  { id: "t3", cls: "t3", name: "Guardrail", tag: "TIER 3", color: "#d4af6a" },
  { id: "fw", cls: "t3", name: "Firewall", tag: "ACTION", color: "#d4af6a" },
];
let cards = [], nums = {}, subs = {}, lane;
const crossed = new Map();

export function initLane() {
  lane = $("#lane");
  lane.innerHTML = STAGES.map((s) => `<div class="stage ${s.cls}" data-id="${s.id}"><span class="led"></span><h3>${s.name}<em>${s.tag}</em></h3><div class="num" id="n-${s.id}">–</div><div class="sub" id="s-${s.id}">idle</div></div>`).join("");
  cards = [...lane.querySelectorAll(".stage")];
  STAGES.forEach((s) => { nums[s.id] = $(`#n-${s.id}`); subs[s.id] = $(`#s-${s.id}`); });
  on(onEvent);
  setInterval(ambient, 260);
  render();
}

function stageOf(inc) {
  if (inc.status === "QUEUED") return 2;
  if (inc.status === "ANALYZING") return inc.verdict || inc.attempts?.some((a) => a.verdict) ? 4 : 3;
  if (inc.status === "SAFE") return 5;
  if (inc.status === "DEPLOYED") return 6;
  return 4.5;
}

function render() {
  const s = state.stats, incs = [...state.incidents.values()];
  const busy = incs.filter((i) => ["QUEUED", "ANALYZING"].includes(i.status)).length;
  const ver = incs.filter((i) => ["SAFE", "DEPLOYED"].includes(i.status)).length, dep = incs.filter((i) => i.status === "DEPLOYED").length;
  const rate = s.flows_per_s || 0;
  nums.net.textContent = fmt(rate); subs.net.textContent = rate ? "flows / second" : "idle";
  nums.zeek.textContent = fmt(s.flows_total || 0); subs.zeek.textContent = "records parsed";
  nums.t1.textContent = fmt(s.alerts_total || 0); subs.t1.textContent = Object.keys(s.rule_hits || {}).join(" · ") || "rules + Isolation Forest";
  const last = incs.at(-1), tm = last?.times || {};
  const dt = (a, b) => (tm[a] != null && tm[b] != null ? tm[b] - tm[a] : null);
  const ret = dt("analysis_started", "retrieved"), llm = last?.attempts?.length ? last.attempts.reduce((x, a) => x + a.llm_seconds, 0) : null;
  const gr = last?.attempts?.filter((a) => a.verdict).at(-1)?.verdict?.checks?.reduce((x, c) => x + (c.elapsed_ms || 0), 0);
  nums.t2.textContent = fmt(incs.length);
  subs.t2.textContent = busy ? `${busy} analysing…` : last && llm != null ? `last: retrieve ${ret != null ? ret.toFixed(1) : "–"} s · LLM ${llm.toFixed(0)} s` : "ATT&CK RAG + local LLM";
  nums.t3.textContent = fmt(ver);
  subs.t3.textContent = gr != null ? `last: 4 checks in ${fmt(gr, 0)} ms` : "policy · subnet · conflict · kernel";
  nums.fw.textContent = fmt(dep); subs.fw.textContent = dep ? "attackers blocked" : "waiting for approval";
  const latest = incs.at(-1), st = latest ? stageOf(latest) : -1;
  cards.forEach((c, i) => { c.classList.toggle("active", i === Math.floor(st) && st < 6); c.classList.toggle("done", i < st); });
}

function dotAlong(i, color, r = 5, dur = 0.9) {
  if (reduced() || !cards[i + 1]) return;
  const L = lane.getBoundingClientRect(), a = cards[i].getBoundingClientRect(), b = cards[i + 1].getBoundingClientRect();
  const d = document.createElement("div"); d.className = "dot"; d.style.background = color; d.style.width = d.style.height = `${r * 2}px`; d.style.margin = `${-r}px 0 0 ${-r}px`;
  lane.appendChild(d);
  gsap.fromTo(d, { left: a.right - L.left - 4, top: (a.top + a.height / 2) - L.top, opacity: 1 }, { left: b.left - L.left + 4, duration: dur, ease: "power1.inOut", onComplete: () => d.remove() });
}
const token = (i, color) => { dotAlong(i, color, 7, 1.1); gsap.fromTo(cards[i + 1], { scale: 1 }, { scale: 1.02, duration: 0.18, yoyo: true, repeat: 1 }); };

function ambient() {
  const rate = state.stats.flows_per_s || 0;
  if (rate <= 0 || document.hidden) return;
  if (Math.random() < Math.min(1, rate / 40)) dotAlong(0, "#6f747c", 2.5, 0.8);
  if (Math.random() < Math.min(1, rate / 60)) dotAlong(1, "#6f747c", 2.5, 0.8);
}

function onEvent(kind, inc) {
  if (["stats", "incident:new", "incident:update", "mode", "summary"].includes(kind)) render();
  if (kind === "mode") crossed.clear();
  if (kind === "incident:new" || kind === "incident:update") {
    const st = stageOf(inc), seen = crossed.get(inc.incident_id) ?? new Set();
    crossed.set(inc.incident_id, seen);
    const hop = (i, min, color) => { if (st >= min && !seen.has(i)) { seen.add(i); token(i, color); } };
    hop(2, 2, "#c8523d"); hop(3, 4, "#8fa3b8"); hop(4, 5, "#d4af6a");
  }
}
