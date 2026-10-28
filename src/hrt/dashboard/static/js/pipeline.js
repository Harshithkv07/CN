// Hero: the live pipeline diagram. Packet dots are driven by the real flows/s; tokens by real incident progress.
import { $, fmt, pct, bytes, countTo, reduced } from "./util.js";
import { state, on } from "./state.js";

const NS = "http://www.w3.org/2000/svg";
const NODES = [
  { id: "net",  x: 85,   w: 150, name: "Network traffic",  sub: "benign + attacker", c: "var(--t0)", ic: "NET" },
  { id: "zeek", x: 295,  w: 150, name: "Zeek sensor",      sub: "conn.log records",  c: "var(--t0)", ic: "ZK" },
  { id: "t1",   x: 505,  w: 150, name: "Triage",           sub: "IForest + rules",   c: "var(--t1)", tier: "TIER 1", ic: "T1" },
  { id: "t2",   x: 715,  w: 150, name: "Reasoning",        sub: "ATT&CK RAG + LLM",  c: "var(--t2)", tier: "TIER 2", ic: "T2" },
  { id: "t3",   x: 925,  w: 150, name: "Guardrail",        sub: "4-stage verifier",  c: "var(--t3)", tier: "TIER 3", ic: "T3" },
  { id: "fw",   x: 1115, w: 150, name: "Firewall",         sub: "iptables · Snort",  c: "var(--t3)", ic: "FW" },
];
const Y = 125, H = 118;
const el = (name, attrs = {}, parent) => {
  const n = document.createElementNS(NS, name);
  for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
  parent?.appendChild(n);
  return n;
};

let svg, layer, nodeEls = {}, linkEls = [], counts = {}, list = {}, spawnAcc = 0, alive = 0;
const crossed = new Map();   // incident id -> Set of link indexes already shown

export function initPipeline() {
  svg = $("#pipe");
  svg.innerHTML = "";
  const defs = el("defs", {}, svg);
  const glow = el("filter", { id: "glow", x: "-50%", y: "-50%", width: "200%", height: "200%" }, defs);
  el("feGaussianBlur", { stdDeviation: 3.2 }, glow);
  const linksG = el("g", {}, svg);
  layer = el("g", { id: "particles" }, svg);
  const nodesG = el("g", {}, svg);

  NODES.forEach((n, i) => {
    if (i) {
      const p = NODES[i - 1];
      linkEls.push(el("line", { class: "link", x1: p.x + p.w / 2, y1: Y, x2: n.x - n.w / 2, y2: Y, style: `--c:${n.c}` }, linksG));
    }
    const g = el("g", { class: "node", style: `--c:${n.c}`, role: "group", "aria-label": `${n.name}: ${n.sub}` }, nodesG);
    el("rect", { x: n.x - n.w / 2, y: Y - H / 2, width: n.w, height: H, rx: 16 }, g);
    const ring = el("rect", { class: "ring", x: n.x - n.w / 2, y: Y - H / 2, width: n.w, height: H, rx: 16, style: `--c:${n.c}` }, g);
    if (n.tier) { const t = el("text", { x: n.x, y: Y - 30, class: "tier", style: `fill:${n.c}` }, g); t.textContent = n.tier; }
    const t1 = el("text", { x: n.x, y: Y - (n.tier ? 8 : 14) }, g); t1.textContent = n.name;
    const t2 = el("text", { x: n.x, y: Y + (n.tier ? 10 : 4), class: "sub" }, g); t2.textContent = n.sub;
    const c = el("text", { x: n.x, y: Y + 38, class: "count" }, g); c.textContent = "–";
    nodeEls[n.id] = { g, ring }; counts[n.id] = c;
  });

  const ol = $("#pipe-list");
  ol.innerHTML = NODES.map((n) => `<li data-n="${n.id}"><span class="ic" style="color:${n.c}">${n.ic}</span><span><b>${n.name}</b><small>${n.sub}</small></span><span class="n" id="pl-${n.id}">–</span></li>`).join("");
  NODES.forEach((n) => (list[n.id] = $(`#pl-${n.id}`)));

  gsap.ticker.add(tick);
  on(onEvent);
  render();
}

function setCount(id, text) {
  if (counts[id]) counts[id].textContent = text;
  if (list[id]) list[id].textContent = text;
}

function render() {
  const s = state.stats;
  const analysing = [...state.incidents.values()].filter((i) => ["QUEUED", "ANALYZING"].includes(i.status)).length;
  const verified = [...state.incidents.values()].filter((i) => ["SAFE", "DEPLOYED"].includes(i.status)).length;
  const deployed = [...state.incidents.values()].filter((i) => i.status === "DEPLOYED").length;
  setCount("net", s.flows_per_s ? `${fmt(s.flows_per_s)} flows/s` : "idle");
  setCount("zeek", `${fmt(s.flows_total)} rec`);
  setCount("t1", `${fmt(s.alerts_total)} alerts`);
  setCount("t2", `${state.incidents.size} inc${analysing ? ` · ${analysing} busy` : ""}`);
  setCount("t3", `${verified} verified`);
  setCount("fw", `${deployed} blocked`);
  linkEls.forEach((l, i) => l.classList.toggle("live", i < 2 ? s.flows_per_s > 0 : state.incidents.size > 0));
}

function stageOf(inc) {
  if (["QUEUED"].includes(inc.status)) return 2;                               // Tier 1 produced it
  if (inc.status === "ANALYZING") return inc.verdict || inc.attempts?.some((a) => a.verdict) ? 4 : 3;
  if (inc.status === "SAFE") return 5;
  if (inc.status === "DEPLOYED") return 6;
  if (["ESCALATED", "ERROR", "REJECTED", "DUPLICATE"].includes(inc.status)) return 4.5;
  return 0;
}

function highlight(stage, tone) {
  NODES.forEach((n, i) => {
    const g = nodeEls[n.id].g;
    g.classList.toggle("active", i === Math.floor(stage) && stage < 6);
    g.classList.toggle("done", i < stage);
  });
  document.querySelectorAll("#pipe-list li").forEach((li, i) => li.classList.toggle("active", i === Math.floor(stage) && stage < 6));
}

function pulseRing(i) {
  if (reduced()) return;
  const r = nodeEls[NODES[i].id].ring;
  gsap.fromTo(r, { opacity: 0.9, scale: 1, transformOrigin: "50% 50%" }, { opacity: 0, scale: 1.14, transformOrigin: "50% 50%", duration: 0.9, ease: "power2.out" });
}

function dot(x1, x2, cls, { r = 3, dur = 0.9, glow = false } = {}) {
  if (reduced() || alive > 90) return null;
  const c = el("circle", { cx: x1, cy: Y + (Math.random() * 16 - 8) * (r < 4 ? 1 : 0), r, fill: cls, opacity: 0.0 }, layer);
  if (glow) c.setAttribute("filter", "url(#glow)");
  alive++;
  gsap.timeline({ onComplete: () => { c.remove(); alive--; } })
    .to(c, { opacity: 1, duration: 0.12 }, 0)
    .to(c, { attr: { cx: x2 }, duration: dur, ease: "none" }, 0)
    .to(c, { opacity: 0, duration: 0.15 }, dur - 0.15);
  return c;
}
const edge = (i) => [NODES[i].x + NODES[i].w / 2 - 4, NODES[i + 1].x - NODES[i + 1].w / 2 + 4];

function token(linkIndex, color, big = true) {
  const [a, b] = edge(linkIndex);
  const t = dot(a, b, color, { r: big ? 7 : 4, dur: reduced() ? 0.01 : 1.1, glow: true });
  if (t) gsap.fromTo(t, { attr: { r: 3 } }, { attr: { r: 8 }, duration: 0.5, yoyo: true, repeat: 1, ease: "sine.inOut" });
  pulseRing(linkIndex + 1);
}

function tick(_, dt) {
  const rate = state.stats.flows_per_s || 0;
  if (rate <= 0 || document.hidden) return;
  spawnAcc += (Math.min(rate, 60) / 60) * 22 * (dt / 1000);      // visual density is capped; the number shown is exact
  while (spawnAcc >= 1) {
    spawnAcc -= 1;
    const [a0, b0] = edge(0), [a1, b1] = edge(1), [a2, b2] = edge(2);
    dot(a0, b0, "var(--t0)", { dur: 0.7 });
    setTimeout(() => dot(a1, b1, "var(--t0)", { dur: 0.7 }), 420);
    if (Math.random() < 0.25) setTimeout(() => dot(a2, b2, "var(--t1)", { r: 2.5, dur: 0.7 }), 840);
  }
}

function onEvent(kind, payload) {
  if (kind === "stats" || kind === "incident:new" || kind === "incident:update" || kind === "mode" || kind === "summary") render();
  if (kind === "mode") { crossed.clear(); highlight(0); return; }
  if (kind === "incident:new" || kind === "incident:update") {
    const inc = payload, stage = stageOf(inc);
    const seen = crossed.get(inc.incident_id) ?? new Set();
    crossed.set(inc.incident_id, seen);
    const hop = (i, min, color) => { if (stage >= min && !seen.has(i)) { seen.add(i); token(i, color); } };
    hop(2, 2, "var(--t1)");                    // alert leaves Tier 1
    hop(3, 4, "var(--t2)");                    // the model's answer reaches the guardrail
    hop(4, 5, "var(--t3)");                    // a verified rule is offered to the firewall
    if (stage >= 4.5 && stage < 5 && !seen.has("esc")) { seen.add("esc"); pulseRing(4); }
    const latest = [...state.incidents.values()].at(-1);
    if (latest && latest.incident_id === inc.incident_id) highlight(stage);
  }
}
