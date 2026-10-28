// The film: a pinned, scroll-scrubbed canvas that follows one attack from raw packets to a firewall rule.
// Packets are drawn at a capped density; every number in the captions is read from results/*.json.
import { reduced, fmt, pct } from "./util.js";
import { state } from "./state.js";

const CH = [0, 0.2, 0.42, 0.64, 0.84, 1.001];               // chapter boundaries in scroll progress
const C = { traffic: "#6f747c", threat: "#c8523d", reason: "#8fa3b8", ok: "#d4af6a", ink: "#070707", line: "#34343a", text: "#ece6da", mute: "#857f74" };
const clamp = (v, a = 0, b = 1) => Math.min(b, Math.max(a, v));
const ease = (t) => 1 - Math.pow(1 - clamp(t), 3);
const lerp = (a, b, t) => a + (b - a) * t;

let cv, ctx, W = 0, H = 0, dpr = 1, parts = [], tokens = [], sparks = [], raf = 0, last = 0;
let prog = 0, progS = 0, mouse = { x: 0, y: 0 }, running = false;
let facts = { records: 634464, alerts: 10, reduction: 0.9999, space: 0.93, cases: 91 };
let story = { rule: "PORT_SCAN", technique: "T1595.001", tname: "Active Scanning", ip: "10.10.0.66", docs: [], iptables: "iptables -I INPUT 1 -s 10.10.0.66 -j DROP" };
let onChapter = () => {};
let curCh = -1;

export function setFacts(f) { facts = { ...facts, ...f }; }
export function setStory(s) { story = { ...story, ...s }; }
export const getFacts = () => facts;

const X = () => ({ sieve: W * 0.30, t2: W * 0.52, t3: W * 0.72, fw: W * 0.90, cy: H * 0.5 });

function resize() {
  dpr = Math.min(window.devicePixelRatio || 1, 2);
  W = cv.clientWidth; H = cv.clientHeight;
  cv.width = W * dpr; cv.height = H * dpr;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  const n = W < 700 ? 420 : 1100;
  parts = Array.from({ length: n }, () => spawn(true));
  tokens = Array.from({ length: 10 }, (_, i) => ({ i, off: i * 0.022, y: 0 }));
}
function spawn(init = false) {
  return { x: init ? Math.random() * W : -10 - Math.random() * 60, y: H * (0.16 + Math.random() * 0.68), v: 60 + Math.random() * 170, s: 0.8 + Math.random() * 1.6, a: 0.25 + Math.random() * 0.6, dead: 0 };
}

function ambientRate() { return state.stats?.flows_per_s > 0 ? 1 + Math.min(state.stats.flows_per_s, 400) / 200 : 1; }

function frame(t) {
  raf = requestAnimationFrame(frame);
  const dt = Math.min((t - last) / 1000 || 0.016, 0.05); last = t;
  progS += (prog - progS) * Math.min(1, dt * 6);                // cinematic lag behind the scrollbar
  draw(dt, t / 1000);
}

function draw(dt, time) {
  const g = X(), p = progS;
  ctx.clearRect(0, 0, W, H);
  const px = (mouse.x - 0.5) * 10, py = (mouse.y - 0.5) * 6;
  ctx.save(); ctx.translate(px, py);

  // --- guide rail
  ctx.strokeStyle = "rgba(133,127,116,0.22)"; ctx.lineWidth = 1;
  ctx.beginPath(); ctx.moveTo(0, g.cy); ctx.lineTo(W, g.cy); ctx.stroke();

  // --- gates (fade in with their chapter)
  const a1 = ease((p - 0.16) / 0.08), a2 = ease((p - 0.38) / 0.08), a3 = ease((p - 0.6) / 0.08), a4 = ease((p - 0.8) / 0.08);
  drawSieve(g, a1, p, time);
  drawReason(g, a2, p, time);
  drawGate(g, a3, p);
  drawWall(g, a4, p);

  // --- ambient packets
  const rate = ambientRate(), sieveOn = p > 0.2;
  ctx.fillStyle = C.traffic;
  for (let i = 0; i < parts.length; i++) {
    const q = parts[i];
    if (q.dead > 0) { q.dead -= dt; if (q.dead <= 0) Object.assign(q, spawn()); continue; }
    q.x += q.v * dt * rate * (0.6 + 0.4 * (1 - p));
    if (sieveOn && q.x >= g.sieve - 2 && q.x < g.sieve + 14) {   // removed by Tier 1
      q.dead = 0.25 + Math.random() * 0.4;
      if (sparks.length < 160) sparks.push({ x: g.sieve, y: q.y, vx: 20 + Math.random() * 40, vy: (Math.random() - 0.5) * 60, life: 0.4 });
      continue;
    }
    if (q.x > W + 10) { Object.assign(q, spawn()); continue; }
    ctx.globalAlpha = q.a * (q.x > g.sieve && sieveOn ? 0 : 1);
    ctx.fillRect(q.x, q.y, q.s * 2.2, q.s);
  }
  ctx.globalAlpha = 1;

  // --- sparks where packets are dropped
  ctx.fillStyle = C.threat;
  for (let i = sparks.length - 1; i >= 0; i--) {
    const s = sparks[i]; s.life -= dt; if (s.life <= 0) { sparks.splice(i, 1); continue; }
    s.x += s.vx * dt; s.y += s.vy * dt; ctx.globalAlpha = s.life * 1.6; ctx.fillRect(s.x, s.y, 1.6, 1.6);
  }
  ctx.globalAlpha = 1;

  drawTokens(g, p, time);
  drawLabels(g, p, a1, a2, a3, a4);
  ctx.restore();

  const ch = CH.findIndex((v, i) => p >= v && p < CH[i + 1]);
  if (ch !== curCh) { curCh = ch; onChapter(ch); }
}

function drawSieve(g, a, p, time) {
  if (a <= 0) return;
  ctx.save(); ctx.globalAlpha = a; ctx.strokeStyle = C.line; ctx.lineWidth = 1;
  const top = H * 0.12, bot = H * 0.88;
  for (let k = -2; k <= 2; k++) {
    ctx.beginPath(); ctx.setLineDash([2, 7]); ctx.moveTo(g.sieve + k * 6, top); ctx.lineTo(g.sieve + k * 6, bot); ctx.stroke();
  }
  ctx.setLineDash([]); ctx.strokeStyle = "rgba(200,82,61,0.6)"; ctx.lineWidth = 1.5;
  ctx.beginPath(); ctx.moveTo(g.sieve, top); ctx.lineTo(g.sieve, bot); ctx.stroke();
  const sweep = ((time * 0.35) % 1) * (bot - top) + top;          // slow scan line
  const grd = ctx.createLinearGradient(0, sweep - 30, 0, sweep + 30);
  grd.addColorStop(0, "rgba(200,82,61,0)"); grd.addColorStop(0.5, "rgba(200,82,61,0.26)"); grd.addColorStop(1, "rgba(200,82,61,0)");
  ctx.fillStyle = grd; ctx.fillRect(g.sieve - 14, sweep - 30, 28, 60);
  ctx.restore();
}

function drawReason(g, a, p, time) {
  if (a <= 0) return;
  ctx.save(); ctx.globalAlpha = a; ctx.translate(g.t2, g.cy);
  ctx.strokeStyle = C.reason; ctx.lineWidth = 1.4;
  ctx.beginPath(); ctx.arc(0, 0, 38, 0, Math.PI * 2); ctx.globalAlpha = a * 0.35; ctx.stroke(); ctx.globalAlpha = a;
  ctx.beginPath(); ctx.arc(0, 0, 38, time * 1.3, time * 1.3 + 1.7); ctx.stroke();
  ctx.beginPath(); ctx.arc(0, 0, 54, -time * 0.8, -time * 0.8 + 0.9); ctx.globalAlpha = a * 0.6; ctx.stroke();
  ctx.globalAlpha = a;
  // retrieved techniques fan out above and below while chapter 3 is active
  const f = ease((p - 0.46) / 0.1) * (1 - ease((p - 0.68) / 0.06));
  const docs = story.docs.length ? story.docs : [{ id: "T1595.001", name: "Active Scanning", score: 0.54 }, { id: "T1046", name: "Network Service Discovery", score: 0.49 }, { id: "T1595", name: "Active Scanning", score: 0.54 }];
  ctx.font = "500 11px 'IBM Plex Mono', ui-monospace, monospace"; ctx.textAlign = "left";
  docs.slice(0, 4).forEach((d, i) => {
    const y = -88 - i * 22, w = 150 * d.score + 20;
    ctx.globalAlpha = f * 0.9; ctx.fillStyle = C.reason;
    ctx.fillRect(-70, y + 4, w * f, 2);
    ctx.fillStyle = C.text; ctx.fillText(`${d.id}  ${d.score.toFixed(2)}`, -70, y);
  });
  ctx.restore();
}

function drawGate(g, a, p) {
  if (a <= 0) return;
  ctx.save(); ctx.translate(g.t3, g.cy);
  const names = ["POLICY", "SUBNET", "CONFLICT", "KERNEL"];
  ctx.font = "500 10px 'IBM Plex Mono', ui-monospace, monospace"; ctx.textAlign = "left";
  names.forEach((n, i) => {
    const y = -66 + i * 44, lit = ease((p - (0.66 + i * 0.035)) / 0.04);
    ctx.globalAlpha = a; ctx.strokeStyle = C.line; ctx.lineWidth = 1; ctx.strokeRect(-34, y, 68, 26);
    ctx.globalAlpha = a * lit; ctx.fillStyle = C.ok; ctx.fillRect(-34, y, 68 * lit, 26);
    ctx.globalAlpha = a; ctx.fillStyle = lit > 0.6 ? C.ink : C.mute; ctx.fillText(n, -29, y + 16);
  });
  ctx.restore();
}

function drawWall(g, a, p) {
  if (a <= 0) return;
  ctx.save(); ctx.translate(g.fw, g.cy); ctx.globalAlpha = a;
  ctx.strokeStyle = C.ok; ctx.lineWidth = 2; ctx.beginPath(); ctx.moveTo(0, -H * 0.3); ctx.lineTo(0, H * 0.3); ctx.stroke();
  ctx.fillStyle = "rgba(212,175,106,0.07)"; ctx.fillRect(0, -H * 0.3, 20, H * 0.6);
  ctx.restore();
}

function drawTokens(g, p, time) {
  const start = 0.24, end = 0.96;
  const u = clamp((p - start) / (end - start));
  tokens.forEach((tk, i) => {
    const pos = clamp(u * 1.3 - tk.off * 1.8 - i * 0.0, 0, 1);              // a convoy; the lead token arrives first
    if (u <= 0 || pos <= 0) return;
    const x = lerp(g.sieve + 6, g.fw - 8, ease(pos) * 0.4 + pos * 0.6);
    const y = g.cy + Math.sin(time * 2 + i) * (i % 2 ? 3 : -3) * (1 - pos);
    const col = x < g.t2 - 40 ? C.threat : x < g.t3 - 40 ? C.reason : C.ok;
    ctx.save(); ctx.shadowColor = col; ctx.shadowBlur = 7; ctx.fillStyle = col;
    ctx.beginPath(); ctx.arc(x, y, i === 0 ? 5.2 : 3.4, 0, Math.PI * 2); ctx.fill();
    ctx.shadowBlur = 0; ctx.globalAlpha = 0.35; ctx.fillRect(x - 38, y - 0.5, 38, 1);   // short trail
    ctx.restore();
  });
}

function drawLabels(g, p, a1, a2, a3, a4) {
  ctx.font = "500 10px 'IBM Plex Mono', ui-monospace, monospace"; ctx.textAlign = "center";
  const lab = (x, y, t, a, c) => { ctx.globalAlpha = a; ctx.fillStyle = c; ctx.fillText(t, x, y); };
  lab(g.sieve, H * 0.1, "TIER 1 · TRIAGE", a1, C.threat);
  lab(g.t2, H * 0.5 + 96, "TIER 2 · REASONING", a2, C.reason);
  lab(g.t3, H * 0.5 - 92, "TIER 3 · GUARDRAIL", a3, C.ok);
  lab(g.fw, H * 0.5 + H * 0.3 + 18, "FIREWALL", a4, C.ok);
  if (W > 700) lab(60, H * 0.1, "NETWORK TRAFFIC", 1, C.mute);
  // running counter at the sieve
  ctx.globalAlpha = a1; ctx.fillStyle = C.text; ctx.font = "600 13px 'IBM Plex Mono', ui-monospace, monospace";
  const left = a1 > 0.5 ? Math.round(lerp(facts.records, facts.alerts, ease((p - 0.2) / 0.2))) : facts.records;
  ctx.fillText(fmt(left), g.sieve, H * 0.1 + 20);
  ctx.globalAlpha = 1;
  if (p > 0.84) {                                                      // the rule types itself onto the wall
    const n = Math.floor(clamp((p - 0.86) / 0.1) * story.iptables.length);
    ctx.textAlign = "right"; ctx.fillStyle = C.ok; ctx.font = "500 12px 'IBM Plex Mono', ui-monospace, monospace";
    ctx.fillText(story.iptables.slice(0, n) + (Math.floor(performance.now() / 400) % 2 ? "▍" : ""), g.fw - 18, g.cy + H * 0.3 + 40);
  }
}

export function initScene({ canvas, progress, chapter, still = false }) {
  cv = canvas; ctx = cv.getContext("2d"); onChapter = chapter || (() => {});
  resize();
  addEventListener("resize", () => { resize(); if (still) draw(0.016, 0); });
  addEventListener("pointermove", (e) => { mouse.x = e.clientX / innerWidth; mouse.y = e.clientY / innerHeight; }, { passive: true });
  if (still) { prog = progS = 0.66; draw(0.016, 0.5); return { set() {} }; }
  const start = () => { if (running) return; running = true; last = performance.now(); raf = requestAnimationFrame(frame); };
  start();
  return { set(v) { prog = v; progress?.(v); } };
}
