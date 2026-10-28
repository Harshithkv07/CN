// Network traffic panel: flows/second chart, live flow ticker, top sources. Fed by the triage engine's stats
// (real Zeek records) or, in replay mode, by clearly labelled illustrative flows.
import { $, esc, fmt, pct, bytes, countTo } from "./util.js";
import { state, on } from "./state.js";

const C = { flow: "#6f747c", ok: "#d4af6a", threat: "#c8523d", grid: "rgba(255,255,255,.06)", text: "#857f74" };
let cv, ctx, W = 0, H = 0, dpr = 1;
const marks = [];                       // timestamps (ms) of alerts, drawn as vertical ticks

const incidentIps = () => new Set([...state.incidents.values()].map((i) => String(i.alert.source_ip)));

export function initTraffic() {
  cv = $("#chart"); ctx = cv.getContext("2d");
  const fit = () => {
    dpr = Math.min(devicePixelRatio || 1, 2);
    W = cv.clientWidth; H = cv.clientHeight;
    cv.width = W * dpr; cv.height = H * dpr; ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    draw();
  };
  new ResizeObserver(fit).observe(cv.parentElement);
  fit();
  on((kind, p) => {
    if (kind === "stats") { numbers(); draw(); ticker(); sources(); }
    if (kind === "incident:new") marks.push(Date.now());
    if (kind === "mode") { marks.length = 0; numbers(); draw(); ticker(); sources(); }
  });
  numbers(); ticker(); sources();
}

function numbers() {
  const s = state.stats;
  countTo($("#k-rate"), s.flows_per_s || 0, { dur: 0.5 });
  countTo($("#k-flows"), s.flows_total || 0, { dur: 0.6 });
  countTo($("#k-alerts"), s.alerts_total || 0, { dur: 0.4 });
  const raw = s.raw_bytes_total || 0, comp = s.alert_bytes_total || 0;
  $("#k-red").textContent = raw && comp ? pct(Math.floor(1e5 * (1 - comp / raw)) / 1e5, 3) : "–";
  $("#k-rate-w").classList.toggle("hot", (s.flows_per_s || 0) > 100);
  $("#trf-src").textContent = state.mode === "replay" ? "recorded run (traffic illustrative)" : "Zeek conn.log, live";
}

function draw() {
  if (!ctx || !W) return;
  ctx.clearRect(0, 0, W, H);
  const h = state.history.slice(-90), n = 90;
  const max = Math.max(20, ...h) * 1.15;
  const x = (i) => W - (h.length - 1 - i) * (W / (n - 1)), y = (v) => H - 14 - (v / max) * (H - 24);
  ctx.strokeStyle = C.grid; ctx.fillStyle = C.text; ctx.font = "10px 'IBM Plex Mono', monospace"; ctx.lineWidth = 1;
  for (let k = 0; k <= 3; k++) {
    const yy = 4 + ((H - 24) * k) / 3; ctx.beginPath(); ctx.moveTo(0, yy); ctx.lineTo(W, yy); ctx.stroke();
    ctx.fillText(fmt(max * (1 - k / 3)), 4, yy + 11);
  }
  ctx.fillText("90 s ago", 4, H - 2); ctx.textAlign = "right"; ctx.fillText("now", W - 4, H - 2); ctx.textAlign = "left";
  if (h.length < 2) return;
  const grd = ctx.createLinearGradient(0, 0, 0, H);
  grd.addColorStop(0, "rgba(212,175,106,.30)"); grd.addColorStop(1, "rgba(212,175,106,0)");
  ctx.beginPath(); ctx.moveTo(x(0), H - 14);
  h.forEach((v, i) => ctx.lineTo(x(i), y(v)));
  ctx.lineTo(x(h.length - 1), H - 14); ctx.closePath(); ctx.fillStyle = grd; ctx.fill();
  ctx.beginPath(); h.forEach((v, i) => (i ? ctx.lineTo(x(i), y(v)) : ctx.moveTo(x(i), y(v))));
  ctx.strokeStyle = C.ok; ctx.lineWidth = 2; ctx.lineJoin = "round"; ctx.stroke();
  const now = Date.now();
  marks.forEach((t) => {
    const age = Math.round((now - t) / 1000); if (age > 89) return;
    const xx = W - age * (W / (n - 1));
    ctx.strokeStyle = C.threat; ctx.lineWidth = 1; ctx.setLineDash([3, 4]); ctx.beginPath(); ctx.moveTo(xx, 2); ctx.lineTo(xx, H - 14); ctx.stroke(); ctx.setLineDash([]);
    ctx.fillStyle = C.threat; ctx.fillText("ALERT", Math.min(xx + 4, W - 40), 12);
  });
}

function ticker() {
  const flows = state.stats.recent_flows || [], bad = incidentIps();
  $("#tick-note").textContent = state.mode === "replay" ? "illustrative" : "";
  const ol = $("#ticker");
  if (!flows.length) { ol.innerHTML = `<li class="empty">waiting for flows…</li>`; return; }
  ol.innerHTML = flows.slice(-12).reverse().map((f) => `<li class="fl ${bad.has(f.src) ? "bad" : ""}"><span>${esc(f.src)} → ${esc(f.dst)}:${f.port}</span><i>${esc(f.proto)} ${esc(f.state || "")}</i></li>`).join("");
  if (window.gsap && ol.firstElementChild) gsap.from(ol.firstElementChild, { opacity: 0, x: -10, duration: 0.3 });
}

function sources() {
  const top = state.stats.top_sources || [], bad = incidentIps(), max = Math.max(1, ...top.map((t) => t.flows));
  $("#sources").innerHTML = top.length ? top.map((t) => `<li class="src ${bad.has(t.ip) ? "bad" : ""}"><span>${esc(t.ip)}</span><span>${fmt(t.flows)}</span><span class="bar2"><i style="width:${(t.flows / max) * 100}%"></i></span></li>`).join("") : `<li class="empty">no sources yet</li>`;
}
