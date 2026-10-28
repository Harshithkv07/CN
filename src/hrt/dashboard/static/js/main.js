import { $, $$, esc, fmt, pct, bytes, countTo, reduced, toast, ICON } from "./util.js";
import { state, on, loadLive, connectStream, api, launch, setMode } from "./state.js";
import { initPipeline } from "./pipeline.js";
import { initIncidents } from "./incident.js";
import { renderEvidence, LIMITS } from "./evidence.js";
import { startReplay, stopReplay, isReplaying } from "./replay.js";
import { initScene, setFacts, setStory } from "./scene.js";

gsap.registerPlugin(ScrollTrigger);
const note = (t) => { $("#ctl-note").textContent = t || ""; };
const clamp = (v, a = 0, b = 1) => Math.min(b, Math.max(a, v));

// ---------------------------------------------------------------- live tiles + status
function spark() {
  const h = state.history.slice(-60), max = Math.max(...h, 1);
  $("#spark").innerHTML = h.length > 1 ? `<polyline points="${h.map((v, i) => `${(i / (h.length - 1)) * 160},${34 - (v / max) * 32}`).join(" ")}"/>` : "";
}
function tiles() {
  const s = state.stats, incs = [...state.incidents.values()];
  countTo($("#v-rate"), s.flows_per_s || 0, { d: 0, dur: 0.6 });
  countTo($("#v-flows"), s.flows_total || 0, { dur: 0.7 });
  countTo($("#v-alerts"), s.alerts_total || 0, { dur: 0.5 });
  const hits = Object.entries(s.rule_hits || {});
  $("#v-rules").textContent = hits.length ? hits.map(([k, v]) => `${k} ×${v}`).join(" · ") : "no rules fired yet";
  const raw = s.raw_bytes_total || 0, comp = s.alert_bytes_total || 0;
  $("#v-red").textContent = raw && comp ? pct(Math.floor(1e5 * (1 - comp / raw)) / 1e5, 3) : "–";
  $("#v-red-s").textContent = raw && comp ? `${bytes(raw)} → ${bytes(comp)}` : "raw bytes vs alert bytes";
  const by = (st) => incs.filter((i) => i.status === st).length;
  countTo($("#v-inc"), incs.length, { dur: 0.4 });
  $("#v-inc-s").textContent = incs.length ? `${by("DEPLOYED") + by("SAFE")} verified · ${by("ESCALATED")} escalated · ${incs.filter((i) => ["QUEUED", "ANALYZING"].includes(i.status)).length} in progress` : " ";
  spark();
  const hud = $("#hud-live");
  hud.textContent = s.flows_per_s > 0 ? `LIVE ${fmt(s.flows_per_s)}/s` : (state.mode === "replay" ? "REPLAY" : "");
}
function statusPill() {
  const el = $("#pill-stream"), sm = state.summary;
  if (state.mode === "replay") { el.className = "pill"; el.textContent = "replay"; return; }
  if (state.stream === "live") { el.className = "pill on"; el.textContent = sm ? `live · ${sm.rag ? "RAG" : "no RAG"} · ${sm.sandbox ? "sandbox" : "no sandbox"}` : "live"; }
  else { el.className = "pill off"; el.textContent = state.stream; }
}
on((kind, p) => {
  if (["stats", "incident:new", "incident:update", "mode"].includes(kind)) tiles();
  if (["stream", "summary", "mode"].includes(kind)) statusPill();
  if (kind === "mode") {
    $("#mode-tag").textContent = p.mode === "replay" ? "Replay" : "Live";
    $("#mode-tag").classList.toggle("replay", p.mode === "replay");
    $("#mode-detail").textContent = p.mode === "replay" ? p.detail : "waiting for traffic";
    $("#foot-mode").textContent = p.mode === "replay" ? "Showing a recorded run" : "Showing live data";
  }
  if (kind === "lab") note(p.state === "running" ? `Started ${p.kind}. An alert normally appears within 15 to 60 seconds, then the model needs about a minute.` : `${p.kind}: ${p.state}`);
  if (kind === "incident:new" && state.mode === "live") $("#mode-detail").textContent = `incident from ${p.alert.source_ip}`;
});

// ---------------------------------------------------------------- controls
$$("[data-attack]").forEach((b) => b.addEventListener("click", async () => {
  if (isReplaying()) { stopReplay(); setMode("live"); await loadLive(); }
  b.disabled = true;
  try { await launch(b.dataset.attack); note(`Launching ${b.dataset.attack} from the attacker container…`); } catch { note("The lab did not accept the attack. Start Docker and run `hrt lab up`."); }
  setTimeout(() => (b.disabled = false), 4000);
}));
$("#btn-replay").addEventListener("click", async () => {
  $("#btn-replay").disabled = true;
  const ok = await startReplay(note);
  if (ok) note("Replaying a recorded run (waiting times are compressed).");
  setTimeout(() => ($("#btn-replay").disabled = false), 1500);
});
$("#btn-reset").addEventListener("click", async () => {
  stopReplay();
  if (state.mode === "live") { try { await api("/api/reset", { method: "POST" }); } catch { /* offline */ } }
  setMode("live"); await loadLive();
  note("Cleared. The lab firewall is back to its baseline.");
});

// ---------------------------------------------------------------- micro-interactions
function cursorGlow() {
  const c = $("#cursor"); if (!c || reduced()) return;
  const qx = gsap.quickTo(c, "x", { duration: 0.6, ease: "power3.out" }), qy = gsap.quickTo(c, "y", { duration: 0.6, ease: "power3.out" });
  gsap.set(c, { x: -999, y: -999 });
  addEventListener("pointermove", (e) => { qx(e.clientX); qy(e.clientY); }, { passive: true });
}
function magnetic() {
  if (reduced() || matchMedia("(pointer: coarse)").matches) return;
  $$(".mag").forEach((b) => {
    const qx = gsap.quickTo(b, "x", { duration: 0.35, ease: "power3.out" }), qy = gsap.quickTo(b, "y", { duration: 0.35, ease: "power3.out" });
    b.addEventListener("pointermove", (e) => { const r = b.getBoundingClientRect(); qx((e.clientX - r.left - r.width / 2) * 0.22); qy((e.clientY - r.top - r.height / 2) * 0.3); });
    b.addEventListener("pointerleave", () => { qx(0); qy(0); });
  });
}
function revealSections() {
  if (reduced()) return;
  $$(".sec-head").forEach((el) => {
    gsap.from([...el.children], { opacity: 0, y: 36, duration: 0.8, stagger: 0.09, ease: "power3.out", scrollTrigger: { trigger: el, start: "top 85%", once: true } });
  });
  gsap.from(".tile", { opacity: 0, y: 24, duration: 0.6, stagger: 0.07, ease: "power3.out", scrollTrigger: { trigger: "#tiles", start: "top 90%", once: true } });
  gsap.from("#stage", { opacity: 0, y: 40, duration: 0.8, ease: "power3.out", scrollTrigger: { trigger: "#stage", start: "top 90%", once: true } });
}

// ---------------------------------------------------------------- the film
function film(all, recorded) {
  const t = all?.telemetry?.result, a = all?.agent?.result, g = all?.guardrail?.result;
  const facts = {};
  if (t) Object.assign(facts, { records: t.records, alerts: t.n_alerts, reduction: t.whole_log_reduction });
  if (a?.retrieval?.avg_search_space_reduction) facts.space = a.retrieval.avg_search_space_reduction;
  if (g) facts.cases = g.n_cases;
  setFacts(facts);
  const m = (k) => $(`[data-m="${k}"]`);
  if (t) { m("records").textContent = fmt(t.records); m("alerts").textContent = fmt(t.n_alerts); m("alerts-s").textContent = `alerts, ${pct(t.whole_log_reduction, 3)} smaller`; }
  if (facts.space) m("space").textContent = pct(facts.space, 0);
  if (g) $(`[data-m="cases"]`).nextElementSibling.textContent = `adversarial cases, ${(g.hrt_false_accepts || []).length} unsafe accepted`;

  const inc = recorded?.[0];
  if (inc) {
    setStory({
      ip: inc.alert.source_ip, rule: inc.alert.detector.rules[0],
      docs: (inc.retrieval?.docs || []).map((d) => ({ id: d.mitre_id, name: d.name, score: d.score })),
      iptables: inc.mitigation?.iptables_rule || undefined,
    });
  }

  const caps = $$(".cap"), intro = $("#intro");
  if (reduced()) {                                    // no pin, no scrubbing: a still frame and the chapters as a list
    initScene({ canvas: $("#cv"), still: true });
    $("#film").style.height = "70svh"; $("#caps").hidden = true; $(".film-hud").hidden = true;
    const list = $("#story-list");
    list.innerHTML = caps.map((c) => `<li>${c.innerHTML}</li>`).join(""); list.hidden = false;
    return;
  }
  gsap.set(caps, { autoAlpha: 0, y: 18 });
  gsap.from(".intro .w", { opacity: 0, y: 44, duration: 1, ease: "power4.out", stagger: 0.07, delay: 0.15 });
  gsap.from(".intro .eyebrow, .intro-sub, .scroll-cue", { opacity: 0, y: 16, duration: 0.8, ease: "power3.out", stagger: 0.12, delay: 0.7 });

  let shown = -1;
  const show = (i) => {
    if (i === shown) return;
    if (shown >= 0) { const o = caps[shown]; gsap.to(o, { autoAlpha: 0, y: -14, duration: 0.2, ease: "power2.in", overwrite: true }); o.classList.remove("on"); }
    if (i >= 0) { const n = caps[i]; gsap.fromTo(n, { autoAlpha: 0, y: 22 }, { autoAlpha: 1, y: 0, duration: 0.5, ease: "power3.out", delay: 0.12, overwrite: true }); n.classList.add("on"); }
    shown = i;
    $("#hud-ch").textContent = i < 0 ? "00 / 05" : `0${i + 1} / 05`;
  };
  let chapter = -1;
  const scene = initScene({ canvas: $("#cv"), chapter: (c) => { chapter = c; }, });
  ScrollTrigger.create({
    trigger: "#film", start: "top top", end: "+=520%", pin: true, scrub: true, anticipatePin: 1,
    onUpdate: (s) => {
      const p = s.progress;
      scene.set(p);
      gsap.set(intro, { opacity: 1 - clamp(p / 0.07), y: -p * 160 });
      $("#hud-fill").style.width = `${p * 100}%`;
      show(p < 0.08 ? -1 : chapter < 0 ? 0 : chapter);
    },
  });
}

// ---------------------------------------------------------------- boot
async function boot() {
  initPipeline();
  initIncidents();
  $("#limits-ul").innerHTML = LIMITS.map((t) => `<li>${ICON.warn}<span>${esc(t)}</span></li>`).join("");
  cursorGlow();
  const [all, rec] = await Promise.all([
    api("/api/results").catch(() => null),
    fetch("/static/data/recorded.json", { cache: "no-store" }).then((r) => r.json()).catch(() => null),
  ]);
  film(all, rec?.incidents);
  await loadLive();
  connectStream();
  tiles(); statusPill();
  $("#foot-mode").textContent = "Showing live data";
  renderEvidence(all);
  magnetic();
  revealSections();
  ScrollTrigger.refresh();
  // keep the in-page nav highlight honest
  $$(".links a").forEach((a) => {
    const target = $(a.getAttribute("href")); if (!target) return;
    ScrollTrigger.create({ trigger: target, start: "top 50%", end: "bottom 50%", onToggle: (s) => a.classList.toggle("on", s.isActive) });
  });
  if (new URLSearchParams(location.search).get("replay")) setTimeout(() => $("#btn-replay").click(), 900);
}
boot();
