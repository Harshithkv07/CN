// Replay of recorded runs: real incident records captured from the live lab, shown step by step with the
// waiting time compressed. Used when the lab, Docker or the model is not running during a demo.
import { state, setMode, putIncident, putStats, emit } from "./state.js";

let timers = [], running = false;
const later = (ms, fn) => timers.push(setTimeout(fn, ms));
export const isReplaying = () => running;

export function stopReplay() { timers.forEach(clearTimeout); timers = []; running = false; }

const clone = (o) => JSON.parse(JSON.stringify(o));

/** Progressive versions of one finished incident, with the real timestamps compressed into ~`budget` seconds. */
export function frames(full, budget = 20) {
  const t = full.times || {}, marks = Object.entries(t).sort((a, b) => a[1] - b[1]);
  const t0 = marks[0]?.[1] ?? 0, total = Math.max((marks.at(-1)?.[1] ?? t0) - t0, 0.001);
  const k = Math.min(1, budget / total);
  const at = (name) => Math.max(0, ((t[name] ?? t0) - t0) * k);
  const out = [];
  const base = clone(full);
  Object.assign(base, { status: "QUEUED", retrieval: null, attempts: [], mitigation: null, verdict: null, grounded: null, escalation_reason: null, snort_rule: null, snort_check: null, deploy_output: null, times: { queued: t0 } });
  out.push({ s: 0, inc: base });
  const step = (s, patch, mark) => {
    const prev = out.at(-1);
    const inc = clone(prev.inc);
    Object.assign(inc, patch(inc));
    if (mark) inc.times[mark] = t[mark] ?? t0;
    out.push({ s: Math.max(s, prev.s + 1.1), inc });
  };
  if (t.analysis_started) step(at("analysis_started"), () => ({ status: "ANALYZING" }), "analysis_started");
  if (full.retrieval) step(at("retrieved"), () => ({ retrieval: clone(full.retrieval) }), "retrieved");
  full.attempts.forEach((a, i) => {
    const copy = clone(a);
    step(at(`llm_${i + 1}`) || out.at(-1).s + 2, (inc) => ({ attempts: [...inc.attempts, copy], mitigation: copy.mitigation }), `llm_${i + 1}`);
  });
  const final = (extra = {}) => step(at("verified") || at("finished"), () => ({ verdict: full.verdict, grounded: full.grounded, mitigation: full.mitigation, snort_rule: full.snort_rule, snort_source: full.snort_source, snort_check: full.snort_check, escalation_reason: full.escalation_reason, status: full.status === "DEPLOYED" ? "SAFE" : full.status, ...extra }), "verified");
  final();
  if (full.status === "DEPLOYED") step(out.at(-1).s + 3, () => ({ status: "DEPLOYED", deploy_output: full.deploy_output }), "deployed");
  const last = out.at(-1).inc;
  last.times = { ...full.times };               // the finished record keeps its real timings for the waterfall
  return out;
}

const BENIGN = "10.10.0.50";
/** Illustrative ticker rows for a replay (the recording holds the incident, not the raw flows). */
function synth(f, attack, n = 10) {
  const dst = String(f.alert.dst_ips?.[0] || "10.10.0.10"), ip = String(f.alert.source_ip), ports = f.alert.features.top_dst_ports?.length ? f.alert.features.top_dst_ports : [80];
  const now = Date.now() / 1000;
  return Array.from({ length: n }, (_, i) => attack && i % 4 !== 3
    ? { t: now, src: ip, dst, port: ports[(i * 7 + Math.floor(now)) % ports.length] + (f.alert.detector.rules[0] === "PORT_SCAN" ? (i * 37) % 900 : 0), proto: "tcp", state: f.alert.detector.rules[0] === "BEACONING" ? "SF" : "S0" }
    : { t: now, src: BENIGN, dst, port: 80, proto: "tcp", state: "SF" });
}

export async function startReplay(onNote = () => {}, { budget = 20 } = {}) {
  stopReplay();
  let data;
  try { data = await (await fetch("/static/data/recorded.json", { cache: "no-store" })).json(); } catch { data = []; }
  const runs = (data.incidents || data || []).filter((i) => i && i.alert);
  if (!runs.length) { onNote("No recorded run is bundled yet. Run an attack on the live lab first, then export one."); return false; }
  setMode("replay", "recorded run");
  running = true;
  emit("mode", { mode: "replay", detail: `${runs.length} recorded incident${runs.length > 1 ? "s" : ""} from the live lab` });
  let offset = 0.5;
  runs.slice(0, 2).forEach((full, n) => {
    const f = clone(full);
    f.incident_id = `rec-${n}-${full.incident_id}`;
    const fr = frames(f, budget);
    const ip = String(f.alert.source_ip), peak = Math.min(Math.max(f.alert.features.flows_per_s || 40, 20), 400), flows = f.alert.raw_flow_count || 1000;
    let seen = 0;
    const tick = (at, rate, attack) => later(at * 1000, () => {
      seen += Math.round(rate);
      putStats({ flows_per_s: rate, flows_total: state.stats.flows_total + Math.round(rate), raw_bytes_total: state.stats.raw_bytes_total + Math.round(rate * 380),
        top_sources: [...(attack ? [{ ip, flows: seen }] : []), { ip: BENIGN, flows: 40 + (seen % 7) }], recent_flows: synth(f, attack), ts: Date.now() / 1000 }, "replay");
    });
    for (let i = 0; i < 5; i++) tick(offset + i * 0.8, 6 + (i % 3), false);          // quiet baseline
    offset += 4.2;
    for (let i = 0; i < 8; i++) tick(offset + i * 0.5, Math.round(peak * (i + 1) / 8), true);   // the attack ramps up
    offset += 4.4;
    fr.forEach((frame, i) => later((offset + frame.s) * 1000, () => {
      if (i === 0) putStats({ alerts_total: state.stats.alerts_total + 1, alert_bytes_total: state.stats.alert_bytes_total + JSON.stringify(f.alert).length, rule_hits: Object.fromEntries(f.alert.detector.rules.map((r) => [r, 1])), raw_bytes_total: state.stats.raw_bytes_total + (f.alert.raw_bytes || flows * 380) }, "replay");
      putIncident(frame.inc, "replay");
    }));
    const end = offset + fr.at(-1).s;
    for (let k = 0; k < 4; k++) tick(end + 0.4 + k * 0.8, 6 + k, false);
    offset = end + 4;
  });
  later((offset + 0.5) * 1000, () => { running = false; onNote("Replay finished."); });
  return true;
}
