// One store for everything the page shows. Sources: server-sent events (live) or the replay engine.
import { toast } from "./util.js";

const subs = new Set();
export const state = {
  mode: "live",                 // "live" | "replay"
  incidents: new Map(),
  stats: { flows_total: 0, alerts_total: 0, raw_bytes_total: 0, alert_bytes_total: 0, flows_per_s: 0, rule_hits: {}, top_sources: [] },
  history: [],                  // recent flows/s
  summary: null,
  results: null,
  stream: "connecting",
  lastEvent: null,
};
export const on = (fn) => { subs.add(fn); return () => subs.delete(fn); };
export const emit = (kind, payload) => { for (const fn of subs) fn(kind, payload); };

export function putIncident(inc, source = "live") {
  if (source !== state.mode) return;
  const isNew = !state.incidents.has(inc.incident_id);
  state.incidents.set(inc.incident_id, inc);
  emit(isNew ? "incident:new" : "incident:update", inc);
}
export function putStats(st, source = "live") {
  if (source !== state.mode) return;
  Object.assign(state.stats, st);
  state.history.push(st.flows_per_s ?? 0);
  if (state.history.length > 90) state.history.shift();
  emit("stats", state.stats);
}
export function setMode(mode, detail = "") {
  state.mode = mode;
  state.incidents.clear();
  state.history.length = 0;
  Object.assign(state.stats, { flows_total: 0, alerts_total: 0, raw_bytes_total: 0, alert_bytes_total: 0, flows_per_s: 0, rule_hits: {}, top_sources: [] });
  emit("mode", { mode, detail });
}

export async function api(path, opts) {
  const r = await fetch(path, opts);
  if (!r.ok) throw new Error(`${path}: ${r.status}`);
  return r.json();
}

export async function loadLive() {
  try {
    const [summary, incs] = await Promise.all([api("/api/summary"), api("/api/incidents?limit=50")]);
    state.summary = summary;
    if (summary.stats) Object.assign(state.stats, summary.stats);
    (summary.history || []).forEach((h) => state.history.push(h.flows_per_s ?? 0));
    emit("summary", summary);
    incs.reverse().forEach((i) => putIncident(i));
    emit("stats", state.stats);
  } catch (e) { /* server still starting */ }
}

export function connectStream() {
  const es = new EventSource("/api/stream");
  es.onopen = () => { state.stream = "live"; emit("stream", "live"); };
  es.onerror = () => { state.stream = "reconnecting"; emit("stream", "reconnecting"); };
  es.onmessage = (m) => {
    let msg; try { msg = JSON.parse(m.data); } catch { return; }
    state.lastEvent = Date.now();
    if (msg.kind === "incident") putIncident(msg.payload);
    else if (msg.kind === "stats") putStats(msg.payload);
    else if (msg.kind === "lab") emit("lab", msg.payload);
  };
  return es;
}

export async function approve(id) { return api(`/api/incidents/${id}/approve`, { method: "POST" }); }
export async function reject(id) { return api(`/api/incidents/${id}/reject`, { method: "POST" }); }
export async function launch(kind) {
  try { return await api(`/api/lab/attack/${kind}`, { method: "POST" }); }
  catch (e) { toast("Could not start the attack. Is Docker running and the lab up?"); throw e; }
}
