// Small helpers shared by every module. No dependencies.
export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
export const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
export const fmt = (n, d = 0) => (n == null || Number.isNaN(n) ? "–" : Number(n).toLocaleString("en-US", { maximumFractionDigits: d, minimumFractionDigits: d }));
export const pct = (x, d = 1) => (x == null ? "–" : `${(x * 100).toFixed(d)}%`);
export const bytes = (n) => {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB"]; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
};
export const secs = (s) => (s == null ? "–" : s < 1 ? `${Math.round(s * 1000)} ms` : s < 120 ? `${s.toFixed(1)} s` : `${Math.floor(s / 60)} m ${Math.round(s % 60)} s`);
export const reduced = () => window.matchMedia("(prefers-reduced-motion: reduce)").matches;
export const html = (strings, ...vals) => strings.reduce((a, s, i) => a + s + (vals[i] ?? ""), "");

export const ICON = {
  check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg>',
  cross: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" aria-hidden="true"><path d="M6 6l12 12M18 6L6 18"/></svg>',
  loop: '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 12a9 9 0 0115.5-6.2L21 8M21 3v5h-5M21 12a9 9 0 01-15.5 6.2L3 16M3 21v-5h5"/></svg>',
  warn: '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l10 18H2zM12 10v5M12 18.5v.01"/></svg>',
};

let toastTimer;
export function toast(msg) {
  const el = $("#toast");
  el.textContent = msg;
  gsap.killTweensOf(el);
  gsap.to(el, { autoAlpha: 1, y: 0, duration: 0.25, ease: "power2.out" });
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => gsap.to(el, { autoAlpha: 0, y: 20, duration: 0.2 }), 3200);
}

export function countTo(el, to, { d = 0, dur = 0.9, suffix = "", fmtFn } = {}) {
  const from = Number(el.dataset.v ?? 0);
  el.dataset.v = to;
  if (reduced() || from === to) { el.textContent = (fmtFn ? fmtFn(to) : fmt(to, d)) + suffix; return; }
  const o = { v: from };
  gsap.to(o, { v: to, duration: dur, ease: "power2.out", overwrite: true, onUpdate: () => { el.textContent = (fmtFn ? fmtFn(o.v) : fmt(o.v, d)) + suffix; } });
}

// Human text for each Tier-1 rule (mirrors triage/rules.py)
export const RULE_TEXT = {
  PORT_SCAN: "many distinct ports probed, mostly half-open or rejected",
  HOST_SWEEP: "the same port probed across many hosts",
  SYN_FLOOD: "very high SYN/ACK half-open ratio on few ports",
  CONN_FLOOD: "very high connection rate against one service",
  UDP_FLOOD: "high-rate UDP from one source",
  BRUTE_FORCE: "repeated short sessions against a login service",
  SLOW_DOS: "many long-lived, low-throughput web sessions",
  BEACONING: "periodic small connections to one host and port",
  EXFILTRATION: "unusually large outbound transfer",
};
export const STATUS = {
  QUEUED: ["Queued", ""], ANALYZING: ["Analysing", "t2"], SAFE: ["Verified · awaiting approval", "ok"],
  DEPLOYED: ["Deployed", "ok"], ESCALATED: ["Escalated to analyst", "warn"], REJECTED: ["Rejected by analyst", "bad"],
  DUPLICATE: ["Already blocked", ""], ERROR: ["Error", "bad"],
};
