// Tiny SVG chart helpers. Each returns an HTML string with a viewBox so charts scale with the card.
import { esc } from "./util.js";

const W = 560;

export function key(items) {
  return `<div class="key">${items.map(([n, c]) => `<span><i style="background:${c}"></i>${esc(n)}</span>`).join("")}</div>`;
}

/** groups: [{label, values:[...]}]; series: [{name,color}]; values are 0..max */
export function groupedBars({ groups, series, max = 1, h = 230, fmtV = (v) => (v * 100).toFixed(0) + "%", label = "Bar chart" }) {
  const pad = { l: 34, r: 8, t: 14, b: 44 }, iw = W - pad.l - pad.r, ih = h - pad.t - pad.b;
  const gw = iw / groups.length, bw = Math.min(30, (gw - 14) / series.length);
  let out = `<svg class="chart" viewBox="0 0 ${W} ${h}" role="img" aria-label="${esc(label)}">`;
  for (let i = 0; i <= 4; i++) {
    const y = pad.t + ih - (ih * i) / 4;
    out += `<line class="gridl" x1="${pad.l}" x2="${W - pad.r}" y1="${y}" y2="${y}"/><text x="${pad.l - 6}" y="${y + 4}" text-anchor="end">${fmtV((max * i) / 4)}</text>`;
  }
  groups.forEach((g, gi) => {
    const x0 = pad.l + gi * gw + (gw - bw * series.length) / 2;
    g.values.forEach((v, si) => {
      if (v == null) return;
      const bh = Math.max(0, Math.min(1, v / max)) * ih;
      out += `<rect x="${x0 + si * bw}" y="${pad.t + ih - bh}" width="${bw - 3}" height="${bh}" rx="3" fill="${series[si].color}"><title>${esc(g.label)} · ${esc(series[si].name)}: ${fmtV(v)}</title></rect>`;
      if (bh > 16 && bw > 20) out += `<text class="val" x="${x0 + si * bw + (bw - 3) / 2}" y="${pad.t + ih - bh - 4}" text-anchor="middle">${fmtV(v)}</text>`;
    });
    const words = g.label.split("\n");
    words.forEach((w, k) => (out += `<text x="${pad.l + gi * gw + gw / 2}" y="${h - 26 + k * 13}" text-anchor="middle">${esc(w)}</text>`));
  });
  return out + `</svg>`;
}

/** rows: [{label, value, color, text}] horizontal bars */
export function hbars({ rows, max, h, ref, label = "Bar chart" }) {
  const rh = 30, H = h || rows.length * rh + 22, lw = 150, iw = W - lw - 70;
  const m = max || Math.max(...rows.map((r) => r.value), 1e-9);
  let out = `<svg class="chart" viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(label)}">`;
  rows.forEach((r, i) => {
    const y = 8 + i * rh, bw = Math.max(2, (r.value / m) * iw);
    out += `<text x="${lw - 8}" y="${y + 15}" text-anchor="end">${esc(r.label)}</text><rect x="${lw}" y="${y + 3}" width="${iw}" height="14" rx="7" fill="var(--surface-3)"/><rect x="${lw}" y="${y + 3}" width="${bw}" height="14" rx="7" fill="${r.color || "var(--t1)"}"><title>${esc(r.label)}: ${esc(r.text ?? r.value)}</title></rect><text class="val" x="${lw + iw + 8}" y="${y + 15}">${esc(r.text ?? r.value)}</text>`;
  });
  if (ref) {
    const x = lw + (ref.value / m) * iw;
    out += `<line x1="${x}" x2="${x}" y1="2" y2="${H - 14}" stroke="var(--warn)" stroke-dasharray="4 4"/><text x="${x}" y="${H - 2}" text-anchor="middle" style="fill:var(--warn)">${esc(ref.label)}</text>`;
  }
  return out + `</svg>`;
}

/** series: [{name,color,points:[[x,y]...]}]; log-free; ticks given */
export function lines({ series, xTicks, yMax, h = 230, fmtY = (v) => v, xLabel = "", label = "Line chart" }) {
  const pad = { l: 46, r: 16, t: 14, b: 40 }, iw = W - pad.l - pad.r, ih = h - pad.t - pad.b;
  const xs = xTicks, x = (v) => pad.l + ((v - xs[0]) / (xs.at(-1) - xs[0])) * iw, y = (v) => pad.t + ih - (v / yMax) * ih;
  let out = `<svg class="chart" viewBox="0 0 ${W} ${h}" role="img" aria-label="${esc(label)}">`;
  for (let i = 0; i <= 4; i++) {
    const v = (yMax * i) / 4;
    out += `<line class="gridl" x1="${pad.l}" x2="${W - pad.r}" y1="${y(v)}" y2="${y(v)}"/><text x="${pad.l - 6}" y="${y(v) + 4}" text-anchor="end">${fmtY(v)}</text>`;
  }
  xs.forEach((t) => (out += `<text x="${x(t)}" y="${h - 20}" text-anchor="middle">${t}</text>`));
  out += `<text x="${pad.l + iw / 2}" y="${h - 4}" text-anchor="middle">${esc(xLabel)}</text>`;
  series.forEach((s) => {
    const d = s.points.map(([px, py], i) => `${i ? "L" : "M"}${x(px)},${y(py)}`).join(" ");
    out += `<path d="${d}" fill="none" stroke="${s.color}" stroke-width="2.4" stroke-linejoin="round" stroke-linecap="round"/>` +
      s.points.map(([px, py]) => `<circle cx="${x(px)}" cy="${y(py)}" r="3.6" fill="${s.color}"><title>${esc(s.name)}: ${fmtY(py)} at ${px}</title></circle>`).join("");
  });
  return out + `</svg>`;
}

/** rows x cols of 0..1 values to a heat grid (HTML) */
export function heat({ rowLabels, colLabels, values, text, colorFor }) {
  const col = colorFor || ((v) => `color-mix(in srgb, var(--t3) ${Math.round(v * 100)}%, var(--surface-3))`);
  let out = `<div class="heat" role="table"><div class="heat-row"><span></span>${colLabels.map((c) => `<span class="heat-h">${esc(c)}</span>`).join("")}</div>`;
  rowLabels.forEach((r, i) => {
    out += `<div class="heat-row" role="row"><span class="heat-h" style="text-align:right;padding-right:6px">${esc(r)}</span>` +
      values[i].map((v, j) => `<span class="heat-c" role="cell" style="background:${col(v)};${v < 0.45 ? "color:var(--text-2)" : ""}" title="${esc(text?.[i]?.[j] ?? "")}">${esc(text?.[i]?.[j] ?? (v * 100).toFixed(0) + "%")}</span>`).join("") + `</div>`;
  });
  return out + `</div>`;
}

export const table = (head, rows, numCols = []) =>
  `<div class="tbl-wrap"><table class="tbl"><thead><tr>${head.map((h) => `<th>${esc(h)}</th>`).join("")}</tr></thead><tbody>${rows.map((r) => `<tr>${r.map((c, i) => `<td class="${numCols.includes(i) ? "num" : ""}">${c}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
