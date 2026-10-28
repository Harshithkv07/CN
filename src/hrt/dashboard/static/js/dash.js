import { $, $$, toast, reduced } from "./util.js";
import { state, on, loadLive, connectStream, api, launch, setMode } from "./state.js";
import { initTraffic } from "./traffic.js";
import { initLane } from "./lane.js";
import { initPanel, log } from "./panel.js";
import { startReplay, stopReplay, isReplaying } from "./replay.js";

function mode() {
  const el = $("#mode"), sm = state.summary;
  if (state.mode === "replay") { el.className = "mode replay"; el.textContent = "replay · recorded"; return; }
  if (state.stream === "live") { el.className = "mode live"; el.textContent = `live${sm ? (sm.sandbox ? " · sandbox on" : " · sandbox off") : ""}`; }
  else { el.className = "mode"; el.textContent = state.stream; }
}
on((kind) => { if (["mode", "summary", "stream"].includes(kind)) mode(); });

setInterval(() => { $("#clock").textContent = new Date().toLocaleTimeString("en-GB"); }, 1000);

$$("[data-attack]").forEach((b) => b.addEventListener("click", async () => {
  if (isReplaying()) { stopReplay(); setMode("live"); await loadLive(); }
  b.disabled = true;
  try { await launch(b.dataset.attack); log(`Launched ${b.dataset.attack} from the attacker container`); } catch { toast("The lab did not accept the attack. Is Docker running?"); }
  setTimeout(() => (b.disabled = false), 4000);
}));
$("#btn-replay").addEventListener("click", async () => { const ok = await startReplay(toast); if (ok) log("Replaying a recorded run"); });
$("#btn-reset").addEventListener("click", async () => {
  stopReplay();
  if (state.mode === "live") { try { await api("/api/reset", { method: "POST" }); } catch { /* offline */ } }
  setMode("live"); await loadLive();
});

async function boot() {
  initTraffic(); initLane(); initPanel();
  await loadLive();
  connectStream();
  mode();
  if (new URLSearchParams(location.search).get("replay")) setTimeout(() => $("#btn-replay").click(), 800);
}
boot();
