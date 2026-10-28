"""Live Tier-1 loop: tail Zeek -> per-source sliding windows -> detector -> Alert -> webhook.

The sink is non-blocking. Alerts go onto an in-memory queue, and a background thread POSTs
them to the orchestrator, so telemetry ingestion never waits on LLM inference. That keeps
d_queue bounded (the nodal-delay argument).
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable

import httpx
import numpy as np

from hrt.models import Alert, DetectorOutput, Flow
from hrt.telemetry.zeek import ConnLogTailer
from hrt.triage.detector import WindowDetector
from hrt.triage.features import window_features
from hrt.triage.rules import BEACON_MAX_FWD_BYTES, BEACON_MAX_GAP_RATIO, BEACON_MIN_FLOWS, beaconing_long

log = logging.getLogger("hrt.triage")


class WebhookSink:
    """Queue alerts and deliver them from a background thread (fire-and-forget, with retries)."""

    def __init__(self, url: str, stats_url: str | None = None, timeout: float = 5.0):
        self.url, self.stats_url, self.timeout = url, stats_url, timeout
        self.q: queue.Queue = queue.Queue()
        self.sent = self.failed = 0
        threading.Thread(target=self._run, name="webhook-sink", daemon=True).start()

    def __call__(self, alert: Alert) -> None:
        self.q.put(("alert", alert.model_dump(mode="json")))

    def stats(self, payload: dict) -> None:
        if self.stats_url:
            self.q.put(("stats", payload))

    def _run(self) -> None:
        with httpx.Client(timeout=self.timeout) as client:
            while True:
                kind, body = self.q.get()
                url = self.url if kind == "alert" else self.stats_url
                for attempt in range(3):
                    try:
                        client.post(url, json=body).raise_for_status()
                        self.sent += kind == "alert"
                        break
                    except httpx.HTTPError as exc:
                        if attempt == 2:
                            self.failed += kind == "alert"
                            log.warning("webhook delivery failed (%s): %s", kind, exc)
                        time.sleep(0.5 * (attempt + 1))


class TriageEngine:
    def __init__(self, detector: WindowDetector, sink: Callable[[Alert], None], window_seconds: float = 10.0,
                 cooldown_seconds: float = 120.0, origin: str = "zeek", use_rules: bool = True, use_ml: bool = True,
                 beacon_window_seconds: float = 900.0):
        self.detector, self.sink = detector, sink
        self.window, self.cooldown = window_seconds, cooldown_seconds
        self.origin, self.use_rules, self.use_ml = origin, use_rules, use_ml
        self.flows: dict[str, deque[Flow]] = defaultdict(deque)
        self.dirty: set[str] = set()
        self.last_alert: dict[str | tuple[str, str], float] = {}
        self.watermark = 0.0
        self.flows_total = self.alerts_total = self.alert_bytes = 0
        self.raw_bytes_total = 0
        # C2 beaconing needs minutes of history, not the 10 s window. Keep only tiny connections, per
        # (source, destination, port), capped in length, so a flood cannot blow up memory.
        self.beacon_window = beacon_window_seconds
        self.beacons: dict[tuple[str, str, int], deque[Flow]] = defaultdict(lambda: deque(maxlen=64))
        self.beacon_dirty: set[tuple[str, str, int]] = set()
        self._last_beacon_gc = 0.0
        self._rate_t, self._rate_n = time.time(), 0
        self.recent: deque = deque(maxlen=14)           # last flows seen, for the live ticker
        self.rule_hits: dict[str, int] = defaultdict(int)

    def ingest(self, flows: list[Flow], raw_bytes: int = 0) -> None:
        for f in flows[-14:]:
            self.recent.append((f.ts, f.src_ip, f.dst_ip, f.dst_port, f.proto, f.conn_state))
        for f in flows:
            self.flows[f.src_ip].append(f)
            self.dirty.add(f.src_ip)
            if f.ts > self.watermark:
                self.watermark = f.ts
            if self.beacon_window and f.fwd_bytes <= BEACON_MAX_FWD_BYTES and f.proto in ("tcp", "udp"):
                key = (f.src_ip, f.dst_ip, f.dst_port)
                self.beacons[key].append(f)
                self.beacon_dirty.add(key)
        self.flows_total += len(flows)
        self.raw_bytes_total += raw_bytes

    @property
    def avg_record_bytes(self) -> float:
        return self.raw_bytes_total / self.flows_total if self.flows_total else 0.0

    def evaluate(self) -> list[Alert]:
        lo = self.watermark - self.window
        emitted: list[Alert] = []
        for src in list(self.dirty):
            dq = self.flows[src]
            while dq and dq[0].ts < lo - self.window:  # prune history we no longer need
                dq.popleft()
            window = [f for f in dq if f.ts >= lo]
            if not window:
                continue
            feats = window_features(window, self.window)
            out = self.detector.detect(feats, self.use_rules, self.use_ml)
            if not (out.rules or out.ml_anomaly):
                continue
            last = self.last_alert.get(src)
            if last is not None and self.watermark - last < self.cooldown:
                continue
            try:
                alert = Alert(
                    source_ip=src,
                    dst_ips=sorted({f.dst_ip for f in window})[:5],
                    first_seen=min(f.ts for f in window),
                    last_seen=max(f.ts for f in window),
                    detector=out,
                    features=feats,
                    raw_flow_count=len(window),
                    raw_bytes=int(len(window) * self.avg_record_bytes),
                    origin=self.origin,
                )
            except ValueError:  # non-IPv4 / malformed address never leaves Tier 1
                continue
            self.last_alert[src] = self.watermark
            for r in out.rules:
                self.rule_hits[r] += 1
            self.alerts_total += 1
            self.alert_bytes += len(alert.model_dump_json())
            self.sink(alert)
            emitted.append(alert)
        self.dirty.clear()
        emitted.extend(self._evaluate_beacons())
        return emitted

    def _evaluate_beacons(self) -> list[Alert]:
        if not self.beacon_window:
            return []
        lo = self.watermark - self.beacon_window
        emitted: list[Alert] = []
        for key in list(self.beacon_dirty):
            dq = self.beacons[key]
            while dq and dq[0].ts < lo:
                dq.popleft()
            if len(dq) < BEACON_MIN_FLOWS:
                continue
            window = list(dq)
            feats = window_features(window, self.beacon_window)
            if not beaconing_long(feats):
                continue
            gaps = np.diff([f.ts for f in window])
            if gaps.min() <= 0 or gaps.max() / gaps.min() > BEACON_MAX_GAP_RATIO:
                continue                      # an outlier gap: not a metronome
            src = key[0]
            last = self.last_alert.get((src, "BEACONING"))
            # one alert per implant per 5 minutes: a beacon keeps checking in, and each alert costs an LLM call
            if last is not None and self.watermark - last < max(self.cooldown, 300.0):
                continue
            try:
                alert = Alert(
                    source_ip=src, dst_ips=[key[1]], first_seen=window[0].ts, last_seen=window[-1].ts,
                    detector=DetectorOutput(rules=["BEACONING"]), features=feats, raw_flow_count=len(window),
                    raw_bytes=int(len(window) * self.avg_record_bytes), origin=self.origin)
            except ValueError:
                continue
            self.last_alert[(src, "BEACONING")] = self.watermark
            self.rule_hits["BEACONING"] += 1
            self.alerts_total += 1
            self.alert_bytes += len(alert.model_dump_json())
            self.sink(alert)
            emitted.append(alert)
        self.beacon_dirty.clear()
        if self.watermark - self._last_beacon_gc > self.beacon_window:   # drop keys that went quiet
            self._last_beacon_gc = self.watermark
            for key in [k for k, d in self.beacons.items() if not d or d[-1].ts < lo]:
                del self.beacons[key]
        return emitted

    def stats(self) -> dict:
        now = time.time()
        rate = (self.flows_total - self._rate_n) / max(now - self._rate_t, 1e-6)
        self._rate_t, self._rate_n = now, self.flows_total
        top = sorted(((s, len(d)) for s, d in self.flows.items() if d), key=lambda x: -x[1])[:5]
        return {
            "flows_per_s": round(rate, 1),
            "top_sources": [{"ip": s, "flows": n} for s, n in top],
            "recent_flows": [{"t": round(t, 2), "src": a, "dst": b, "port": p, "proto": pr, "state": st}
                             for t, a, b, p, pr, st in list(self.recent)[-10:]],
            "rule_hits": dict(self.rule_hits),
            "ts": now,
            "flows_total": self.flows_total,
            "alerts_total": self.alerts_total,
            "raw_bytes_total": self.raw_bytes_total,
            "alert_bytes_total": self.alert_bytes,
            "sources_tracked": len(self.flows),
            "watermark": self.watermark,
            "ml_enabled": self.detector.model is not None,
        }

    def replay(self, flows: list[Flow], step: float | None = None) -> list[Alert]:
        """Offline replay: step the watermark through the capture in time order, evaluating each
        window as the live loop would. Without this, a one-shot evaluate() only sees the final
        window and misses earlier bursts."""
        if not flows:
            return []
        step = step or self.window / 2
        ordered = sorted(flows, key=lambda f: f.ts)
        emitted: list[Alert] = []
        i, n = 0, len(ordered)
        t = ordered[0].ts + self.window
        end = ordered[-1].ts
        while t <= end + step:
            batch = []
            while i < n and ordered[i].ts <= t:
                batch.append(ordered[i])
                i += 1
            if batch:
                self.ingest(batch)
                emitted.extend(self.evaluate())
            t += step
        if i < n:  # flush any remainder
            self.ingest(ordered[i:])
            emitted.extend(self.evaluate())
        return emitted

    def run(self, tailer: ConnLogTailer, poll_seconds: float = 1.0, stop: threading.Event | None = None,
            stats_cb: Callable[[dict], None] | None = None, stats_every: float = 5.0) -> None:
        last_stats = 0.0
        while not (stop and stop.is_set()):
            before = tailer.bytes_read
            flows = tailer.poll()
            if flows:
                self.ingest(flows, tailer.bytes_read - before)
                for alert in self.evaluate():
                    log.info("ALERT %s rules=%s ml=%s flows=%d", alert.source_ip, alert.detector.rules,
                             alert.detector.ml_anomaly, alert.raw_flow_count)
            if stats_cb and time.time() - last_stats >= stats_every:
                stats_cb(self.stats())
                last_stats = time.time()
            time.sleep(poll_seconds)
