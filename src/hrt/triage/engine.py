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

from hrt.models import Alert, Flow
from hrt.telemetry.zeek import ConnLogTailer
from hrt.triage.detector import WindowDetector
from hrt.triage.features import window_features

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
                 cooldown_seconds: float = 120.0, origin: str = "zeek", use_rules: bool = True, use_ml: bool = True):
        self.detector, self.sink = detector, sink
        self.window, self.cooldown = window_seconds, cooldown_seconds
        self.origin, self.use_rules, self.use_ml = origin, use_rules, use_ml
        self.flows: dict[str, deque[Flow]] = defaultdict(deque)
        self.dirty: set[str] = set()
        self.last_alert: dict[str, float] = {}
        self.watermark = 0.0
        self.flows_total = self.alerts_total = self.alert_bytes = 0
        self.raw_bytes_total = 0

    def ingest(self, flows: list[Flow], raw_bytes: int = 0) -> None:
        for f in flows:
            self.flows[f.src_ip].append(f)
            self.dirty.add(f.src_ip)
            if f.ts > self.watermark:
                self.watermark = f.ts
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
            self.alerts_total += 1
            self.alert_bytes += len(alert.model_dump_json())
            self.sink(alert)
            emitted.append(alert)
        self.dirty.clear()
        return emitted

    def stats(self) -> dict:
        return {
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
