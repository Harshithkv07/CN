"""FastAPI orchestrator.

POST /webhook/alert accepts a Tier-1 alert and returns immediately after enqueuing it. A pool of
worker threads runs the analyst pipeline (retrieval + local LLM + guardrail), so ingestion is
decoupled from inference latency. Progress is streamed to the dashboard over SSE, and verified
rules wait for analyst approval unless auto-deploy is on.
"""

from __future__ import annotations

import asyncio
import json
import logging
import queue
import threading
from collections import deque
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from hrt.agent.analyst import AnalystAgent
from hrt.config import Settings, get_settings
from hrt.guardrail.deploy import LabFirewall
from hrt.guardrail.pipeline import Guardrail
from hrt.guardrail.sandbox import KernelSandbox
from hrt.llm import make_llm
from hrt.models import Alert, Incident, Status
from hrt.orchestrator.events import EventHub
from hrt.orchestrator.store import IncidentStore
from hrt.rag.retriever import Retriever

log = logging.getLogger("hrt.orchestrator")
STATIC_DIR = __import__("pathlib").Path(__file__).resolve().parent.parent / "dashboard" / "static"


class Orchestrator:
    def __init__(self, settings: Settings, workers: int = 2, auto_deploy: bool | None = None):
        self.settings = settings
        self.store = IncidentStore(settings.db_path)
        self.hub = EventHub()
        self.q: queue.Queue[Incident] = queue.Queue()
        self.workers = workers
        self.auto_deploy = settings.auto_deploy if auto_deploy is None else auto_deploy
        self._threads: list[threading.Thread] = []
        self._stop = threading.Event()
        self.sandbox = KernelSandbox(settings)
        self.firewall = LabFirewall(settings)
        self._sandbox_ok = self.sandbox.available()
        self.guardrail = Guardrail(settings, self.sandbox if self._sandbox_ok else None, self.store.deployed_rules)
        self.retriever: Retriever | None = None
        self.stats = {"flows_total": 0, "alerts_total": 0, "raw_bytes_total": 0, "alert_bytes_total": 0}
        self.history: deque = deque(maxlen=180)      # recent stats points, so a page opened late has a sparkline
        self.lab_jobs: list[dict] = []

    def _lazy_retriever(self) -> Retriever | None:
        if self.retriever is None and self.settings.chroma_dir.exists():
            try:
                self.retriever = Retriever(self.settings)
            except Exception as exc:
                log.warning("retriever unavailable: %s", exc)
        return self.retriever

    def start(self) -> None:
        for i in range(self.workers):
            t = threading.Thread(target=self._worker, name=f"analyst-{i}", daemon=True)
            t.start()
            self._threads.append(t)

    def stop(self) -> None:
        self._stop.set()

    def submit(self, alert: Alert) -> Incident:
        inc = Incident(alert=alert)
        inc.mark("queued")
        self.store.upsert(inc)
        self.hub.publish("incident", inc.model_dump(mode="json"))
        self.q.put(inc)
        return inc

    def _publish(self, inc: Incident) -> None:
        self.store.upsert(inc)
        self.hub.publish("incident", inc.model_dump(mode="json"))

    def _worker(self) -> None:
        llm = make_llm(self.settings)
        agent = AnalystAgent(llm, self.guardrail, self._lazy_retriever(), use_rag=True,
                             top_k=self.settings.retrieval_top_k, max_attempts=self.settings.max_attempts,
                             on_update=self._publish)
        while not self._stop.is_set():
            try:
                inc = self.q.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                agent.retriever = self._lazy_retriever()
                agent.use_rag = agent.retriever is not None
                agent.analyze(inc.alert, inc)
                if inc.status == Status.SAFE and self.auto_deploy:
                    self.deploy(inc.incident_id)
            except Exception as exc:
                log.exception("worker error")
                inc.status, inc.escalation_reason = Status.ERROR, str(exc)
                self._publish(inc)

    def deploy(self, incident_id: str) -> Incident:
        inc = self.store.get(incident_id)
        if inc is None:
            raise KeyError(incident_id)
        if inc.status not in (Status.SAFE,):
            return inc
        ok, out = (True, "auto-deploy disabled (dry run)")
        if self._sandbox_ok and inc.verdict:
            try:
                ok, out = self.firewall.apply(inc.verdict.argv)
            except Exception as exc:
                ok, out = False, str(exc)
        inc.status = Status.DEPLOYED if ok else Status.ERROR
        inc.deploy_output = out
        inc.mark("deployed")
        self._publish(inc)
        return inc

    def reject(self, incident_id: str) -> Incident:
        inc = self.store.get(incident_id)
        if inc is None:
            raise KeyError(incident_id)
        inc.status = Status.REJECTED
        inc.mark("rejected")
        self._publish(inc)
        return inc


def create_app(settings: Settings | None = None, workers: int = 2, auto_deploy: bool | None = None) -> FastAPI:
    settings = settings or get_settings()
    orch = Orchestrator(settings, workers=workers, auto_deploy=auto_deploy)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        orch.hub.bind(asyncio.get_running_loop())
        orch.start()
        log.info("orchestrator up (sandbox=%s, workers=%d, auto_deploy=%s)", orch._sandbox_ok, workers, orch.auto_deploy)
        yield
        orch.stop()

    app = FastAPI(title="HRT-Agent Orchestrator", lifespan=lifespan)
    app.state.orch = orch

    @app.post("/webhook/alert")
    async def webhook_alert(alert: Alert):
        inc = orch.submit(alert)
        return {"incident_id": inc.incident_id, "status": inc.status}

    @app.post("/webhook/stats")
    async def webhook_stats(request: Request):
        orch.stats.update(await request.json())
        orch.history.append({k: orch.stats.get(k) for k in ("ts", "flows_per_s", "flows_total", "alerts_total")})
        orch.hub.publish("stats", orch.stats)
        return {"ok": True}

    @app.get("/api/incidents")
    async def incidents(limit: int = 100):
        return [i.model_dump(mode="json") for i in orch.store.recent(limit)]

    @app.get("/api/incidents/{incident_id}")
    async def incident(incident_id: str):
        inc = orch.store.get(incident_id)
        if inc is None:
            raise HTTPException(404)
        return inc.model_dump(mode="json")

    @app.post("/api/incidents/{incident_id}/approve")
    async def approve(incident_id: str):
        try:
            return orch.deploy(incident_id).model_dump(mode="json")
        except KeyError:
            raise HTTPException(404)

    @app.post("/api/incidents/{incident_id}/reject")
    async def reject(incident_id: str):
        try:
            return orch.reject(incident_id).model_dump(mode="json")
        except KeyError:
            raise HTTPException(404)

    @app.post("/api/reset")
    async def reset():
        """Clear incident history and reset the lab firewall to baseline. Used between benchmark
        runs and for demos, so a repeat attack from the same source is not treated as a duplicate."""
        cleared = orch.store.clear()
        fw_ok = False
        try:
            fw_ok, _ = orch.firewall.reset()
        except Exception:
            pass
        return {"cleared": cleared, "firewall_reset": fw_ok}

    @app.get("/api/results")
    async def results():
        """Every evaluation JSON in results/, keyed by file name, for the evidence section of the site."""
        out = {}
        for prefix, folder in (("", settings.results_dir), ("v1_", settings.results_dir / "v1")):
            for path in sorted(folder.glob("*.json")):
                try:
                    out[prefix + path.stem] = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    continue
        return out

    @app.post("/api/lab/attack/{kind}")
    async def lab_attack(kind: str, request: Request):
        """Launch a lab attack from the attacker container (needs Docker). Local requests only."""
        from hrt import lab

        if request.client is None or request.client.host not in ("127.0.0.1", "::1", "localhost"):
            raise HTTPException(403, "lab control is local-only")
        if kind not in ("scan", "synflood", "sshbf", "beacon", "benign"):
            raise HTTPException(400, f"unknown attack '{kind}'")
        job = {"kind": kind, "started": __import__("time").time(), "state": "running"}
        orch.lab_jobs.append(job)
        orch.hub.publish("lab", job)

        def go():
            try:
                lab.attack(kind)
                job["state"] = "done"
            except BaseException as exc:          # SystemExit from lab.attack included
                job["state"] = f"failed: {exc}"
            orch.hub.publish("lab", job)

        threading.Thread(target=go, name=f"lab-{kind}", daemon=True).start()
        return job

    @app.get("/api/summary")
    async def summary():
        return {"counts": orch.store.counts(), "stats": orch.stats, "sandbox": orch._sandbox_ok,
                "auto_deploy": orch.auto_deploy, "rag": orch._lazy_retriever() is not None,
                "firewall_rules": _safe_rules(orch), "history": list(orch.history),
                "lab_jobs": orch.lab_jobs[-5:]}

    @app.get("/api/stream")
    async def stream():
        q = await orch.hub.subscribe()

        async def gen():
            try:
                yield "retry: 2000\n\n"
                while True:
                    try:
                        msg = await asyncio.wait_for(q.get(), timeout=15)
                        yield f"data: {msg}\n\n"
                    except asyncio.TimeoutError:
                        yield ": keepalive\n\n"
            finally:
                orch.hub.unsubscribe(q)

        return StreamingResponse(gen(), media_type="text/event-stream")

    @app.get("/")
    async def index():
        return FileResponse(STATIC_DIR / "index.html")

    if STATIC_DIR.exists():
        class FreshStatic(StaticFiles):
            """Always revalidate: the site is edited between demos and a stale cached script is confusing."""

            async def get_response(self, path, scope):
                resp = await super().get_response(path, scope)
                resp.headers["Cache-Control"] = "no-cache"
                return resp

        app.mount("/static", FreshStatic(directory=STATIC_DIR), name="static")
    return app


def _safe_rules(orch: Orchestrator) -> list[str]:
    try:
        return orch.firewall.rules() if orch._sandbox_ok else []
    except Exception:
        return []
