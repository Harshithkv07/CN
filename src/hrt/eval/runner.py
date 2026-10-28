"""Run one or all evaluation suites and persist results as JSON under ``results/``."""

from __future__ import annotations

import inspect
import json
import logging
import time
from pathlib import Path

from hrt.config import Settings

log = logging.getLogger("hrt.eval")

SUITES = {
    "triage": ("triage_eval", "CICIDS2018 detection: HRT vs SIEM vs supervised RF"),
    "agent": ("agent_eval", "Incident accuracy + RAG hallucination ablation"),
    "guardrail": ("guardrail_suite", "Adversarial rule verification vs regex baseline"),
    "async": ("async_vs_inline", "Nodal-delay: async webhook vs inline LLM"),
    "live": ("live_benchmark", "End-to-end time-to-response on the live lab"),
    "beacon": ("beacon_eval", "C2 beaconing: long-window rule vs period and jitter"),
    "injection": ("injection_eval", "Prompt injection and RAG poisoning, layer by layer"),
    "telemetry": ("telemetry_eval", "Measured Tier-1 telemetry reduction on the lab capture"),
}


def _save(settings: Settings, name: str, data: dict) -> Path:
    settings.results_dir.mkdir(parents=True, exist_ok=True)
    path = settings.results_dir / f"{name}.json"
    payload = {"suite": name, "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"), "result": data}
    path.write_text(json.dumps(payload, indent=2))
    log.info("wrote %s", path)
    return path


def run_one(suite: str, settings: Settings, fast: bool, tag: str = "", **opts) -> dict:
    module_name, _ = SUITES[suite]
    module = __import__(f"hrt.eval.{module_name}", fromlist=["run"])
    params = inspect.signature(module.run).parameters
    kwargs = {k: v for k, v in opts.items() if v is not None and k in params}
    log.info("=== running suite: %s (%s) %s ===", suite, "fast" if fast else "full", kwargs or "")
    t0 = time.time()
    data = module.run(settings, fast=fast, **kwargs)
    data["_elapsed_s"] = round(time.time() - t0, 1)
    _save(settings, f"{suite}_{tag}" if tag else suite, data)
    return data


def run(suite: str, settings: Settings, fast: bool = False, tag: str = "", **opts) -> int:
    order = ["triage", "guardrail", "async", "telemetry", "beacon", "agent", "live"] if suite == "all" else [suite]
    failed = []
    for s in order:
        try:
            run_one(s, settings, fast, tag, **opts)
        except SystemExit as exc:
            log.warning("suite %s skipped: %s", s, exc)
            failed.append(s)
        except Exception:
            log.exception("suite %s failed", s)
            failed.append(s)
    if suite == "all":
        from hrt.eval import report

        try:
            report.build(settings)
        except Exception:
            log.exception("report generation failed")
    return 1 if failed and suite != "all" else 0
