"""End-to-end time-to-response benchmark against the live Docker lab.

For each attack (scan, synflood, sshbf): reset the firewall, mark t0, launch the attack, wait for
the orchestrator to produce a verified+deployed incident for the attacker IP, and record the
stage breakdown (attack -> alert -> retrieval -> LLM -> verified -> deployed). Then confirm the
attacker is actually blocked. Requires the lab and orchestrator to be running.
"""

from __future__ import annotations

import logging
import time

import httpx

from hrt import lab
from hrt.config import Settings
from hrt.eval.labels import LAB_ATTACKS

log = logging.getLogger("hrt.eval.live")
ATTACKER_IP = "10.10.0.66"


def _latest_incident(base: str, source_ip: str, after: float) -> dict | None:
    try:
        incs = httpx.get(f"{base}/api/incidents", timeout=5).json()
    except httpx.HTTPError:
        return None
    for inc in incs:
        if inc["alert"]["source_ip"] == source_ip and inc["alert"]["detected_at"] >= after - 1:
            return inc
    return None


def _stage_times(inc: dict, t0: float) -> dict:
    t = inc.get("times", {})
    def rel(k):
        return round(t[k] - t0, 2) if k in t else None
    return {"to_alert": rel("queued"), "to_retrieved": rel("retrieved"), "to_verified": rel("verified"),
            "to_deployed": rel("deployed"), "status": inc["status"], "attempts": len(inc.get("attempts", []))}


def _run_one(kind: str, base: str, timeout_s: float, settings: Settings) -> dict:
    try:
        httpx.post(f"{base}/api/reset", timeout=15)   # clear store + firewall so repeats aren't duplicates
    except httpx.HTTPError:
        lab.reset_firewall()
    time.sleep(1)
    t0 = time.time()
    lab.attack(kind)
    deadline = t0 + timeout_s
    inc = None
    while time.time() < deadline:
        cand = _latest_incident(base, ATTACKER_IP, t0)
        if cand and cand["status"] in ("SAFE", "DEPLOYED", "ESCALATED", "DUPLICATE"):
            inc = cand
            if cand["status"] == "SAFE":  # approve to measure deploy time
                try:
                    httpx.post(f"{base}/api/incidents/{cand['incident_id']}/approve", timeout=10)
                except httpx.HTTPError:
                    pass
                time.sleep(1.5)
                inc = _latest_incident(base, ATTACKER_IP, t0) or cand
            break
        time.sleep(1)
    if inc is None:
        return {"attack": kind, "detected": False, "note": "no verified incident within timeout"}
    stages = _stage_times(inc, t0)
    blocked = _confirm_blocked(kind)
    return {"attack": kind, "detected": True, "expected_rule": LAB_ATTACKS[kind]["rule"],
            "total_response_s": stages.get("to_deployed") or stages.get("to_verified"),
            **stages, "attacker_blocked_after": blocked,
            "mitigation": inc.get("mitigation", {}).get("iptables_rule") if inc.get("mitigation") else None,
            "technique": inc.get("mitigation", {}).get("mitre_technique_id") if inc.get("mitigation") else None}


def _confirm_blocked(kind: str) -> bool | None:
    rules = lab.firewall_rules()
    return any("DROP" in r or "REJECT" in r for r in rules if ATTACKER_IP in r) if rules else None


def run(settings: Settings, fast: bool = False) -> dict:
    base = f"http://{settings.host}:{settings.port}"
    try:
        httpx.get(f"{base}/api/summary", timeout=3)
    except httpx.HTTPError:
        return {"error": "orchestrator not reachable; run `hrt serve` (and `hrt triage`) first", "runs": []}
    if not lab.ensure_docker():
        return {"error": "docker/lab not available", "runs": []}

    attacks = ["scan"] if fast else ["scan", "synflood", "sshbf"]
    repeats = 1 if fast else 3
    runs = []
    for kind in attacks:
        for r in range(repeats):
            log.info("live run %s #%d", kind, r + 1)
            runs.append(_run_one(kind, base, timeout_s=300, settings=settings))  # = the 5-min target
            time.sleep(2)
    ok = [r for r in runs if r.get("detected") and r.get("total_response_s")]
    summary = {}
    for kind in attacks:
        times = [r["total_response_s"] for r in ok if r["attack"] == kind and r["total_response_s"]]
        if times:
            summary[kind] = {"runs": len(times), "mean_s": round(sum(times) / len(times), 2),
                             "min_s": round(min(times), 2), "max_s": round(max(times), 2),
                             "under_5min": all(t < 300 for t in times)}
    return {"target_seconds": 300, "runs": runs, "summary": summary}
