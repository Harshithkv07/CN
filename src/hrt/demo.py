"""Scripted end-to-end demo: reset, launch a port scan, wait for the verified mitigation, show it.

Assumes `hrt serve` and `hrt triage` are already running (see docs/DEMO_RUNBOOK.md).
"""

from __future__ import annotations

import time

import httpx

from hrt import lab
from hrt.config import Settings

ATTACKER_IP = "10.10.0.66"


def _banner(msg: str) -> None:
    print(f"\n{'=' * 64}\n  {msg}\n{'=' * 64}")


def run_demo(settings: Settings) -> int:
    base = f"http://{settings.host}:{settings.port}"
    try:
        httpx.get(f"{base}/api/summary", timeout=3)
    except httpx.HTTPError:
        print("Orchestrator not reachable. In two terminals run:\n  hrt serve\n  hrt triage")
        return 1
    if not lab.ensure_docker():
        return 1

    _banner("1. Reset lab firewall to baseline and clear old incidents")
    try:
        httpx.post(f"{base}/api/reset", timeout=30).raise_for_status()
    except httpx.HTTPError:
        lab.reset_firewall()          # older orchestrator without /api/reset: firewall only
    print("current rules:")
    for r in lab.firewall_rules():
        print("   ", r)

    _banner("2. Launch nmap SYN scan from the attacker container")
    t0 = time.time()
    lab.attack("scan")

    _banner("3. Wait for HRT-Agent to detect, retrieve, synthesise and verify")
    incident = None
    while time.time() - t0 < 180:
        try:
            incs = httpx.get(f"{base}/api/incidents", timeout=5).json()
        except httpx.HTTPError:
            incs = []
        for inc in incs:
            if inc["alert"]["source_ip"] == ATTACKER_IP and inc["alert"]["detected_at"] >= t0 - 1:
                incident = inc
                break
        if incident and incident["status"] in ("SAFE", "DEPLOYED", "ESCALATED"):
            break
        time.sleep(2)

    if not incident:
        print("No incident produced within 3 minutes.")
        return 1

    m = incident.get("mitigation") or {}
    print(f"   status:     {incident['status']}")
    print(f"   technique:  {m.get('mitre_technique_id')} {m.get('mitre_technique_name')}")
    print(f"   summary:    {m.get('incident_summary')}")
    print(f"   rule:       {m.get('iptables_rule')}")
    if incident.get("verdict"):
        for c in incident["verdict"]["checks"]:
            print(f"     [{'PASS' if c['passed'] else 'FAIL'}] {c['stage']}: {c['detail'][:80]}")

    if incident["status"] == "SAFE":
        _banner("4. Approve -> deploy the verified rule")
        httpx.post(f"{base}/api/incidents/{incident['incident_id']}/approve", timeout=10)
        time.sleep(2)

    _banner("5. Confirm the attacker is now blocked")
    for r in lab.firewall_rules():
        if ATTACKER_IP in r:
            print("    deployed:", r)
    print(f"\nElapsed: {time.time() - t0:.1f}s")
    return 0
