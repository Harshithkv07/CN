"""Export finished incidents from the local store into the website's replay file.

Usage: python scripts/export_recorded.py [--limit 3] [--status DEPLOYED,SAFE,ESCALATED]

The replay on the website plays these real records back with the waiting time compressed, so the demo
still works when Docker or the model is not running.
"""

import argparse
import json
import time
from pathlib import Path

from hrt.config import get_settings
from hrt.orchestrator.store import IncidentStore

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=3)
    ap.add_argument("--status", default="DEPLOYED,SAFE,ESCALATED")
    ap.add_argument("--ids", default="", help="comma-separated incident ids to export, in order")
    args = ap.parse_args()
    store = IncidentStore(get_settings().db_path)
    wanted = set(args.status.split(","))
    incs = [i for i in store.recent(200) if i.status in wanted and i.attempts]
    if args.ids:
        order = args.ids.split(",")
        incs = sorted((i for i in incs if i.incident_id in order), key=lambda i: order.index(i.incident_id))
    else:
        incs = sorted(incs, key=lambda i: i.alert.detected_at)
        seen, picked = set(), []
        for i in incs:                                  # one per kind of alert first, for variety
            key = tuple(i.alert.detector.rules)
            if key not in seen:
                seen.add(key)
                picked.append(i)
        incs = picked
    incs = incs[: args.limit]
    out = ROOT / "src" / "hrt" / "dashboard" / "static" / "data" / "recorded.json"
    out.write_text(json.dumps({"exported": time.strftime("%Y-%m-%d %H:%M:%S"),
                               "incidents": [json.loads(i.model_dump_json()) for i in incs]}, indent=1), encoding="utf-8")
    print(f"wrote {len(incs)} incident(s) -> {out}")
    for i in incs:
        print(" ", i.incident_id, i.alert.source_ip, i.alert.detector.rules, i.status, f"{len(i.attempts)} attempt(s)")


if __name__ == "__main__":
    main()
