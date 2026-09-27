"""``hrt`` command-line entry point."""

from __future__ import annotations

import argparse
import json
import logging
import sys
import threading

from hrt.config import get_settings


def _log(verbose: bool) -> None:
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s", datefmt="%H:%M:%S")


# --------------------------------------------------------------------------------------
def cmd_lab(args) -> int:
    from hrt import lab

    s = get_settings()
    if args.action in ("up", "build", "attack") and not lab.ensure_docker():
        return 1
    if args.action == "build":
        lab.build(s)
    elif args.action == "up":
        lab.build(s)
        lab.up(s)
    elif args.action == "down":
        lab.down(s)
    elif args.action == "status":
        lab.status()
    elif args.action == "reset":
        lab.reset_firewall()
    elif args.action == "attack":
        lab.attack(args.kind)
    return 0


def cmd_build_kb(args) -> int:
    from hrt.rag.ingest import build_kb

    s = get_settings()
    if not s.mitre_stix.exists():
        print(f"MITRE STIX not found at {s.mitre_stix}; run `hrt fetch-intel` first")
        return 1
    stats = build_kb(s)
    print(json.dumps(stats, indent=2))
    return 0


def cmd_fetch_intel(args) -> int:
    from hrt.data_fetch import fetch_kev, fetch_mitre

    s = get_settings()
    fetch_mitre(s)
    fetch_kev(s)
    return 0


def cmd_train(args) -> int:
    from hrt.train import train_from_lab

    s = get_settings()
    det = train_from_lab(s, minimum=args.min_windows)
    print(f"trained window detector: threshold={det.threshold:.4f} on {det.meta.get('n_train')} benign windows")
    print(f"saved -> {s.models_dir / 'window_detector.joblib'}")
    return 0


def cmd_triage(args) -> int:
    from hrt.telemetry.zeek import ConnLogTailer
    from hrt.triage.detector import WindowDetector
    from hrt.triage.engine import TriageEngine, WebhookSink

    s = get_settings()
    detector = WindowDetector.load(s.models_dir / "window_detector.joblib")
    if detector.model is None:
        print("[triage] no ML baseline found; running with deterministic rules only "
              "(run `hrt train` for the Isolation Forest)")
    sink = WebhookSink(s.webhook_url, stats_url=s.webhook_url.replace("/alert", "/stats"))
    engine = TriageEngine(detector, sink, s.window_seconds, s.alert_cooldown_seconds)
    tailer = ConnLogTailer(s.conn_log, from_start=args.from_start)
    print(f"[triage] tailing {s.conn_log} -> {s.webhook_url}")
    try:
        engine.run(tailer, stats_cb=sink.stats)
    except KeyboardInterrupt:
        print("\n[triage] stopped")
    return 0


def cmd_serve(args) -> int:
    import uvicorn

    from hrt.orchestrator.server import create_app

    s = get_settings()
    app = create_app(s, workers=args.workers, auto_deploy=args.auto_deploy)
    uvicorn.run(app, host=s.host, port=s.port, log_level="info")
    return 0


def cmd_replay(args) -> int:
    """Replay a saved conn.log (or the lab's) through triage without the webhook, printing alerts."""
    from hrt.telemetry.zeek import read_conn_log
    from hrt.triage.detector import WindowDetector
    from hrt.triage.engine import TriageEngine

    s = get_settings()
    detector = WindowDetector.load(s.models_dir / "window_detector.joblib")
    flows = read_conn_log(args.path or s.conn_log)
    engine = TriageEngine(detector, lambda a: None, s.window_seconds, s.alert_cooldown_seconds, origin="replay")
    alerts = engine.replay(flows)
    for a in alerts:
        print(f"{str(a.source_ip):16} rules={a.detector.rules} ml={a.detector.ml_anomaly} "
              f"ports={a.features.n_dst_ports} flows={a.raw_flow_count}")
    print(f"\n{len(flows)} flows -> {len(alerts)} alerts")
    return 0


def cmd_eval(args) -> int:
    from hrt.eval import runner

    return runner.run(args.suite, get_settings(), fast=args.fast)


def cmd_report(args) -> int:
    from hrt.eval import report

    report.build(get_settings())
    return 0


def cmd_demo(args) -> int:
    from hrt.demo import run_demo

    return run_demo(get_settings())


# --------------------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="hrt", description="HRT-Agent: autonomous Level-1 SOC pipeline")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    lab = sub.add_parser("lab", help="control the Docker lab")
    lab.add_argument("action", choices=["build", "up", "down", "status", "reset", "attack"])
    lab.add_argument("kind", nargs="?", default="scan", help="attack kind for `lab attack`")
    lab.set_defaults(func=cmd_lab)

    sub.add_parser("fetch-intel", help="download MITRE ATT&CK + CISA KEV").set_defaults(func=cmd_fetch_intel)
    sub.add_parser("build-kb", help="embed threat intel into ChromaDB").set_defaults(func=cmd_build_kb)

    tr = sub.add_parser("train", help="fit the benign-baseline Isolation Forest from lab traffic")
    tr.add_argument("--min-windows", type=int, default=50)
    tr.set_defaults(func=cmd_train)

    tri = sub.add_parser("triage", help="run the live Tier-1 triage loop")
    tri.add_argument("--from-start", action="store_true", help="read conn.log from the beginning")
    tri.set_defaults(func=cmd_triage)

    srv = sub.add_parser("serve", help="run the orchestrator + dashboard")
    srv.add_argument("--workers", type=int, default=2)
    srv.add_argument("--auto-deploy", action="store_true", help="deploy verified rules without asking")
    srv.set_defaults(func=cmd_serve)

    rp = sub.add_parser("replay", help="replay a conn.log through triage (offline)")
    rp.add_argument("path", nargs="?")
    rp.set_defaults(func=cmd_replay)

    ev = sub.add_parser("eval", help="run an evaluation suite")
    ev.add_argument("suite", choices=["triage", "agent", "guardrail", "live", "async", "telemetry", "all"])
    ev.add_argument("--fast", action="store_true", help="smaller samples for a quick check")
    ev.set_defaults(func=cmd_eval)

    sub.add_parser("report", help="build results/summary.md and charts").set_defaults(func=cmd_report)
    sub.add_parser("demo", help="scripted end-to-end lab demo").set_defaults(func=cmd_demo)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _log(args.verbose)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
