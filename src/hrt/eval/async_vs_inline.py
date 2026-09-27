"""Nodal-delay experiment: async webhook triage vs an inline (blocking) LLM design.

Alerts arrive at a fixed rate for ``duration`` seconds, each needing ``llm_seconds`` of inference.

* **inline**: the ingest path itself runs the LLM, so a new alert can only be accepted after the
  previous one finishes. Ingest lag (arrival -> accepted) is the growing queue backed up behind
  inference: this is d_queue -> infinity when arrival rate > 1/llm_seconds.
* **async**: ingest just enqueues (accept lag ~ 0) and ``workers`` threads consume. Ingestion
  keeps pace regardless of inference time; only end-to-end completion lag grows, bounded by
  worker throughput.

Both are simulated as discrete-event queues.
"""

from __future__ import annotations

from hrt.config import Settings


def _simulate(rate_hz: float, duration_s: float, llm_seconds: float, workers: int, inline: bool) -> dict:
    n = max(int(rate_hz * duration_s), 1)
    arrivals = [i / rate_hz for i in range(n)]

    # accept_lag[i]: time from arrival to being accepted for processing (the ingest-side queue).
    # complete_lag[i]: time from arrival to finished mitigation (end-to-end).
    accept_lag, complete_lag = [], []
    servers = 1 if inline else workers
    free = [0.0] * servers
    max_backlog = 0

    for i, t in enumerate(arrivals):
        s = min(range(servers), key=lambda j: free[j])
        start = max(t, free[s])
        if inline:
            # ingestion is the server: it cannot accept alert i until server is free
            accept_lag.append(start - t)
        else:
            accept_lag.append(0.0)  # enqueue is non-blocking
        free[s] = start + llm_seconds
        complete_lag.append(free[s] - t)
        # backlog = alerts that have arrived but not yet started service
        in_progress = sum(1 for f in free if f > t)
        arrived = i + 1
        started = sum(1 for cl, a in zip(complete_lag, arrivals) if a + (cl - llm_seconds) <= t)
        max_backlog = max(max_backlog, arrived - started)

    return {
        "processed": n,
        "mean_accept_lag_s": round(sum(accept_lag) / n, 2),
        "max_accept_lag_s": round(max(accept_lag), 2),
        "mean_complete_lag_s": round(sum(complete_lag) / n, 2),
        "max_complete_lag_s": round(max(complete_lag), 2),
        "max_backlog": max_backlog,
        "overloaded": rate_hz * llm_seconds > servers,  # arrivals outpace service capacity
    }


def run(settings: Settings, fast: bool = False) -> dict:
    llm_seconds = 3.0     # representative CPU inference time per incident
    duration = 30.0
    workers = 2
    rates = [1, 5, 10] if fast else [1, 2, 5, 10, 20]
    out: dict = {"llm_seconds": llm_seconds, "duration_s": duration, "workers": workers, "rates": {}}
    for r in rates:
        out["rates"][str(r)] = {
            "inline": _simulate(r, duration, llm_seconds, 1, inline=True),
            "async": _simulate(r, duration, llm_seconds, workers, inline=False),
        }
    return out
