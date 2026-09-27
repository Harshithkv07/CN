# HRT-Agent

**Hybrid RAG-Telemetry Architecture for Autonomous SOC Automation**
Group 9, Amrita Vishwa Vidyapeetham — Computer Networks project.

An autonomous **Level-1 SOC analyst** that watches live network telemetry, detects attacks,
grounds its reasoning in the MITRE ATT&CK knowledge base, synthesises an `iptables` mitigation
rule, and **deterministically verifies that rule in a kernel sandbox before it is ever deployed**.

It is built around three tiers with strict interface contracts — raw packets never reach the LLM,
and no rule leaves the sandbox unverified.

```
                          data/zeek/conn.log
   ┌─────────┐   flows    ┌──────────────┐  compact alert  ┌────────────────┐
   │  Zeek   │──────────▶│  Tier 1      │────JSON webhook─▶│  Orchestrator  │
   │ sensor  │            │  Triage      │   (async)        │  (FastAPI +    │
   └─────────┘            │ rules + PyOD │                  │   queue +      │
        ▲                 │ IsolationF.  │                  │   SQLite)      │
   ┌─────────┐  attacks   └──────────────┘                  └───────┬────────┘
   │attacker │                                                      │ worker
   │container│                              ┌───────────────────────▼─────────┐
   └─────────┘                              │  Tier 2  RAG intelligence        │
   ┌─────────┐                              │  hierarchical retrieve (ChromaDB)│
   │ victim  │◀──── verified rule ────┐     │  + local LLM (Ollama/Llama-3.2)  │
   │(iptables)│      (analyst approve)│     └───────────────────┬──────────────┘
   └─────────┘                        │                         │ mitigation JSON
        ▲                     ┌───────┴───────────┐  ┌──────────▼──────────────┐
        └── deploy ───────────│ Tier 3 guardrail  │◀─│ policy→subnet→conflict→ │
                              │  gated deployment │  │ kernel iptables-restore │
                              └───────────────────┘  │ --test (Docker sandbox) │
                                                      └─────────────────────────┘
                                                        self-correct ≤3×, else escalate
```

## Why three tiers

| Gap (from the literature) | HRT-Agent's answer |
|---|---|
| **Telemetry blind spot** — PCAP/NetFlow overwhelms LLM context | Tier 1 aggregates flows into a ~20-number alert; raw packets never reach the LLM |
| **Hallucination** — LLMs invent techniques/CVEs | Tier 2 grounds every attribution in retrieved MITRE ATT&CK; ungrounded technique IDs are rejected and retried |
| **Excessive agency** — an unverified rule can cause self-inflicted DoS | Tier 3 checks policy + a bitwise-AND subnet guardrail + conflicts + a real `iptables-restore --test`, then gates on human approval |
| **Latency** — inline LLM stalls line-rate traffic | Async webhook + worker queue decouples ingestion from inference (bounded `d_queue`) |

## Quick start

```bash
python -m venv .venv && .venv\Scripts\activate     # Windows
pip install -e ".[dev]"

hrt fetch-intel      # MITRE ATT&CK (authoritative STIX) + CISA KEV
hrt build-kb         # embed into ChromaDB (local ONNX MiniLM, no GPU)
hrt lab build        # build victim / attacker / sandbox Docker images
hrt lab up           # start the lab; let benign traffic run ~2 min
hrt train            # fit the Tier-1 Isolation Forest on benign traffic

hrt serve            # orchestrator + dashboard at http://localhost:8000   (terminal B)
hrt triage           # live Tier-1 loop                                    (terminal C)
hrt demo             # scripted end-to-end attack -> mitigation demo       (terminal D)
```

The LLM runs locally through **Ollama** (`llama3.2:3b`). This project keeps a portable Ollama
under `D:\Ollama` (`app\` + `models\`) so it can be removed cleanly afterwards; see `.env.example`.

### Windows launchers

Long-running pieces are started from `scripts\` as minimized, named console windows that log to
`data\logs\` (Ollama logs to `D:\Ollama\serve.*.log`). Double-click them or run them from Explorer;
close the window to stop that piece.

| Script | Starts | Log |
|---|---|---|
| `start_ollama.cmd` | portable Ollama server on `127.0.0.1:11434` | `D:\Ollama\serve.err.log` |
| `start_orchestrator.cmd` | `hrt serve` (dashboard at http://localhost:8000) | `data\logs\serve.log` |
| `start_triage.cmd` | `hrt triage` (tails `data\zeek\conn.log`) | `data\logs\triage.log` |
| `run_live_benchmark.cmd` | `hrt eval live` (needs lab + the two above) | `data\logs\live.log` |
| `run_agent_eval.cmd` | `hrt eval agent --fast` (~40 min on CPU) | `data\logs\agent.log` |

## Evaluation

```bash
hrt eval guardrail   # adversarial rule verification vs a regex baseline (needs Docker)
hrt eval triage      # CICIDS2018 detection: HRT vs SIEM rules vs supervised RF
hrt eval agent       # attribution + RAG hallucination ablation (needs Ollama; --fast ~40 min CPU, full ~2-3 h)
hrt eval async       # nodal-delay: async webhook vs inline LLM
hrt eval telemetry   # measured raw-telemetry vs alert-JSON byte reduction on the lab capture
hrt eval live        # end-to-end time-to-response on the live lab (needs serve+triage+lab)
hrt eval all && hrt report      # writes results/summary.md + charts
```

Full tables and charts are in [`results/summary.md`](results/summary.md). Headline numbers
(CPU-only laptop, `llama3.2:3b`):

| What | Result |
|---|---|
| **Live time-to-response** (attack start → verified rule deployed, 3 runs each) | mean: port scan **97 s**, SYN flood **117 s**, SSH brute force **173 s** — 9/9 deployed, all under the 5-min target, max 196 s |
| **Rule verification** (28 adversarial rules) | HRT guardrail **100 %** vs regex validator **39 %**; the regex accepted 17 unsafe rules (injection, blocking the gateway/server/LAN, `0.0.0.0/0`, …) |
| **Telemetry reduction** (634,464 Zeek records, 242 MB) | median alert is **99.82 %** smaller than the flows it summarises; everything logged vs everything sent to the LLM: **99.997 %** smaller |
| **Async vs inline LLM** (3 s inference, 2 workers) | inline ingest lag grows to 58 s at 1 alert/s and 1,767 s at 20/s; async webhook + queue stays at 0 s |
| **Tier-1 detection** (CICIDS2018, 34,105 flows) | SIEM-style rules F1 0.978; Isolation Forest (unsupervised, benign-only) P 0.93 / R 0.53 / ROC-AUC 0.96 — catches brute force (recall ≈1.0), misses volumetric DoS/DDoS, which the rules cover; supervised RF ≈1.0 as an upper bound |
| **Incident attribution / RAG ablation** (12 CICIDS incidents: DDoS-HOIC, DoS-Hulk, FTP & SSH brute force) | with RAG (flat or hierarchical): **12/12** correct technique and tactic, 0 invented IDs, 12/12 verified rules. **Without RAG: 1/12 technique, 0/12 tactic, 5/12 cite ATT&CK IDs that don't exist** (e.g. `T1210.001`), 1 escalation. Tactic prefilter cuts the search space by 92.8 % with recall@1 = 1.0 |

## Layout

```
src/hrt/
  telemetry/   Zeek conn.log + CICIDS2018 parsers -> normalised Flow
  triage/      windowed features, threshold rules, PyOD Isolation Forest, live engine
  rag/         ATT&CK/KEV ingest, hierarchical retriever, alert->query builder
  llm/         provider interface: Ollama (JSON-schema constrained) + Fake (tests)
  agent/       analyst loop: retrieve -> prompt -> validate -> guardrail -> self-correct/escalate
  guardrail/   policy, subnet (bitwise AND), conflicts, kernel sandbox, gated deploy
  orchestrator/ FastAPI webhook + queue + SQLite store + SSE
  dashboard/   live SOC console (no external CDNs)
  eval/        triage / agent / guardrail / async / telemetry / live suites + report
docker/        victim, attacker, sandbox images; Zeek policy; compose
scripts/       Windows launchers (see above)
tests/         pytest (Docker-dependent tests auto-skip)
docs/          DEMO_RUNBOOK.md, DATA_NOTES.md (data provenance + environment caveats),
               deck/ (update_deck.py builds ../CN SEM3 - Final Review.pptx from results/*.json)
results/       measured results (JSON), summary.md, charts
```

## Honesty notes

- CICIDS2018 CSVs carry no source IPs, so Tier-1 dataset evaluation is **flow-level**, and agent
  incidents synthesised from them use documented TEST-NET attacker addresses.
- The "SIEM baseline" is a faithful set of SIEM-style correlation rules implemented here, labelled
  as such — not Splunk/QRadar themselves.
- Search-space reduction and telemetry-reduction figures are **measured per run**, not assumed.
- The Isolation Forest is weak on volumetric DoS/DDoS in CICIDS2018 (recall 0.21 / 0.00); the
  deterministic rules carry those classes. The two are complementary, which is why Tier 1 is hybrid.
- The agent evaluation is small (12 incidents, 4 CICIDS classes, `--fast`) because each incident
  costs 1-2 minutes of CPU inference. On it, flat and hierarchical RAG tie at 100 %; the
  hierarchy's measured benefit here is the 92.8 % smaller search space, not higher accuracy.
- The 3B model rarely gets the `iptables` rule right first time. All 9 live-lab incidents needed 3
  attempts (in the one inspected, both rejections came from the policy check, e.g. no `-A/-I`
  chain), and in the no-RAG
  probe (`results/agent_probe_norag.txt`) each incident failed the policy check, then the conflict
  check (an `-A` rule shadowed by an existing ACCEPT), and passed on attempt 3 using the verifier's
  feedback. The Tier-3 loop is what turns the small model's output into a safe rule.
- The live lab runs every attack from one attacker (10.10.0.66); the benchmark resets the victim
  firewall and incident store between runs so earlier blocks don't skew later ones.
- On this machine Windows Smart App Control blocks some unsigned scikit-learn DLLs, so PyOD is
  imported lazily and one detector test auto-skips when it is blocked. See `docs/DATA_NOTES.md`.
