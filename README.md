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

hrt serve            # orchestrator + monitor at http://localhost:8000      (terminal B)
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
| `run_agent_eval_full.cmd` | `hrt eval agent` (10 alerts per class, ~2.5 h on CPU) | `data\logs\agent_full.log` |
| `run_queue_llama.cmd` | `hrt eval agent` then `hrt eval injection` on llama3.2:3b | `data\logs\queue_llama.log` |
| `run_queue_rest.cmd` | waits for the above, then the hard-class run, the second model and `hrt report` | `data\logs\queue_rest.log` |
| `fetch_hard.cmd` | `hrt fetch-hard` | `data\logs\fetch_hard.log` |

## Pipeline monitor (dashboard)

`hrt serve` also serves a single-screen monitor at <http://localhost:8000> for watching the pipeline work. It has no
scrolling and no explanatory text:

- **Network traffic:** flows per second (from Zeek via the triage loop), flows seen, alerts sent to the LLM, telemetry
  reduction, a live flow ticker and the top sources.
- **Pipeline lane:** traffic, Zeek, Tier 1, Tier 2, Tier 3 and firewall, each with a live counter and its last timings
  (retrieval and LLM seconds, guardrail milliseconds). A dot crosses a connector when an incident really crosses it.
- **Incident:** four columns for the selected incident: what Tier 1 summarised, what Tier 2 retrieved and answered,
  each guardrail gate with its reason, and the outcome with the rule, the Snort signature and Approve / Reject.
- **Firewall and events:** deployed rules and a timestamped event feed (alerts, retrieval, each model attempt, each
  gate, status changes).
- **Controls:** launch a scan, SYN flood, SSH brute force or beacon in the lab (needs Docker), **Replay** a recorded
  incident (no Docker or model needed; its traffic panel is labelled illustrative), **Reset**.

Plain HTML, CSS and ES modules; GSAP is vendored under `dashboard/static/vendor/`. `python scripts/export_recorded.py`
refreshes the recording from the incident store.

## Evaluation

```bash
hrt eval guardrail   # adversarial rule verification vs a regex baseline (needs Docker)
hrt eval triage      # CICIDS2018 detection: HRT vs SIEM rules vs supervised RF
hrt eval agent       # attribution + RAG hallucination ablation (needs Ollama; --fast ~40 min CPU, full ~2-3 h)
hrt eval async       # nodal-delay: async webhook vs inline LLM
hrt eval telemetry   # measured raw-telemetry vs alert-JSON byte reduction on the lab capture
hrt eval beacon      # C2 beaconing: detection vs period and jitter, and false alarms (no Docker, seconds)
hrt eval injection   # prompt injection and RAG poisoning, layer by layer
hrt fetch-hard       # download Bot / Infiltration / DoS-variant slices of CICIDS2018 (~40 MB)
hrt eval agent --hard --tag hard                 # harder-class ablation
HRT_OLLAMA_MODEL=qwen2.5:3b hrt eval agent --tag qwen --modes rag_hier,no_rag   # a second model
HRT_LLM_PROVIDER=langchain hrt serve             # route the model call through LangChain (pip install -e ".[langchain]")
hrt eval live        # end-to-end time-to-response on the live lab (needs serve+triage+lab)
hrt eval all && hrt report      # writes results/summary.md + charts
```

Full tables and charts are in [`results/summary.md`](results/summary.md). Headline numbers
(CPU-only laptop, `llama3.2:3b`):

| What | Result |
|---|---|
| **Live time-to-response** (attack start → verified rule deployed, 3 runs each) | mean: port scan **97 s**, SYN flood **117 s**, SSH brute force **173 s** — 9/9 deployed, all under the 5-min target, max 196 s |
| **Rule verification** (91 adversarial cases: the original 28 plus IPv6/encoding tricks, CIDR overlap, ordering, conflicts with deployed rules, option smuggling and 20 Snort signatures) | HRT guardrail **100 %** (0 unsafe accepted, 0 safe rejected) vs regex validator **45 %** (accepted 50 unsafe rules). The cases were written by the team that wrote the gate: coverage of known tricks, not an independent audit |
| **Telemetry reduction** (634,464 Zeek records, 242 MB) | median alert is **99.82 %** smaller than the flows it summarises; everything logged vs everything sent to the LLM: **99.997 %** smaller |
| **Async vs inline LLM** (3 s inference, 2 workers) | inline ingest lag grows to 58 s at 1 alert/s and 1,767 s at 20/s; async webhook + queue stays at 0 s |
| **Tier-1 detection** (CICIDS2018, 34,105 flows, same 5 % benign false-positive budget) | Isolation Forest (unsupervised, benign-only): recall **0.53 → 0.999** (F1 0.68 → 0.98) after raising `max_samples` from 256 to 2048, chosen on a validation split; SIEM-style rules F1 0.978; supervised RF ≈1.0 as an upper bound. The families are easy to separate: read the ranking, not the absolute figures |
| **C2 beaconing** (simulated implants through the real Tier-1 engine) | the old 10 s window saw only 1 s beacons; the 15-minute per-destination rule detects 5 s to 2 min beacons at 100 % up to ±20 % jitter, 25-88 % at ±30 %, and misses most at ±50 %. False alarms: 0 % of Poisson web client-hours, 9 % for a client that sleeps a random 2-6 s; a perfectly periodic benign monitor is flagged (a known limit) |
| **Prompt injection / RAG poisoning** (14 payloads) | 0 of 14 reached the prompt from log fields; a fully obedient stub LLM got 0 of 14 harmful rules past grounding and the gate; the live-model test is in `results/injection.json` |
| **Incident attribution / RAG ablation** (first run, original prompt; the re-run after the prompt fix is in `results/summary.md`; 40 CICIDS incidents, 10 each: DDoS-HOIC, DoS-Hulk, FTP & SSH brute force) | with RAG (flat or hierarchical): **40/40** correct technique and tactic, 0 invented IDs, 40/40 verified rules. **Without RAG: 1/40 technique, 0/40 tactic, 19/40 cite ATT&CK IDs that don't exist** (e.g. `T1210.001`), DoS/DDoS labelled as brute force, 1 escalation. Tactic prefilter cuts the search space by 92.8 % with recall@1 = 1.0. **Re-run after the prompt fix** (Llama 3.2 3B, 40 incidents): hierarchical RAG 40/40, 1 LLM call, 59.5 s median; no RAG 10/40 technique, 0/40 tactic, 10/40 invented IDs, 26 s. **Qwen 2.5 3B** (12 incidents): RAG 12/12, 61.8 s; no RAG 6/12 technique, 2/12 tactic. **Harder classes (DoS-Hulk, Infiltration)**: Llama RAG 4/8 vs 0/8 without; Qwen RAG 2/6 vs 0/6. Small samples. |

## Layout

```
src/hrt/
  telemetry/   Zeek conn.log + CICIDS2018 parsers -> normalised Flow
  triage/      windowed features, threshold rules, PyOD Isolation Forest, live engine
  rag/         ATT&CK/KEV ingest, hierarchical retriever, alert->query builder
  llm/         provider interface: Ollama (JSON-schema constrained), LangChain adapter, Fake (tests)
  agent/       analyst loop: retrieve -> prompt -> validate -> guardrail -> self-correct/escalate
  guardrail/   policy, subnet (bitwise AND), conflicts, kernel sandbox, Snort signature gate, gated deploy
  orchestrator/ FastAPI webhook + queue + SQLite store + SSE
  dashboard/   single-screen pipeline monitor (traffic, pipeline lane, incident, firewall, events)
  eval/        triage / agent / guardrail / async / telemetry / live suites + report
docker/        victim, attacker, sandbox images; Zeek policy; compose
scripts/       Windows launchers (see above)
tests/         pytest (Docker-dependent tests auto-skip)
docs/          DEMO_RUNBOOK.md, DATA_NOTES.md (data provenance + environment caveats), THREAT_MODEL.md,
results/       measured results (JSON), summary.md, charts
```

## Honesty notes

- CICIDS2018 CSVs carry no source IPs, so Tier-1 dataset evaluation is **flow-level**, and agent
  incidents synthesised from them use documented TEST-NET attacker addresses.
- The "SIEM baseline" is a faithful set of SIEM-style correlation rules implemented here, labelled
  as such — not Splunk/QRadar themselves.
- The project brief suggested LangChain. The default agent loop in `src/hrt/agent/analyst.py` calls ChromaDB and
  Ollama's `/api/chat` directly, so every step (retrieve, prompt, validate, guardrail, retry) is visible in one
  short file. `HRT_LLM_PROVIDER=langchain` routes the model call through a LangChain runnable
  (`src/hrt/llm/langchain.py`, tested against LangChain's fake chat model) and leaves the loop untouched. LangChain
  does not orchestrate the retrieval or the retry loop.
- The Snort/Suricata signature is **rendered from the verified decision** (or accepted from the model if it passes) and
  checked by a static allowlist parser. The lab has no Snort engine, so a signature is never loaded and the kernel
  does not verify it; only the iptables rule is kernel-verified.
- CVE data is already in the RAG store (the CISA known-exploited-vulnerabilities list, a second ChromaDB collection).
  It is shown as patch context for the targeted service, not used for attribution.
- Search-space reduction and telemetry-reduction figures are **measured per run**, not assumed.
- The Isolation Forest is weak on volumetric DoS/DDoS in CICIDS2018 (recall 0.21 / 0.00); the
  deterministic rules carry those classes. The two are complementary, which is why Tier 1 is hybrid.
- C2 beaconing is demonstrated on **simulated** implant traffic (`hrt eval beacon`) and by a lab attack that starts
  a beacon loop in the attacker container (`hrt lab attack beacon`). The CICIDS2018 slices used here contain no
  botnet traffic. Heavily jittered beacons are missed, and a perfectly periodic benign agent (a 30 s monitoring
  poll) looks identical to a beacon on timing alone. See `docs/THREAT_MODEL.md`.
- The agent evaluation covers 40 incidents from 4 CICIDS classes (each costs 1-2 minutes of CPU
  inference, 2 h 49 min for all three modes). Flat and hierarchical RAG tie at 100 % and gave
  identical answers on every incident: for these attack types flat search already ranks the right
  techniques first, so the hierarchy's measured benefit here is the 92.8 % smaller search space,
  not higher accuracy. Harder or more ambiguous classes would be needed to separate them.
- With the 3B model no incident passed verification on the first attempt. Across the 40-incident run, 36
  incidents needed 3 attempts and 4 needed 2; all 9 live-lab incidents needed 3. In the no-RAG
  probe (`results/agent_probe_norag.txt`) each incident failed the policy check (no `-A/-I` chain),
  then the conflict check (an `-A` rule shadowed by an existing ACCEPT), and passed on attempt 3
  using the verifier's feedback. The Tier-3 loop is what turns the small model's output into a
  safe rule.
- The live lab runs every attack from one attacker (10.10.0.66); the benchmark resets the victim
  firewall and incident store between runs so earlier blocks don't skew later ones.
- On this machine Windows Smart App Control blocks some unsigned scikit-learn DLLs, so PyOD is
  imported lazily and one detector test auto-skips when it is blocked. See `docs/DATA_NOTES.md`.
