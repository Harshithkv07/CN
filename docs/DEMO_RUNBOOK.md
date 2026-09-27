# HRT-Agent — Live Demo Run-book

A ~5-minute classroom demo: bring up the lab, launch an attack, and watch HRT-Agent detect it,
ground the analysis in MITRE ATT&CK, synthesise a firewall rule, verify it in a kernel sandbox,
and deploy it — then confirm the attacker is blocked.

## 0. One-time setup (do before class)

```bash
# from hrt-agent/, with the venv active
pip install -e .
hrt fetch-intel        # download MITRE ATT&CK + CISA KEV  (~55 MB, once)
hrt build-kb           # embed threat intel into ChromaDB   (~1 min)
hrt lab build          # build victim/attacker/sandbox images (~2 min)
```

Requirements: Docker Desktop running, and Ollama serving `llama3.2:3b`
(`scripts\start_ollama.cmd` runs `D:\Ollama\app\ollama.exe serve` with
`OLLAMA_MODELS=D:\Ollama\models`; the app also auto-starts it if it is down).
Confirm with `curl http://127.0.0.1:11434/api/version`. On CPU the first model load takes ~5 s
and each LLM call 30-60 s, so start Ollama a few minutes early.

## 1. Bring up the lab (Terminal A)

```bash
hrt lab up
```

This starts four containers on `10.10.0.0/24`: the protected server (`hrt-victim`,
10.10.0.10), a Zeek sensor writing `data/zeek/conn.log`, a benign client, and an idle attacker.

Let benign traffic run ~2 minutes, then train the Tier-1 baseline once:

```bash
hrt train              # fits the Isolation Forest on benign windows
```

## 2. Start the pipeline

Terminal B — orchestrator + dashboard:
```bash
hrt serve
```
Open <http://localhost:8000>. The header pills should read *stream live*, *RAG ready*,
*sandbox up*, *gated*.

Terminal C — Tier-1 triage (tails Zeek, POSTs alerts to the orchestrator):
```bash
hrt triage
```

On Windows you can instead double-click `scripts\start_orchestrator.cmd` and
`scripts\start_triage.cmd`; they run minimized and log to `data\logs\`.

## 3. Run the demo

Either the scripted version (Terminal D), which clears old incidents and the firewall, launches the
scan, waits for the verified rule, approves it and shows it deployed (about 100 s on CPU):
```bash
hrt demo
```
or drive it manually and narrate from the dashboard:
```bash
hrt lab attack scan        # nmap SYN scan across 1024 ports
```

What to point at on the dashboard, in order:
1. **Tier 1** — a red incident appears for `10.10.0.66` with rule `PORT_SCAN`; note the
   SYN/ACK ratio and that only the compact alert (not raw packets) moved downstream.
2. **Tier 2** — the tactic prefilter (`discovery, reconnaissance`), the search-space reduction,
   and the retrieved MITRE techniques with similarity scores. In the recorded runs the model
   attributed **T1595.001 Active Scanning: Scanning IP Blocks**, grounded in the retrieved set
   (T1046 Network Service Discovery is the other accepted answer).
3. **Tier 3** — the four guardrail checks tick green: policy → subnet (bitwise-AND) →
   conflict → kernel `iptables-restore --test`. If an attempt fails (in the recorded runs
   the small model's first tries were rejected by the policy check, e.g. a missing `-A/-I`), the
   failure reason is fed back and the agent self-corrects; up to 3 attempts, then it escalates.
   Expect roughly 1.5-3 minutes from attack to a SAFE rule on CPU.
4. **Approve & deploy** — click it; the rule is applied to the victim's firewall.

## 4. Prove it worked

```bash
hrt lab attack scan        # run the same scan again
```
The dashboard's firewall panel now shows the DROP rule for `10.10.0.66`, and the second scan
reports the ports filtered. Show a legitimate check still passing:
```bash
hrt lab attack benign      # HTTP from an allowed host still succeeds
```

## 5. Optional talking points

- `hrt lab attack synflood` and `hrt lab attack sshbf` show other techniques (T1499, T1110).
- The subnet guardrail: if the model ever proposed blocking `10.10.0.0/24`, Tier 3 refuses it and
  escalates — no self-inflicted DoS.
- `hrt eval guardrail` on the spot: HRT verifier vs a regex baseline on adversarial rules.

## Reset between runs

```bash
hrt lab reset      # restore the victim firewall to baseline
```

## Teardown

```bash
hrt lab down       # stop and remove containers + network
```
