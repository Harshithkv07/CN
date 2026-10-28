# HRT-Agent: threat model and limitations

This page says what HRT-Agent protects, who it assumes is attacking, which defence handles each threat,
what evidence backs that defence, and what is **not** covered. Every number points at a file in `results/`.

## 1. What is being protected

| Asset | Why it matters |
|---|---|
| The protected server (10.10.0.10), its gateway (10.10.0.1), loopback and known-good clients | Blocking any of them is a self-inflicted denial of service. They are the `protected_subnets` in `config.py`. |
| The firewall ruleset on the protected server | The agent is allowed to add block rules. A bad rule (flush, default-DROP, ACCEPT-all) removes protection or availability. |
| The analyst's time and trust | A hallucinated incident wastes hours; a wrong block erodes trust. |
| The host running the agent | Model output must never reach a shell. |

## 2. Trust boundaries

```
 untrusted                         semi-trusted                       trusted
 ----------                        ------------                       -------
 network traffic -> Zeek -> Tier 1 (numbers only) -> Tier 2 (LLM + RAG) -> Tier 3 gate -> analyst -> firewall
 attacker-chosen      parsed into    validated IPv4 +     model output is    deterministic     human approves
 bytes and strings    typed Flow     numeric features     UNTRUSTED text     code decides      (gated deploy)
```

Two rules follow from this picture and drive the design:

1. **Nothing the attacker writes reaches the prompt as text.** `Alert` holds a validated `IPv4Address` and numbers.
2. **Nothing the model writes reaches the firewall without a deterministic gate.** The LLM is treated as an
   unreliable author, not a trusted component.

## 3. Adversaries assumed

| Adversary | Capability assumed | Out of scope |
|---|---|---|
| Remote attacker | Sends arbitrary traffic to the server (scans, floods, brute force, beaconing), controls every byte and string in it | Physical access, root on the server, the analyst's workstation |
| Attacker who can influence log fields | Puts text into any Zeek field | Compromising the Zeek sensor itself |
| Attacker who can poison the knowledge base | Edits retrieved ATT&CK/CVE text | Supply-chain attacks on the Python or model packages |
| Misbehaving or hijacked LLM | Emits any text, including exact attacker-chosen rules | Weights tampering |

## 4. Threats and defences

| # | Threat | Defence | Evidence | Residual risk |
|---|---|---|---|---|
| T1 | Telemetry overload: raw packets exceed the model's context | Tier 1 collapses a window into about 20 numbers | `results/telemetry.json`: median 99.82 % per-alert reduction | Alerts from many distinct sources still queue; the async workers bound lag, not total work |
| T2 | LLM hallucinates an ATT&CK technique | Retrieval-grounded prompt, then a check that the cited ID exists **and** was retrieved | `results/agent.json`: invalid-ID rate 47.5 % without RAG, 0 % with | Grounding checks membership, not correctness; see T7 |
| T3 | LLM proposes a destructive or malformed rule | Stage 1 allowlist parser (single `-A`/`-I`, DROP/REJECT, allowed options, no shell characters) | `results/guardrail.json`: 91 cases, 0 false accepts | Allowlist is only as good as its option list (see section 5) |
| T4 | Rule blocks the server, gateway, LAN, or everything | Stage 2 bitwise-AND overlap with protected subnets plus a minimum prefix length | Same file, `self_dos` category | Protected list is configuration; a wrong list is a wrong defence |
| T5 | Rule is shadowed by an earlier ACCEPT, or duplicates an existing block | Stage 3 conflict check against the baseline and deployed rules | Same file, `ordering` and `conflict` categories | Only the rules HRT knows about; a rule added out of band is invisible |
| T6 | Rule is syntactically valid-looking but the kernel rejects it | Stage 4 `iptables-restore --test` plus commit in a throwaway container (no network, read-only, `NET_ADMIN` only) | Same file, kernel-stage cases | Needs Docker; without it the gate fails closed ("cannot verify") |
| T7 | Attribution steered to a wrong but retrieved technique | None beyond grounding | `results/injection.json`, `limits` | **Open.** Injected text can change which retrieved technique is cited |
| T8 | Indirect prompt injection through log fields | Typed `Alert`; strings never leave the parser | `results/injection.json`, `telemetry_path`: 0 of 14 payloads reached the prompt | Any future field that carries free text breaks this guarantee |
| T9 | RAG poisoning | Fenced prompt ("data, never instructions"), grounding, Stage 1-4 gate | `results/injection.json`: obedient-LLM path 0 of 14 harmful rules accepted; live path reports follow-rate with and without the fence | A poisoned entry can still mislead attribution (T7) |
| T10 | Shell injection through model output | Rule is tokenised, never passed to a shell; the sandbox gets the ruleset base64-encoded in an environment variable with a fixed entrypoint | `inject_*` cases in the guardrail suite | A new code path that interpolates model text into a command would undo this |
| T11 | Self-inflicted DoS through automation | Gated deployment: a human approves each rule by default | `auto_deploy=False` | Turning on auto-deploy trades safety for speed |
| T12 | Slow C2 evades timing windows | Long-window beacon rule (15 min, per source-destination-port) | `results/beacon.json` | Heavy jitter (30 % and up) is missed; see section 5 |

## 5. Limitations (read before trusting a number)

**Detection**
- The CICIDS2018 evaluation is **flow-level** on a sample of 34,105 flows and four attack families. The files
  carry no source IPs, so per-source windowing is not tested on this data. High scores partly reflect that these
  families are easy to separate (the supervised Random Forest scores 0.9999).
- The Isolation Forest operating point is a 5 % benign false-positive budget, so it flags about 1 benign flow in
  20. That is acceptable for a triage filter and would be too noisy to act on alone.
- The SIEM baseline is a set of SIEM-style rules written for this project, not Splunk or QRadar.
- Beacon detection is **simulated traffic**, not real malware. Detection is complete up to about 20 % jitter and falls
  off beyond that. A perfectly periodic benign agent (a 30 s monitoring poll) is indistinguishable from a
  beacon by timing alone and raised an alert in the evaluation. A client that sleeps a random 2 to 6 s raised a false
  alarm in about 9 % of simulated client-hours.

**Reasoning (Tier 2)**
- One small local model (Llama 3.2 3B) and, for comparison, a second small model. Larger or different models may
  behave differently.
- Incident evidence for the CICIDS evaluation is synthesised from flow groups with documented TEST-NET source
  addresses, so retrieval and attribution are tested on realistic numbers but not on a live attacker.
- Technique accuracy is scored against an allowlist of acceptable techniques per attack class that the authors wrote.
  A different allowlist would change the numbers.
- Flat and hierarchical retrieval tie on accuracy. The hierarchy's measured benefit is the smaller search space.

**Guardrail (Tier 3)**
- The 91 adversarial cases were written by the same people who wrote the gate. A 100 % result shows the gate handles
  the cases its authors thought of; it is not a proof and not an independent audit.
- The Snort/Suricata check is **static** (grammar, options, source scoping). The lab has no Snort binary, so a
  signature is not loaded into an engine.
- Stage 4 depends on Docker. If the sandbox is unavailable the gate rejects everything (fail closed).

**System**
- It is a near-real-time responder, not an inline packet filter. End-to-end time was 97 to 173 s per attack on CPU
  in the earlier run; see `results/live.json` for the current figures.
- No authentication on the orchestrator: it binds to localhost and assumes a single trusted operator.
- IPv4 only.

## 6. What would make it stronger

1. An independent red team (not the authors) writing the guardrail test cases.
2. A real attack tool for C2 (for example a Sliver or Mythic lab) instead of simulated beacons.
3. A learned or statistical check on attribution, to close T7.
4. A real Snort/Suricata container so signatures are loaded, not only parsed.
5. Per-source CICIDS data (the 2017 release has IPs) to test windowed detection on public traffic.
