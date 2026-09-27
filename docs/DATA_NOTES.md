# Data notes & integrity

## MITRE ATT&CK STIX tactic labels

The `enterprise-attack.json` STIX bundle obtained on the build network (both from the old project
copy and via a fresh download from the official `mitre-attack/attack-stix-data` raw URL — verified
byte-identical, SHA-256 `dc1639ca…c3d8f4`) carries **two non-canonical ATT&CK tactic labels**:

| In this bundle | Canonical MITRE ATT&CK tactic |
|---|---|
| `stealth` | `defense-evasion` |
| `defense-impairment` | `defense-evasion` |

The real ATT&CK Enterprise matrix has 14 tactics and includes `defense-evasion`; it has no
`stealth` or `defense-impairment` tactic. Every other tactic label matches. The **technique
content itself — IDs, names, descriptions, detections, mitigations — is authentic**; only these
tactic labels were altered, and the download URL on this network returns this modified copy.

### How the pipeline handles it

`hrt.rag.ingest.canonical_tactic()` folds `stealth` and `defense-impairment` back to
`defense-evasion` at ingestion time, so the vector store, dashboard and report use standard MITRE
tactic names. On an authoritative bundle this mapping is a no-op.

None of HRT-Agent's Tier-1 detection rules map to the defense-evasion tactic, so this issue does
not affect attack attribution for the scenarios evaluated (scanning→discovery/reconnaissance,
floods→impact, brute force→credential-access, beaconing→command-and-control, exfiltration→
exfiltration). Retrieval ranks techniques by the cosine similarity of their authentic text, so the
coarse tactic prefilter is not the sole determinant of a match.

## Windows Smart App Control and the ML stack

Partway through the project, Windows **Smart App Control** on the build machine moved from
*Evaluation* to *On* (enforce) mode — Windows does this automatically at the end of the
evaluation period (`HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy\VerifiedAndReputablePolicyState`
= 1). It blocks unsigned binaries that lack cloud reputation. Because this project runs on
**Python 3.14** (very new, so its wheels have few installs), it blocked some of scikit-learn's
compiled extensions (Code Integrity events 3033/3077), e.g.
`sklearn/metrics/cluster/_expected_mutual_info_fast.cp314-win_amd64.pyd` and
`sklearn/utils/_sorting.cp314-win_amd64.pyd`. Importing PyOD or most of scikit-learn fails.

How the project handles it, without changing any security setting:

- `hrt.triage.detector` imports PyOD **lazily** — only when an Isolation Forest is fitted or
  loaded. The live triage engine runs on the deterministic rules, which need no compiled ML
  code, so live detection, the orchestrator, the RAG agent and the guardrail are unaffected.
- The CICIDS2018 detection results in `results/triage.json` (Isolation Forest, SIEM rules,
  Random Forest) were produced with PyOD/scikit-learn **before** enforcement began; they are
  real measurements.
- `tests/test_detector.py::test_iforest_flags_scan_not_benign` skips with an explicit reason
  when the ML stack can't load.

To restore the full ML stack on this machine the options are: turn Smart App Control off
(Windows Security → App & browser control; note it **cannot be re-enabled without reinstalling
Windows**), or run the project on Python 3.12/3.13, whose wheels have established reputation.
That choice belongs to the machine owner; the project does not change security settings.

## CICIDS2018

The "Processed Traffic Data for ML Algorithms" CSVs contain flow features but **no source/destination
IP columns**. Consequences, both documented in the report:

- Tier-1 detection is evaluated at the **flow level** (benign vs malicious per flow), not by
  per-source windowing.
- Agent incidents synthesised from CICIDS flows are assigned **synthetic TEST-NET-2 (198.51.100.0/24)
  attacker addresses** so the guardrail and rule-synthesis stages have a concrete IP to act on.

### How the sample was obtained (bandwidth-bounded)

The full processed dataset is ~1.3 GB and this build network delivered the AWS bucket at
**~50 KB/s** (a full download would take ~7 hours). Instead, `hrt.eval.cicids_data` streams
**targeted HTTP-Range slices** of three attack days. A Range request skips earlier bytes without
downloading them, and probing showed where each day's attack and benign zones sit in the
time-ordered files:

| Day | Slice start | Cap | Contents |
|---|---|---|---|
| Wednesday-14-02-2018 | 30% | 16 MB | FTP-BruteForce, SSH-Bruteforce |
| Wednesday-14-02-2018 | 62% | 8 MB | Benign |
| Friday-16-02-2018 | 30% | 16 MB | DoS-Hulk + Benign |
| Wednesday-21-02-2018 | 30% | 14 MB | DDoS-HOIC |
| Wednesday-21-02-2018 | 62% | 8 MB | Benign |

About 62 MB in total. The slices are normalised, de-duplicated, and stratified-sampled (≤ 15,000
benign, ≤ 5,000 per attack class) into `data/cicids2018/cicids_sample.parquet`, giving **34,105
flows**: Benign 15,000; DDoS-HOIC 5,000; DoS-Hulk 5,000; SSH-Bruteforce 5,000; FTP-BruteForce 4,105.
No raw CSV is kept on disk. On a fast link, raise the caps in `SLICE_PLAN` or add days (for example
`fri-02-03` for Bot traffic).

## Live lab services and process lifetime

The daemons (Ollama, orchestrator, triage) and long evaluations are started through the launchers
in `scripts/*.cmd`, each opening a minimized console window with output logged to `data/logs/`.
They must be started the way a user would, by double-clicking or via `explorer.exe`: processes
launched from inside an automation session (a scripted PowerShell `Start-Process`, or WMI
`Win32_Process.Create`) were torn down together with that session. Close the minimized
"HRT - ..." windows to stop the services.

## Agent (RAG-ablation) evaluation run

`results/agent.json` comes from `hrt eval agent --fast` on 2026-09-27 (12:35 to 13:14, 40 min):
3 synthesised incidents per class for 4 classes (DDoS-HOIC, DoS-Hulk, FTP-BruteForce,
SSH-Bruteforce), each class given its own TEST-NET-2 attacker (brute force 198.51.100.11, DoS .21,
DDoS .31). Each incident goes through all three modes, `rag_hier`, `rag_flat` and `no_rag`, with the
same local model (`llama3.2:3b`) and the real guardrail, including the kernel sandbox.

- An earlier attempt at 11:52 stopped after about a minute, before finishing any incident. The
  Ollama server stopped at the same moment, Docker Desktop was later also found stopped, and no log
  shows an error.
  It is kept as `data/logs/agent.failed-1153.log`. The run above is a clean relaunch.
- That run recorded only aggregate metrics. Per-incident rows (`details`: technique, tactic,
  attempts, status) are recorded from now on. To show what the no-RAG model actually answers, a
  separate 4-incident probe (`scripts/probe_norag.py`) was run afterwards. Its output is
  `results/agent_probe_norag.txt`. It reproduces the aggregate picture: wrong or non-existent
  technique IDs (for example `T1110.001` for a DDoS, or `T1210.001`, which does not exist) and
  non-tactic strings in the tactic field.

## Lab capture used for the telemetry measurement

`results/telemetry.json` was measured on the Zeek capture accumulated during the live benchmark on
2026-09-26 (634,464 records, 241.9 MB). **Zeek truncates `data/zeek/conn.log` whenever the lab starts**,
so that capture was overwritten when the lab was restarted on 2026-09-27 to record the dashboard
screenshot for the deck. The measured numbers remain in `results/telemetry.json`. To reproduce them,
run the live benchmark again and then `hrt eval telemetry`. The absolute counts will differ; the
per-alert reduction depends only on the alert type. If a capture needs to be kept, copy
`data/zeek/conn.log` somewhere safe before running `hrt lab up`.
