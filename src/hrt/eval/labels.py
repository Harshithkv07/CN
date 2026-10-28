"""Ground-truth mapping for evaluation.

CICIDS2018 labels and lab attack kinds map to (attack family, acceptable MITRE technique IDs,
expected Tier-1 rule). A predicted technique is 'correct' if it's in the acceptable set for the
true label. Acceptable sets are deliberately small and defensible.
"""

from __future__ import annotations

# CICIDS2018 "Label" value -> evaluation spec
CIC_LABELS: dict[str, dict] = {
    "Benign": {"family": "benign", "malicious": False, "techniques": [], "tactic": None},
    "FTP-BruteForce": {"family": "brute_force", "malicious": True,
                       "techniques": ["T1110", "T1110.001", "T1110.003"], "tactic": "credential-access"},
    "SSH-Bruteforce": {"family": "brute_force", "malicious": True,
                       "techniques": ["T1110", "T1110.001", "T1110.003"], "tactic": "credential-access"},
    "DoS attacks-Hulk": {"family": "dos", "malicious": True,
                         "techniques": ["T1499", "T1499.002", "T1498"], "tactic": "impact"},
    "DoS attacks-SlowHTTPTest": {"family": "dos", "malicious": True,
                                 "techniques": ["T1499", "T1499.001"], "tactic": "impact"},
    "DoS attacks-GoldenEye": {"family": "dos", "malicious": True,
                              "techniques": ["T1499", "T1499.002"], "tactic": "impact"},
    "DoS attacks-Slowloris": {"family": "dos", "malicious": True,
                              "techniques": ["T1499", "T1499.001"], "tactic": "impact"},
    "DDOS attack-HOIC": {"family": "ddos", "malicious": True,
                         "techniques": ["T1498", "T1498.001", "T1499", "T1499.002"], "tactic": "impact"},
    "DDOS attack-LOIC-UDP": {"family": "ddos", "malicious": True,
                             "techniques": ["T1498", "T1498.001", "T1499"], "tactic": "impact"},
    "DDoS attacks-LOIC-HTTP": {"family": "ddos", "malicious": True,
                               "techniques": ["T1498", "T1499", "T1499.002"], "tactic": "impact"},
    "Bot": {"family": "botnet", "malicious": True,
            "techniques": ["T1071", "T1071.001", "T1102", "T1571"], "tactic": "command-and-control"},
    "Infilteration": {"family": "infiltration", "malicious": True,
                      "techniques": ["T1041", "T1071", "T1105"], "tactic": "exfiltration"},
    "Brute Force -Web": {"family": "web_attack", "malicious": True,
                         "techniques": ["T1110", "T1190"], "tactic": "credential-access"},
    "Brute Force -XSS": {"family": "web_attack", "malicious": True,
                         "techniques": ["T1190", "T1059"], "tactic": "initial-access"},
    "SQL Injection": {"family": "web_attack", "malicious": True,
                      "techniques": ["T1190"], "tactic": "initial-access"},
}

# lab attack kind -> spec (used by live and agent evaluation)
LAB_ATTACKS: dict[str, dict] = {
    "scan": {"family": "recon", "techniques": ["T1046", "T1595", "T1595.001", "T1595.002"],
             "tactic": "discovery", "rule": "PORT_SCAN"},
    "synflood": {"family": "dos", "techniques": ["T1499", "T1499.001", "T1499.002", "T1498"],
                 "tactic": "impact", "rule": "SYN_FLOOD"},
    "connflood": {"family": "dos", "techniques": ["T1499", "T1499.002", "T1498"],
                  "tactic": "impact", "rule": "CONN_FLOOD"},
    "beacon": {"family": "c2", "techniques": ["T1071", "T1071.001", "T1102", "T1571", "T1008"],
               "tactic": "command-and-control", "rule": "BEACONING"},
    "sshbf": {"family": "brute_force", "techniques": ["T1110", "T1110.001", "T1110.003"],
              "tactic": "credential-access", "rule": "BRUTE_FORCE"},
}


def normalise_label(raw: str) -> str:
    return raw.strip()


def is_malicious(label: str) -> bool:
    spec = CIC_LABELS.get(normalise_label(label))
    return bool(spec and spec["malicious"])


def technique_ok(label_or_kind: str, predicted_id: str, table: dict) -> bool:
    spec = table.get(label_or_kind)
    if not spec:
        return False
    acc = spec["techniques"]
    base = predicted_id.split(".")[0]
    return predicted_id in acc or base in acc or any(a.split(".")[0] == base for a in acc)
