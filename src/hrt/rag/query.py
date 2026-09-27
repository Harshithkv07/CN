"""Turn a numeric Tier-1 alert into a natural-language behaviour query and ATT&CK tactic candidates.

This replaces the old hardcoded "network scanning" string: the query now describes what was
actually observed.
"""

from __future__ import annotations

from hrt.models import Alert
from hrt.triage.rules import tactics_for

SERVICES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    123: "NTP", 143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 1433: "MSSQL",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 8000: "HTTP-alt", 8080: "HTTP-proxy",
    8443: "HTTPS-alt",
}


def service_name(port: int) -> str:
    return SERVICES.get(port, f"port {port}")


def candidate_tactics(alert: Alert) -> list[str]:
    """Deterministic tactic prefilter (the first level of the hierarchical RAG)."""
    return tactics_for(alert.detector.rules)


# Security-semantic lead sentences per Tier-1 pattern. These describe the adversary behaviour in
# the vocabulary MITRE ATT&CK technique descriptions use, so cosine retrieval lands on the right
# technique (e.g. "scanning service ports to discover running services" -> T1046/T1595).
_PATTERN_QUERY = {
    "PORT_SCAN": "Port scanning reconnaissance: one source probed many different destination service "
                 "ports on the target with half-open TCP SYN connections to discover which network "
                 "services are running and listening. Active scanning and network service discovery.",
    "HOST_SWEEP": "Network sweep reconnaissance: one source probed the same service port across many "
                  "hosts to enumerate live systems. Active scanning of IP blocks and remote system discovery.",
    "SYN_FLOOD": "Denial-of-service SYN flood: a high volume of half-open TCP SYN connections flood a "
                 "service to exhaust its resources and deny availability. Endpoint denial of service / network DoS.",
    "CONN_FLOOD": "Denial-of-service flood: a very high rate of connections overwhelms a single service "
                  "to exhaust resources and deny availability. Endpoint denial of service.",
    "UDP_FLOOD": "Volumetric UDP flood denial-of-service: high-rate UDP traffic overwhelms the target to "
                 "deny availability. Network denial of service.",
    "BRUTE_FORCE": "Credential brute-force: repeated short authentication attempts against a login "
                   "service to guess valid credentials by password guessing or spraying.",
    "SLOW_DOS": "Slow denial-of-service: many long-lived low-throughput connections hold a web service "
                "open to exhaust its connection pool. Endpoint denial of service application exhaustion.",
    "BEACONING": "Command-and-control beaconing: periodic small connections at regular intervals to a "
                 "single remote host, characteristic of malware C2 check-in over an application protocol.",
    "EXFILTRATION": "Data exfiltration: an unusually large outbound data transfer to a remote host, "
                    "consistent with stealing data over the network.",
}


def behaviour_query(alert: Alert) -> str:
    f = alert.features
    proto = "TCP" if f.n_tcp >= f.n_udp else "UDP"
    ports = ", ".join(f"{p} ({service_name(p)})" for p in f.top_dst_ports[:3])
    # Lead with the security-semantic description of the strongest matched pattern.
    parts = [_PATTERN_QUERY[name] for name in alert.detector.rules if name in _PATTERN_QUERY][:2]
    if not parts:
        parts = ["Anomalous network activity from a single source, statistically deviating from the "
                 "benign baseline; possible reconnaissance, denial of service, or command and control."]
    # Then the quantitative evidence.
    parts.append(f"Observed over {f.window_seconds:.0f}s: {f.n_flows} {proto} flows to {f.n_dst_hosts} "
                 f"host(s) across {f.n_dst_ports} destination port(s); most targeted {ports}.")
    if f.n_tcp and f.half_open_frac >= 0.3:
        parts.append(f"{f.half_open_frac:.0%} half-open TCP (SYN without completed handshake), "
                     f"SYN/ACK ratio {f.syn_ack_ratio:.1f}.")
    if f.rej_frac >= 0.3:
        parts.append(f"{f.rej_frac:.0%} rejected or reset by the target.")
    if f.flows_per_s >= 10:
        parts.append(f"About {f.flows_per_s:.0f} flows per second.")
    if f.n_flows >= 8 and f.iat_cv <= 0.25:
        parts.append("Highly regular inter-arrival timing.")
    return " ".join(parts)


def cve_query(alert: Alert) -> str:
    services = [service_name(p) for p in alert.features.top_dst_ports[:2]]
    return f"remote vulnerability in network service {' '.join(services)} server"
