"""Typed contracts passed between the three tiers.

Tier 1 emits an :class:`Alert` (never raw packets or flows). Tier 2 turns it into a
:class:`Mitigation`. Tier 3 returns a :class:`GuardrailVerdict`. Everything is recorded on an
:class:`Incident`.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from enum import StrEnum
from ipaddress import IPv4Address
from typing import Any, Literal

from pydantic import BaseModel, Field


@dataclass(slots=True)
class Flow:
    """One connection record, normalised from Zeek conn.log or a CICIDS2018 CSV row."""

    ts: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    proto: str            # tcp | udp | icmp
    duration: float       # seconds
    fwd_bytes: int        # originator -> responder payload bytes
    bwd_bytes: int
    fwd_pkts: int
    bwd_pkts: int
    syn: bool             # originator sent a SYN
    ack: bool             # originator completed the handshake with an ACK
    rst: bool
    conn_state: str = ""
    label: str = ""       # ground truth (evaluation only; never shown to the LLM)


class AlertFeatures(BaseModel):
    """Compact, numeric description of one source's behaviour inside a time window."""

    window_seconds: float
    n_flows: int
    n_tcp: int
    n_udp: int
    n_dst_hosts: int
    n_dst_ports: int
    top_dst_ports: list[int]
    dominant_port_share: float
    syn_count: int
    ack_count: int
    syn_ack_ratio: float      # TCP SYN_in / TCP ACK_out  (half-open ratio from the slides)
    half_open_frac: float     # SYN seen, handshake never completed
    rej_frac: float           # connection rejected / reset by the responder
    flows_per_s: float
    mean_duration_s: float
    fwd_bytes: int
    bwd_bytes: int
    mean_fwd_bytes: float
    iat_cv: float             # coefficient of variation of inter-arrival times (beaconing)


class DetectorOutput(BaseModel):
    rules: list[str] = Field(default_factory=list)
    ml_score: float | None = None
    ml_threshold: float | None = None
    ml_anomaly: bool = False


class Alert(BaseModel):
    alert_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    source_ip: IPv4Address
    dst_ips: list[IPv4Address] = Field(default_factory=list)
    first_seen: float
    last_seen: float
    detected_at: float = Field(default_factory=time.time)
    detector: DetectorOutput
    features: AlertFeatures
    raw_flow_count: int = 0
    raw_bytes: int = 0        # size of the raw telemetry this alert summarises
    origin: Literal["zeek", "cicids", "replay", "test"] = "zeek"
    ground_truth: str | None = None  # evaluation only; stripped before prompting

    def llm_view(self) -> dict[str, Any]:
        """What the LLM is allowed to see: typed numbers and validated IPs only."""
        return self.model_dump(mode="json", exclude={"ground_truth", "raw_bytes", "origin", "alert_id"})


class Mitigation(BaseModel):
    """Structured output the LLM must produce."""

    incident_summary: str
    attack_type: str
    mitre_technique_id: str
    mitre_technique_name: str = ""
    mitre_tactic: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    iptables_rule: str
    snort_rule: str = ""       # optional; if absent, a signature is rendered from the verified decision


class GuardrailCheck(BaseModel):
    stage: str                 # policy | subnet | conflict | kernel
    passed: bool
    detail: str
    retryable: bool = True     # False -> escalate to a human instead of asking the LLM again
    elapsed_ms: float = 0.0


class GuardrailVerdict(BaseModel):
    passed: bool
    checks: list[GuardrailCheck]
    rule: str
    argv: list[str] = Field(default_factory=list)       # validated argv for deployment
    restore_line: str = ""                               # rule in iptables-restore syntax

    @property
    def failure(self) -> GuardrailCheck | None:
        return next((c for c in self.checks if not c.passed), None)


class Status(StrEnum):
    QUEUED = "QUEUED"
    ANALYZING = "ANALYZING"
    SAFE = "SAFE"               # verified; waiting for analyst approval
    DEPLOYED = "DEPLOYED"
    ESCALATED = "ESCALATED"     # no safe rule could be produced -> human
    REJECTED = "REJECTED"       # analyst rejected
    DUPLICATE = "DUPLICATE"     # source already blocked
    ERROR = "ERROR"


class Attempt(BaseModel):
    number: int
    llm_seconds: float
    prompt_chars: int
    raw_output: str
    mitigation: Mitigation | None = None
    error: str | None = None             # schema / grounding problem
    verdict: GuardrailVerdict | None = None


class RetrievedDoc(BaseModel):
    mitre_id: str
    name: str
    tactics: list[str]
    score: float


class RetrievalTrace(BaseModel):
    query: str
    candidate_tactics: list[str]
    candidates: int
    total_docs: int
    search_space_reduction: float
    docs: list[RetrievedDoc]
    cves: list[dict[str, str]] = Field(default_factory=list)
    seconds: float = 0.0


class Incident(BaseModel):
    incident_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:10])
    alert: Alert
    status: Status = Status.QUEUED
    times: dict[str, float] = Field(default_factory=dict)   # stage -> epoch seconds
    retrieval: RetrievalTrace | None = None
    attempts: list[Attempt] = Field(default_factory=list)
    mitigation: Mitigation | None = None
    verdict: GuardrailVerdict | None = None
    grounded: bool | None = None
    escalation_reason: str | None = None
    deploy_output: str | None = None
    snort_rule: str | None = None          # drop signature for an inline IPS (static-checked, not loaded)
    snort_source: str | None = None        # "llm" | "template"
    snort_check: GuardrailCheck | None = None

    def mark(self, stage: str) -> None:
        self.times[stage] = time.time()
