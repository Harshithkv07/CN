"""The Tier-2 -> Tier-3 loop: retrieve, prompt, validate, verify, then self-correct or escalate.

::

    alert -> hierarchical retrieval -> LLM (JSON schema) -> schema check -> ID + grounding check
          -> guardrail (policy, subnet, conflict, kernel) -> SAFE
             on a retryable failure: the reason goes back to the LLM (at most ``max_attempts`` tries)
             on a non-retryable failure or out of tries: ESCALATED to a human
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable

from pydantic import ValidationError

from hrt.agent.prompts import MITIGATION_SCHEMA, build_messages, correction, correction_for
from hrt.guardrail.pipeline import Guardrail
from hrt.llm.base import LLM
from hrt.models import Alert, Attempt, Incident, Mitigation, RetrievalTrace, Status
from hrt.rag.retriever import Retriever

log = logging.getLogger("hrt.agent")
_ID = re.compile(r"T\d{4}(?:\.\d{3})?")


def extract_json(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        text = text.removeprefix("json").strip()
    start, end = text.find("{"), text.rfind("}")
    return text[start: end + 1] if start != -1 and end > start else text


def normalise_id(raw: str) -> str:
    m = _ID.search((raw or "").upper().replace(" ", ""))
    return m.group(0) if m else (raw or "").strip()


def grounded(tid: str, trace: RetrievalTrace | None) -> bool:
    if trace is None:
        return False
    ids = {d.mitre_id for d in trace.docs}
    return tid in ids or tid.split(".")[0] in ids or any(i.split(".")[0] == tid for i in ids)


class AnalystAgent:
    def __init__(self, llm: LLM, guardrail: Guardrail, retriever: Retriever | None, use_rag: bool = True,
                 top_k: int = 5, max_attempts: int = 3, hierarchical: bool = True,
                 on_update: Callable[[Incident], None] | None = None):
        self.llm, self.guardrail, self.retriever = llm, guardrail, retriever
        self.use_rag = use_rag and retriever is not None
        self.top_k, self.max_attempts, self.hierarchical = top_k, max_attempts, hierarchical
        self.on_update = on_update or (lambda inc: None)

    def analyze(self, alert: Alert, incident: Incident | None = None) -> Incident:
        inc = incident or Incident(alert=alert)
        inc.status = Status.ANALYZING
        inc.mark("analysis_started")
        self.on_update(inc)

        texts: list[str] = []
        if self.use_rag:
            inc.retrieval, texts = self.retriever.retrieve(alert, self.top_k, self.hierarchical)
            inc.mark("retrieved")
            self.on_update(inc)

        messages = build_messages(alert, inc.retrieval if self.use_rag else None, texts)
        last_error = "no attempt made"
        for n in range(1, self.max_attempts + 1):
            try:
                resp = self.llm.chat(messages, MITIGATION_SCHEMA)
            except Exception as exc:  # LLM server down, timeout, ...
                inc.status, inc.escalation_reason = Status.ERROR, f"LLM call failed: {exc}"
                break
            attempt = Attempt(number=n, llm_seconds=round(resp.seconds, 3),
                              prompt_chars=sum(len(m["content"]) for m in messages), raw_output=resp.text)
            inc.attempts.append(attempt)
            inc.mark(f"llm_{n}")
            messages = [*messages, {"role": "assistant", "content": resp.text}]

            try:
                mit = Mitigation.model_validate(json.loads(extract_json(resp.text)))
            except (json.JSONDecodeError, ValidationError) as exc:
                attempt.error = last_error = f"schema: {str(exc).splitlines()[0][:200]}"
                messages.append({"role": "user", "content": correction("schema", attempt.error)})
                self.on_update(inc)
                continue
            mit.mitre_technique_id = normalise_id(mit.mitre_technique_id)
            attempt.mitigation = inc.mitigation = mit

            if self.use_rag:
                tid = mit.mitre_technique_id
                if not self.retriever.known(tid):
                    attempt.error = last_error = f"grounding: {tid} is not a valid ATT&CK Enterprise technique ID"
                elif not grounded(tid, inc.retrieval):
                    ids = ", ".join(d.mitre_id for d in inc.retrieval.docs)
                    attempt.error = last_error = f"grounding: {tid} is not among the retrieved techniques ({ids})"
                if attempt.error:
                    messages.append({"role": "user", "content": correction("grounding", attempt.error)})
                    self.on_update(inc)
                    continue
                inc.grounded = True

            verdict = self.guardrail.check(mit.iptables_rule, str(alert.source_ip))
            attempt.verdict = inc.verdict = verdict
            if verdict.passed:
                inc.status = Status.SAFE
                inc.mark("verified")
                break
            failure = verdict.failure
            last_error = f"{failure.stage}: {failure.detail}"
            if not failure.retryable:
                duplicate = failure.stage == "conflict" and failure.detail.startswith("duplicate")
                inc.status = Status.DUPLICATE if duplicate else Status.ESCALATED
                inc.escalation_reason = last_error
                break
            messages.append({"role": "user", "content": correction_for(failure)})
            self.on_update(inc)
        else:
            inc.status = Status.ESCALATED
            inc.escalation_reason = f"no verified rule after {self.max_attempts} attempts; last error: {last_error}"

        if inc.status == Status.ANALYZING:  # loop exited via a path that set nothing
            inc.status, inc.escalation_reason = Status.ESCALATED, last_error
        inc.mark("finished")
        self.on_update(inc)
        log.info("incident %s %s -> %s", inc.incident_id, alert.source_ip, inc.status)
        return inc
