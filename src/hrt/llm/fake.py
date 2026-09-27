"""Deterministic LLM stand-in for tests and load experiments (no model needed)."""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable

from hrt.llm.base import LLMResponse


def _default_reply(messages: list[dict[str, str]]) -> str:
    """Blocks the source IP from the alert and cites the first retrieved technique."""
    user = next(m["content"] for m in messages if m["role"] == "user")
    ip = re.search(r'"source_ip":\s*"([\d.]+)"', user)
    tid = re.search(r"\b(T\d{4}(?:\.\d{3})?)\b", user)
    return json.dumps({
        "incident_summary": "Automated test incident.",
        "attack_type": "test",
        "mitre_technique_id": tid.group(1) if tid else "T1046",
        "mitre_technique_name": "",
        "mitre_tactic": "discovery",
        "confidence": 0.5,
        "evidence": ["fake"],
        "recommended_actions": ["block source"],
        "iptables_rule": f"iptables -I INPUT -s {ip.group(1) if ip else '198.51.100.1'} -j DROP",
    })


class FakeLLM:
    name = "fake"

    def __init__(self, replies: list[str] | Callable[[list[dict[str, str]]], str] | None = None, delay: float = 0.0):
        self.replies = replies
        self.delay = delay
        self.calls: list[list[dict[str, str]]] = []

    def chat(self, messages: list[dict[str, str]], schema: dict | None = None) -> LLMResponse:
        self.calls.append(messages)
        if self.delay:
            time.sleep(self.delay)
        if isinstance(self.replies, list) and self.replies:
            text = self.replies.pop(0)
        elif callable(self.replies):
            text = self.replies(messages)
        else:
            text = _default_reply(messages)
        return LLMResponse(text=text, seconds=self.delay)
