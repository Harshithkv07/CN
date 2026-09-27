from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass
class LLMResponse:
    text: str
    seconds: float
    prompt_tokens: int = 0
    completion_tokens: int = 0


class LLM(Protocol):
    name: str

    def chat(self, messages: list[dict[str, str]], schema: dict | None = None) -> LLMResponse: ...
