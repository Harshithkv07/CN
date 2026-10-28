"""LangChain-backed LLM (optional; ``pip install hrt-agent[langchain]``).

The brief suggests LangChain for orchestration. The default pipeline calls Ollama directly, which keeps every
step visible in one short file. This adapter routes the model call through a LangChain runnable
(``chat_model | StrOutputParser``), so the same retrieve -> prompt -> validate -> guardrail -> retry loop can
run on any LangChain chat model (Ollama, a hosted API, or a fake model in tests) without touching the agent:
select it with ``HRT_LLM_PROVIDER=langchain``.
"""

from __future__ import annotations

import time

from hrt.config import Settings
from hrt.llm.base import LLMResponse

_ROLES = {"system": "system", "user": "human", "assistant": "ai"}


class LangChainLLM:
    def __init__(self, settings: Settings | None = None, model=None):
        from langchain_core.output_parsers import StrOutputParser

        if model is None:
            from langchain_ollama import ChatOllama

            from hrt.llm.ollama import ensure_server

            ensure_server(settings)
            model = ChatOllama(model=settings.ollama_model, base_url=settings.ollama_url, temperature=0.1, seed=7,
                               num_ctx=settings.llm_num_ctx, num_predict=settings.llm_num_predict, keep_alive="30m")
        self.model = model
        self.parser = StrOutputParser()
        self.name = f"langchain:{getattr(model, 'model', None) or type(model).__name__}"

    def chat(self, messages: list[dict[str, str]], schema: dict | None = None) -> LLMResponse:
        runnable = self.model.bind(format=schema) if schema is not None and hasattr(self.model, "format") else self.model
        msgs = [(_ROLES[m["role"]], m["content"]) for m in messages]
        t0 = time.perf_counter()
        reply = runnable.invoke(msgs)
        text = self.parser.invoke(reply)
        usage = getattr(reply, "usage_metadata", None) or {}
        return LLMResponse(text=text, seconds=time.perf_counter() - t0, prompt_tokens=usage.get("input_tokens", 0),
                           completion_tokens=usage.get("output_tokens", 0))
