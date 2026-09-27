from hrt.config import Settings
from hrt.llm.base import LLM, LLMResponse


def make_llm(settings: Settings) -> LLM:
    if settings.llm_provider == "fake":
        from hrt.llm.fake import FakeLLM

        return FakeLLM()
    from hrt.llm.ollama import OllamaLLM

    return OllamaLLM(settings)


__all__ = ["LLM", "LLMResponse", "make_llm"]
