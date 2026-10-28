"""The agent loop gives the same result through a LangChain model as through the direct client."""

import pytest

pytest.importorskip("langchain_core")

from langchain_core.language_models.fake_chat_models import FakeListChatModel  # noqa: E402

from hrt.agent.analyst import AnalystAgent  # noqa: E402
from hrt.config import get_settings  # noqa: E402
from hrt.guardrail.pipeline import Guardrail  # noqa: E402
from hrt.llm.langchain import LangChainLLM  # noqa: E402
from hrt.models import Status  # noqa: E402
from tests.test_agent_loop import FakeSandbox, StubRetriever, _mit  # noqa: E402


def _agent(replies):
    gr = Guardrail(get_settings(), sandbox=FakeSandbox(), deployed_rules=lambda: [])
    llm = LangChainLLM(model=FakeListChatModel(responses=replies))
    return AnalystAgent(llm, gr, StubRetriever(), use_rag=True, max_attempts=3)


def test_langchain_first_try(scan_alert):
    inc = _agent([_mit()]).analyze(scan_alert)
    assert inc.status == Status.SAFE and len(inc.attempts) == 1 and inc.grounded


def test_langchain_self_correction(scan_alert):
    bad = _mit(rule="iptables INPUT -s 203.0.113.9 -j DROP")        # missing -A/-I
    inc = _agent([bad, _mit()]).analyze(scan_alert)
    assert inc.status == Status.SAFE and len(inc.attempts) == 2


def test_provider_name():
    assert LangChainLLM(model=FakeListChatModel(responses=["{}"])).name.startswith("langchain:")
