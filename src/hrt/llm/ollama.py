"""Local LLM through Ollama's REST API. Output is constrained to a JSON schema.

Ollama is used as a portable install (``D:/Ollama`` by default). If the server isn't running,
:func:`ensure_server` starts ``ollama serve`` with ``OLLAMA_MODELS`` pointing at that folder. No
installer, no auto-start entry and no global env var are needed, so deleting the folder removes it.
"""

from __future__ import annotations

import logging
import os
import subprocess
import time

import httpx

from hrt.config import Settings
from hrt.llm.base import LLMResponse

log = logging.getLogger("hrt.llm")


def server_up(url: str) -> bool:
    try:
        return httpx.get(f"{url}/api/version", timeout=2).status_code == 200
    except httpx.HTTPError:
        return False


def ensure_server(settings: Settings, wait_seconds: float = 45) -> None:
    if server_up(settings.ollama_url):
        return
    exe = settings.ollama_exe
    if not exe.exists():
        raise RuntimeError(f"Ollama is not running and {exe} was not found")
    env = os.environ.copy()
    env["OLLAMA_MODELS"] = str(settings.ollama_models_dir)
    env.setdefault("OLLAMA_HOST", settings.ollama_url.removeprefix("http://"))
    settings.ollama_models_dir.mkdir(parents=True, exist_ok=True)
    logfile = open(settings.ollama_models_dir.parent / "ollama-serve.log", "ab")
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    subprocess.Popen([str(exe), "serve"], env=env, stdout=logfile, stderr=logfile, creationflags=flags)
    deadline = time.time() + wait_seconds
    while time.time() < deadline:
        if server_up(settings.ollama_url):
            log.info("started ollama serve from %s", exe)
            return
        time.sleep(1)
    raise RuntimeError("ollama serve did not come up in time")


class OllamaLLM:
    def __init__(self, settings: Settings, model: str | None = None, temperature: float = 0.1, seed: int = 7):
        self.settings = settings
        self.model = model or settings.ollama_model
        self.name = f"ollama:{self.model}"
        self.options = {"temperature": temperature, "seed": seed, "num_ctx": settings.llm_num_ctx}
        ensure_server(settings)
        self.client = httpx.Client(base_url=settings.ollama_url, timeout=settings.llm_timeout_seconds)

    def chat(self, messages: list[dict[str, str]], schema: dict | None = None) -> LLMResponse:
        body = {"model": self.model, "messages": messages, "stream": False, "options": self.options,
                "keep_alive": "30m"}
        if schema is not None:
            body["format"] = schema
        t0 = time.perf_counter()
        # Self-healing: if the local server died mid-request (connection refused/reset), restart it
        # and retry once, instead of failing the incident.
        for attempt in range(2):
            try:
                r = self.client.post("/api/chat", json=body)
                r.raise_for_status()
                break
            except (httpx.ConnectError, httpx.RemoteProtocolError, httpx.ReadError) as exc:
                if attempt == 1:
                    raise
                log.warning("LLM server connection lost (%s); restarting ollama and retrying", exc)
                ensure_server(self.settings)
        data = r.json()
        return LLMResponse(text=data["message"]["content"], seconds=time.perf_counter() - t0,
                           prompt_tokens=data.get("prompt_eval_count", 0),
                           completion_tokens=data.get("eval_count", 0))
