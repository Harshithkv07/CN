"""Central configuration. Every value can be overridden with an ``HRT_*`` env var or a ``.env`` file."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="HRT_", env_file=PROJECT_ROOT / ".env", extra="ignore")

    # --- paths -------------------------------------------------------------------------
    root: Path = PROJECT_ROOT
    data_dir: Path = PROJECT_ROOT / "data"
    results_dir: Path = PROJECT_ROOT / "results"

    # --- Tier 1: telemetry triage ------------------------------------------------------
    window_seconds: float = 10.0          # sliding window per source IP
    alert_cooldown_seconds: float = 30.0   # suppress repeat alerts for the same source
    benign_score_quantile: float = 0.995   # IForest threshold = this quantile of benign scores

    # --- Tier 2: RAG + LLM ------------------------------------------------------------
    llm_provider: str = "ollama"           # "ollama" | "fake"
    ollama_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "llama3.2:3b"
    ollama_exe: Path = Path("D:/Ollama/app/ollama.exe")
    ollama_models_dir: Path = Path("D:/Ollama/models")
    llm_timeout_seconds: float = 600.0
    llm_num_ctx: int = 6144
    retrieval_top_k: int = 5
    max_attempts: int = 3

    # --- Tier 3: guardrail + sandbox ---------------------------------------------------
    # Critical assets the agent must never block, checked with bitwise AND in guardrail/subnet.py.
    # These are specific infrastructure/known-good hosts, not the whole LAN: that way a single
    # compromised internal host can still be contained, while blocking the gateway, the protected
    # server, a known-good client, loopback -- or any range broad enough to include them -- is
    # refused as a self-inflicted DoS. See docs/DATA_NOTES.md (threat model).
    protected_subnets: list[str] = Field(
        default_factory=lambda: [
            "10.10.0.1/32",      # lab gateway (blocking it isolates the whole segment)
            "10.10.0.10/32",     # the protected server itself
            "10.10.0.50/32",     # a known-good internal client
            "127.0.0.0/8",       # loopback
            "0.0.0.0/32",
        ]
    )
    min_source_prefix: int = 24            # reject blocks broader than a /24 (e.g. /23, /16, /8, /0)
    sandbox_image: str = "hrt-sandbox:latest"
    victim_container: str = "hrt-victim"
    auto_deploy: bool = False              # gated deployment: a human approves by default

    # --- orchestrator ----------------------------------------------------------------
    host: str = "127.0.0.1"
    port: int = 8000

    # --- derived paths -----------------------------------------------------------------
    @property
    def zeek_dir(self) -> Path:
        return self.data_dir / "zeek"

    @property
    def conn_log(self) -> Path:
        return self.zeek_dir / "conn.log"

    @property
    def models_dir(self) -> Path:
        return self.data_dir / "models"

    @property
    def chroma_dir(self) -> Path:
        return self.data_dir / "chroma"

    @property
    def mitre_stix(self) -> Path:
        return self.data_dir / "mitre" / "enterprise-attack.json"

    @property
    def kev_json(self) -> Path:
        return self.data_dir / "cve" / "known_exploited_vulnerabilities.json"

    @property
    def cicids_dir(self) -> Path:
        return self.data_dir / "cicids2018"

    @property
    def lab_dir(self) -> Path:
        return self.data_dir / "lab"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "hrt.sqlite3"

    @property
    def baseline_rules(self) -> Path:
        return self.root / "docker" / "victim" / "baseline.rules"

    @property
    def webhook_url(self) -> str:
        return f"http://{self.host}:{self.port}/webhook/alert"


@lru_cache
def get_settings() -> Settings:
    return Settings()
