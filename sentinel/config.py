"""Centralised, validated configuration.

Security posture:
* ``SENTINEL_MODE`` is a ``Literal["simulator"]``. There is no live adapter in the
  codebase, so even a tampered configuration cannot reach real infrastructure.
* Live-mode escape hatches are actively rejected (``SENTINEL_ALLOW_LIVE``).
* Production requires an explicitly supplied, sufficiently long JWT secret.
* Development secrets are generated once and stored outside version control.
"""

from __future__ import annotations

import os
import secrets
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from sentinel.errors import ConfigError, SimulationOnlyViolation

Environment = Literal["dev", "test", "prod"]
LlmProvider = Literal["none", "ollama", "openai_compat"]
RagBackend = Literal["bm25", "chroma"]

_FORBIDDEN_LIVE_ENV_VARS = (
    "SENTINEL_ALLOW_LIVE",
    "SENTINEL_LIVE_ENDPOINT",
    "SENTINEL_DOCKER_SOCKET",
    "SENTINEL_KUBECONFIG",
    "SENTINEL_AWS_ACCESS_KEY_ID",
)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SENTINEL_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- runtime ---------------------------------------------------------
    service_name: str = "sentinel-ai"
    environment: Environment = "dev"
    mode: Literal["simulator"] = "simulator"
    log_level: str = "INFO"
    data_dir: Path = Path("data")
    var_dir: Path = Path("var")
    db_path: Path | None = None

    # --- security --------------------------------------------------------
    jwt_secret: SecretStr | None = None
    jwt_issuer: str = "sentinel-ai"
    jwt_audience: str = "sentinel-ui"
    session_ttl_minutes: int = Field(default=30, ge=5, le=720)
    login_rate_limit_per_minute: int = Field(default=5, ge=1, le=120)
    login_lockout_minutes: int = Field(default=5, ge=1, le=120)
    api_rate_limit_per_minute: int = Field(default=240, ge=10, le=100_000)
    max_request_bytes: int = Field(default=262_144, ge=4096, le=10_485_760)
    cors_origins: list[str] = Field(default_factory=list)
    dev_admin_username: str = "admin"
    dev_admin_password: SecretStr | None = None

    # --- simulator / remediation ----------------------------------------
    auto_remediate: bool = True
    max_restore_attempts: int = Field(default=2, ge=0, le=5)
    worker_threads: int = Field(default=2, ge=1, le=8)
    strict_baseline_integrity: bool = True
    simulator_faults: Path = Path("data/sim/faults.json")
    scan_interval_seconds: int = Field(default=0, ge=0, le=3600)

    # --- AI --------------------------------------------------------------
    llm_provider: LlmProvider = "none"
    llm_base_url: str | None = None
    llm_model: str | None = None
    llm_api_key: SecretStr | None = None
    llm_timeout_seconds: float = Field(default=20.0, ge=1.0, le=120.0)
    llm_max_output_tokens: int = Field(default=1200, ge=128, le=8192)

    # --- RAG -------------------------------------------------------------
    rag_backend: RagBackend = "bm25"
    rag_top_k: int = Field(default=4, ge=1, le=12)
    embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2"
    allow_model_download: bool = False

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_origins(cls, value: object) -> object:
        if value is None or value == "":
            return []
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value

    @field_validator("log_level")
    @classmethod
    def _valid_log_level(cls, value: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = value.upper()
        if upper not in allowed:
            raise ValueError(f"log level must be one of {sorted(allowed)}")
        return upper

    @model_validator(mode="after")
    def _enforce_security_posture(self) -> Settings:
        for name in _FORBIDDEN_LIVE_ENV_VARS:
            if os.environ.get(name):
                raise SimulationOnlyViolation(
                    f"{name} is set. SENTINEL AI is simulator-only and refuses to start "
                    "when live-infrastructure configuration is present."
                )

        if self.environment == "prod":
            secret = self.jwt_secret.get_secret_value() if self.jwt_secret else ""
            if len(secret) < 32:
                raise ConfigError(
                    "SENTINEL_JWT_SECRET (>=32 chars) is mandatory when "
                    "SENTINEL_ENVIRONMENT=prod"
                )
            if not self.strict_baseline_integrity:
                raise ConfigError("strict baseline integrity cannot be disabled in production")
            if any(not origin.startswith("https://") for origin in self.cors_origins):
                raise ConfigError("production CORS origins must use https://")

        if self.llm_provider == "openai_compat" and not self.llm_base_url:
            raise ConfigError("SENTINEL_LLM_BASE_URL is required for openai_compat")
        if self.llm_provider == "ollama" and not self.llm_base_url:
            self.llm_base_url = "http://127.0.0.1:11434"
        return self

    # --- derived paths ---------------------------------------------------
    @property
    def raw_dir(self) -> Path:
        return self.data_dir / "raw"

    @property
    def knowledge_dir(self) -> Path:
        return self.data_dir / "knowledge"

    @property
    def quarantine_dir(self) -> Path:
        return self.var_dir / "quarantine"

    @property
    def resolved_db_path(self) -> Path:
        return self.db_path or (self.var_dir / "sentinel.db")

    def ensure_directories(self) -> None:
        for path in (self.var_dir, self.raw_dir, self.quarantine_dir, self.resolved_db_path.parent):
            path.mkdir(parents=True, exist_ok=True)

    def resolved_jwt_secret(self) -> str:
        """Return the JWT signing secret, generating a dev-only secret if needed."""
        if self.jwt_secret is not None:
            value = self.jwt_secret.get_secret_value()
            if len(value) < 32:
                raise ConfigError("JWT secret must be at least 32 characters")
            return value

        if self.environment == "prod":
            raise ConfigError("JWT secret is not configured")

        secret_file = self.var_dir / ".jwt_secret"
        if secret_file.exists():
            value = secret_file.read_text(encoding="utf-8").strip()
            if len(value) >= 32:
                return value
        secret_file.parent.mkdir(parents=True, exist_ok=True)
        value = secrets.token_urlsafe(48)
        secret_file.write_text(value, encoding="utf-8")
        try:  # best effort on Windows; no-op on POSIX if unsupported
            secret_file.chmod(0o600)
        except OSError:  # pragma: no cover - platform dependent
            pass
        return value

    @property
    def is_dev(self) -> bool:
        return self.environment in {"dev", "test"}


def assert_simulator_only(settings: Settings) -> None:
    """Defence-in-depth guard called at every process boundary.

    Independent of any user-supplied request: the process refuses to start if a
    live-infrastructure indicator is present, regardless of API payloads.
    """
    if settings.mode != "simulator":
        raise SimulationOnlyViolation("only simulator mode is supported")
    for name in _FORBIDDEN_LIVE_ENV_VARS:
        if os.environ.get(name):
            raise SimulationOnlyViolation(f"live-infrastructure variable {name} is set")
    # A live adapter must never be importable in this build.
    from sentinel.simulator import backend as simulator_backend

    if getattr(simulator_backend, "EXECUTION_BACKEND", None) != "simulator":
        raise SimulationOnlyViolation("execution backend is not the simulator")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    settings = Settings()
    settings.ensure_directories()
    return settings


def reset_settings_cache() -> None:
    """Test helper: re-read environment variables."""
    get_settings.cache_clear()
