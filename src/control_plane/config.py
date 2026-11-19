"""Runtime settings, read from environment variables (and a local `.env` file)."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="SCP_", env_file=".env", extra="ignore", populate_by_name=True
    )

    data_dir: Path = Path("data")
    policy_path: Path = Path("policy/policy.yaml")
    ui_dir: Path = Path("ui/dist")

    max_prompt_chars: int = 20_000
    detection_timeout_s: float = 15.0
    spacy_model: str = "en_core_web_md"

    # The in-boundary model. "stub" is a labelled stand-in for running without Ollama.
    sovereign_provider: Literal["ollama", "stub"] = "ollama"
    ollama_url: str = "http://localhost:11434"
    sovereign_model: str = "llama3.2:1b"

    # The external model. "auto" uses Anthropic when a key is set and the stub otherwise.
    external_provider: Literal["auto", "anthropic", "stub"] = "auto"
    external_model: str = "claude-opus-5-5"
    external_refusal_fallback: bool = True
    anthropic_api_key: SecretStr | None = Field(default=None, validation_alias="ANTHROPIC_API_KEY")

    model_timeout_s: float = 300.0

    @property
    def max_body_bytes(self) -> int:
        # Worst case four bytes per character, doubled for JSON escapes, plus the envelope.
        return self.max_prompt_chars * 8 + 1024
