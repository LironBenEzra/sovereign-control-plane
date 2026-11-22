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
    # The default policy: copied into the data volume on first start, and what "restore
    # default" goes back to. The policy in force is changed through the API, not here.
    policy_path: Path = Path("policy/policy.yaml")
    ui_dir: Path = Path("ui/dist")

    max_prompt_chars: int = 20_000
    # For the prompt and again for the answer. The local LLM judges about 7,500
    # characters in this time on a laptop CPU; a longer text counts as a detector failure.
    detection_timeout_s: float = 30.0
    spacy_model: str = "en_core_web_md"

    # The in-boundary model. "stub" is a labelled stand-in for running without Ollama.
    sovereign_provider: Literal["ollama", "stub"] = "ollama"
    ollama_url: str = "http://localhost:11434"
    # Answers the prompts that stay inside, and is also the semantic detector's model, so
    # one model is downloaded and kept in memory. The detector is off when the sovereign
    # provider is the stub, because then there is no Ollama to run it on.
    sovereign_model: str = "llama3.2:3b"

    # The external model, Anthropic's Claude API. Without ANTHROPIC_API_KEY it is not
    # ready, and prompts the policy lets out are refused.
    # The smallest Claude model. It has no server-side refusal fallback, so none is
    # requested; turn it on only with a model that has one, such as claude-opus-5-5.
    external_model: str = "claude-haiku-5-5"
    external_refusal_fallback: bool = False
    anthropic_api_key: SecretStr | None = Field(default=None, validation_alias="ANTHROPIC_API_KEY")

    model_timeout_s: float = 300.0

    # Needed to change the policy through the API or the UI. Unset or empty: the policy is
    # read-only.
    admin_token: SecretStr | None = None

    # A demo setting: anyone may save or restore the policy, with no token, and each change
    # is recorded as made by "visitor". The admin token still works. Off by default; a real
    # deployment keeps policy changes to admins.
    open_policy_editing: bool = False

    # Set (the hosted demo uses "scp-demo/") to read every secret from AWS Secrets Manager
    # at startup instead: the audit keys, the admin token and the Anthropic key. See
    # control_plane.aws_secrets. Unset, the keys are files on the data volume.
    aws_secrets_prefix: str | None = None

    # Set (the hosted demo uses "alias/scp-demo-audit") to sign the audit log with an
    # Ed25519 key in AWS KMS, which never leaves KMS. See control_plane.aws_kms. Unset,
    # the signing key is a file on the data volume, or a secret under the prefix above.
    audit_kms_key_id: str | None = None

    @property
    def admin_token_value(self) -> str | None:
        # An empty variable (as Compose passes when none is set) means no token.
        return (self.admin_token.get_secret_value() if self.admin_token else "") or None

    @property
    def max_body_bytes(self) -> int:
        # Worst case four bytes per character, doubled for JSON escapes, plus the envelope.
        return self.max_prompt_chars * 8 + 1024
