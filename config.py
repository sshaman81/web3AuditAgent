from __future__ import annotations

from typing import Optional

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

VALID_MODELS = {
    "claude-3-5-haiku-20241022",
    "claude-3-5-sonnet-20241022",
    "claude-3-opus-20240229",
}


class Settings(BaseSettings):
    recon_model: str = Field("claude-3-5-haiku-20241022", validation_alias="RECON_MODEL")
    audit_model: str = Field("claude-3-5-sonnet-20241022", validation_alias="AUDIT_MODEL")
    exploit_model: str = Field("claude-3-opus-20240229", validation_alias="EXPLOIT_MODEL")

    max_hypotheses: int = Field(5, validation_alias="MAX_HYPOTHESES")
    max_parallel_hypotheses: int = Field(3, validation_alias="MAX_PARALLEL_HYPOTHESES")
    max_forge_log_chars: int = Field(8000, validation_alias="MAX_FORGE_LOG_CHARS")
    forge_timeout_seconds: int = Field(120, validation_alias="FORGE_TIMEOUT_SECONDS")
    forge_fork_url: Optional[str] = Field(default=None, validation_alias="FORGE_FORK_URL")

    max_node_attempts: int = Field(6, validation_alias="MAX_NODE_ATTEMPTS")
    circuit_breaker_failure_threshold: int = Field(3, validation_alias="CB_FAILURE_THRESHOLD")
    circuit_breaker_recovery_seconds: int = Field(45, validation_alias="CB_RECOVERY_SECONDS")

    code_context_token_limit: int = Field(32000, validation_alias="CODE_CONTEXT_TOKEN_LIMIT")

    log_level: str = Field("INFO", validation_alias="LOG_LEVEL")
    log_json: bool = Field(True, validation_alias="LOG_JSON")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    @field_validator("recon_model", "audit_model", "exploit_model")
    @classmethod
    def validate_model_name(cls, value: str) -> str:
        if value not in VALID_MODELS:
            raise ValueError(f"Unsupported model '{value}'. Allowed: {sorted(VALID_MODELS)}")
        return value

    @field_validator("forge_timeout_seconds")
    @classmethod
    def validate_forge_timeout(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("FORGE_TIMEOUT_SECONDS must be > 0")
        return value

    @field_validator("max_hypotheses")
    @classmethod
    def validate_max_hypotheses(cls, value: int) -> int:
        if value <= 0 or value > 10:
            raise ValueError("MAX_HYPOTHESES must be between 1 and 10")
        return value

    @field_validator("max_parallel_hypotheses")
    @classmethod
    def validate_parallel_hypotheses(cls, value: int) -> int:
        if value <= 0 or value > 10:
            raise ValueError("MAX_PARALLEL_HYPOTHESES must be between 1 and 10")
        return value

    @field_validator("max_node_attempts", "circuit_breaker_failure_threshold", "circuit_breaker_recovery_seconds")
    @classmethod
    def validate_positive_ints(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("Configuration values must be > 0")
        return value

    @field_validator("forge_fork_url")
    @classmethod
    def validate_fork_url(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        cleaned = value.strip()
        if not cleaned:
            return None
        if not (cleaned.startswith("http://") or cleaned.startswith("https://")):
            raise ValueError("FORGE_FORK_URL must start with http:// or https://")
        return cleaned

    @field_validator("log_level")
    @classmethod
    def normalize_log_level(cls, value: str) -> str:
        normalized = value.strip().upper()
        if normalized not in {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}:
            raise ValueError("LOG_LEVEL must be one of CRITICAL, ERROR, WARNING, INFO, DEBUG")
        return normalized

    @model_validator(mode="after")
    def validate_parallel_not_exceed_max(self) -> "Settings":
        if self.max_parallel_hypotheses > self.max_hypotheses:
            raise ValueError("MAX_PARALLEL_HYPOTHESES cannot exceed MAX_HYPOTHESES")
        return self


settings = Settings()
