from __future__ import annotations

from typing import Literal, Optional

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

VALID_MODELS = {
    "claude-3-5-haiku-20241022",
    "claude-3-5-sonnet-20241022",
    "claude-3-opus-20240229",
}

ForkMode = Literal["off", "mainnet", "anvil"]


class Settings(BaseSettings):
    recon_model: str = Field("claude-3-5-haiku-20241022", validation_alias="RECON_MODEL")
    audit_model: str = Field("claude-3-5-sonnet-20241022", validation_alias="AUDIT_MODEL")
    exploit_model: str = Field("claude-3-opus-20240229", validation_alias="EXPLOIT_MODEL")

    fast_mode: bool = Field(True, validation_alias="FAST_MODE")
    skip_known_contract_types: bool = Field(True, validation_alias="SKIP_KNOWN_CONTRACT_TYPES")

    max_hypotheses: int = Field(2, validation_alias="MAX_HYPOTHESES")
    max_parallel_hypotheses: int = Field(2, validation_alias="MAX_PARALLEL_HYPOTHESES")
    max_parallel_contracts: int = Field(10, validation_alias="MAX_PARALLEL_CONTRACTS")

    max_forge_log_chars: int = Field(8000, validation_alias="MAX_FORGE_LOG_CHARS")
    forge_timeout_seconds: int = Field(30, validation_alias="FORGE_TIMEOUT_SECONDS")

    forge_mode: ForkMode = Field("anvil", validation_alias="FORGE_MODE")
    forge_fork_url: Optional[str] = Field(default=None, validation_alias="FORGE_FORK_URL")
    alchemy_mainnet_url: Optional[str] = Field(default=None, validation_alias="ALCHEMY_MAINNET_URL")
    infura_mainnet_url: Optional[str] = Field(default=None, validation_alias="INFURA_MAINNET_URL")
    anvil_rpc_url: str = Field("http://127.0.0.1:8545", validation_alias="ANVIL_RPC_URL")

    triage_timeout_seconds: int = Field(10, validation_alias="TRIAGE_TIMEOUT_SECONDS")
    code_context_token_limit: int = Field(28000, validation_alias="CODE_CONTEXT_TOKEN_LIMIT")

    max_node_attempts: int = Field(6, validation_alias="MAX_NODE_ATTEMPTS")
    circuit_breaker_failure_threshold: int = Field(3, validation_alias="CB_FAILURE_THRESHOLD")
    circuit_breaker_recovery_seconds: int = Field(45, validation_alias="CB_RECOVERY_SECONDS")

    cache_db_path: str = Field("./audit_cache.sqlite3", validation_alias="CACHE_DB_PATH")

    immunefi_api_base: str = Field("https://immunefi.com", validation_alias="IMMUNEFI_API_BASE")
    immunefi_api_key: Optional[str] = Field(default=None, validation_alias="IMMUNEFI_API_KEY")
    hackenproof_api_base: str = Field("https://hackenproof.com", validation_alias="HACKENPROOF_API_BASE")
    hackenproof_api_key: Optional[str] = Field(default=None, validation_alias="HACKENPROOF_API_KEY")
    cantina_base_url: str = Field("https://cantina.xyz", validation_alias="CANTINA_BASE_URL")

    tenderly_enabled: bool = Field(False, validation_alias="TENDERLY_ENABLED")
    tenderly_account: Optional[str] = Field(default=None, validation_alias="TENDERLY_ACCOUNT")
    tenderly_project: Optional[str] = Field(default=None, validation_alias="TENDERLY_PROJECT")
    tenderly_access_key: Optional[str] = Field(default=None, validation_alias="TENDERLY_ACCESS_KEY")

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

    @field_validator(
        "forge_timeout_seconds",
        "triage_timeout_seconds",
        "max_node_attempts",
        "circuit_breaker_failure_threshold",
        "circuit_breaker_recovery_seconds",
    )
    @classmethod
    def validate_positive_ints(cls, value: int) -> int:
        if value <= 0:
            raise ValueError("Configuration value must be > 0")
        return value

    @field_validator("max_hypotheses", "max_parallel_hypotheses")
    @classmethod
    def validate_hypothesis_limits(cls, value: int) -> int:
        if value <= 0 or value > 10:
            raise ValueError("Hypothesis limits must be between 1 and 10")
        return value

    @field_validator("max_parallel_contracts")
    @classmethod
    def validate_parallel_contracts(cls, value: int) -> int:
        if value <= 0 or value > 50:
            raise ValueError("MAX_PARALLEL_CONTRACTS must be between 1 and 50")
        return value

    @field_validator("forge_fork_url", "alchemy_mainnet_url", "infura_mainnet_url")
    @classmethod
    def validate_urls(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        cleaned = value.strip()
        if not cleaned:
            return None
        if not cleaned.startswith(("http://", "https://")):
            raise ValueError("RPC URLs must start with http:// or https://")
        return cleaned

    @field_validator("anvil_rpc_url")
    @classmethod
    def validate_anvil_rpc_url(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned.startswith(("http://", "https://")):
            raise ValueError("ANVIL_RPC_URL must start with http:// or https://")
        return cleaned

    @field_validator("log_level")
    @classmethod
    def normalize_log_level(cls, value: str) -> str:
        normalized = value.strip().upper()
        if normalized not in {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}:
            raise ValueError("LOG_LEVEL must be one of CRITICAL, ERROR, WARNING, INFO, DEBUG")
        return normalized

    @model_validator(mode="after")
    def validate_cross_fields(self) -> "Settings":
        if self.max_parallel_hypotheses > self.max_hypotheses:
            raise ValueError("MAX_PARALLEL_HYPOTHESES cannot exceed MAX_HYPOTHESES")
        if self.forge_mode == "mainnet" and not (self.forge_fork_url or self.alchemy_mainnet_url or self.infura_mainnet_url):
            raise ValueError("FORGE_MODE=mainnet requires FORGE_FORK_URL or ALCHEMY_MAINNET_URL or INFURA_MAINNET_URL")
        if self.tenderly_enabled and not (self.tenderly_account and self.tenderly_project and self.tenderly_access_key):
            raise ValueError("Tenderly enabled but account/project/access key missing")
        return self


settings = Settings()
