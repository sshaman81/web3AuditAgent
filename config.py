from pydantic import Field
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    recon_model: str = Field("claude-haiku-4-5", env="RECON_MODEL")
    audit_model: str = Field("claude-sonnet-4-5", env="AUDIT_MODEL")
    exploit_model: str = Field("claude-opus-4-5", env="EXPLOIT_MODEL")
    max_hypotheses: int = Field(5, env="MAX_HYPOTHESES")
    max_forge_log_chars: int = Field(8000, env="MAX_FORGE_LOG_CHARS")
    forge_timeout_seconds: int = Field(120, env="FORGE_TIMEOUT_SECONDS")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
