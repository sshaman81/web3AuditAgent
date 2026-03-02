import pytest
from pydantic import ValidationError

from web3audit.config import Settings


def test_openai_provider_accepts_non_claude_models():
    settings = Settings(
        _env_file=None,
        llm_provider="openai",
        openai_api_key="test-key",
        recon_model="codex-mini-latest",
        audit_model="gpt-5-mini",
        exploit_model="gpt-5",
    )
    assert settings.llm_provider == "openai"
    assert settings.recon_model == "codex-mini-latest"


def test_anthropic_provider_rejects_unknown_models():
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            llm_provider="anthropic",
            anthropic_api_key="test-key",
            recon_model="codex-mini-latest",
            audit_model="claude-3-5-sonnet-20241022",
            exploit_model="claude-3-opus-20240229",
        )


def test_provider_requires_matching_api_key():
    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            llm_provider="openai",
            recon_model="codex-mini-latest",
            audit_model="gpt-5-mini",
            exploit_model="gpt-5",
        )
