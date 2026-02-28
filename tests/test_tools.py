import subprocess
from types import SimpleNamespace

import pytest

from tools import execute_foundry_poc


def _stub_forge(monkeypatch):
    monkeypatch.setattr("tools.shutil.which", lambda _: "/usr/bin/forge")


def test_execute_foundry_poc_success(monkeypatch):
    _stub_forge(monkeypatch)

    def fake_run(*args, **kwargs):
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr("tools.subprocess.run", fake_run)
    result = execute_foundry_poc.func("contract Foo {}", timeout_seconds=1, max_chars=20)
    assert result["success"]
    assert result["exit_code"] == 0
    assert "ok" in result["stdout"]
    assert not result["truncated"]


def test_execute_foundry_poc_failure_truncation(monkeypatch):
    _stub_forge(monkeypatch)

    def fake_run(*args, **kwargs):
        return SimpleNamespace(returncode=1, stdout="X" * 128, stderr="ERR")

    monkeypatch.setattr("tools.subprocess.run", fake_run)
    result = execute_foundry_poc.func("contract Foo {}", timeout_seconds=1, max_chars=10)
    assert not result["success"]
    assert result["exit_code"] == 1
    assert result["stdout"] == "X" * 10
    assert result["truncated"]


def test_execute_foundry_poc_timeout(monkeypatch):
    _stub_forge(monkeypatch)

    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(
            cmd=kwargs.get("cmd", "forge"),
            timeout=kwargs.get("timeout", 1),
            output="partial",
            stderr="timeout",
        )

    monkeypatch.setattr("tools.subprocess.run", fake_run)
    result = execute_foundry_poc.func("contract Foo {}", timeout_seconds=1, max_chars=20)
    assert not result["success"]
    assert result["exit_code"] is None
    assert result["truncated"]
    assert "partial" in result["stdout"]
