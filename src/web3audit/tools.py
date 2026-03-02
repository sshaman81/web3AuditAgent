from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Optional, TypedDict

import requests
from langchain.tools import tool


class FoundryResult(TypedDict):
    success: bool
    exit_code: int | None
    stdout: str
    stderr: str
    truncated: bool
    duration_seconds: float


class GasUsage(TypedDict):
    test_name: str
    gas_used: int


class TenderlyResult(TypedDict):
    success: bool
    status_code: int
    simulation_id: str
    gas_used: int
    state_diff: dict[str, Any]
    raw: dict[str, Any]


def _truncate_end(text: str, limit: int) -> tuple[str, bool]:
    if len(text) <= limit:
        return text, False
    return text[-limit:], True


def _ensure_within_sandbox(path: Path, sandbox_root: Path) -> None:
    if not path.is_relative_to(sandbox_root):
        raise ValueError(f"Refusing to write outside sandbox: {path}")


def resolve_fork_url(
    explicit_fork_url: Optional[str] = None,
    mode: str = "off",
    anvil_rpc_url: Optional[str] = None,
) -> Optional[str]:
    if mode == "off":
        return None
    if mode == "anvil":
        url = (anvil_rpc_url or os.getenv("ANVIL_RPC_URL") or "http://127.0.0.1:8545").strip()
        return url

    if explicit_fork_url and explicit_fork_url.strip():
        return explicit_fork_url.strip()

    for env_name in ("FORGE_FORK_URL", "ALCHEMY_MAINNET_URL", "INFURA_MAINNET_URL"):
        value = os.getenv(env_name)
        if value and value.strip():
            return value.strip()
    return None


def _build_forge_command(
    fork_url: Optional[str],
) -> list[str]:
    cmd = ["forge", "test", "--match-path", "test/AgentExploit.t.sol", "-vvvv"]
    if fork_url:
        cmd.extend(["--fork-url", fork_url])
    return cmd


def extract_gas_usage(stdout: str) -> list[GasUsage]:
    gas_entries: list[GasUsage] = []
    patterns = [
        re.compile(r"\[PASS\]\s+([^\(\n]+)\([^\)]*\)\s+\(gas:\s*([0-9_]+)\)", re.IGNORECASE),
        re.compile(r"Gas\s+Used\s*:\s*([0-9_]+)", re.IGNORECASE),
    ]

    for line in stdout.splitlines():
        for pattern in patterns:
            match = pattern.search(line)
            if not match:
                continue
            if len(match.groups()) == 2:
                test_name = match.group(1).strip()
                gas_value = int(match.group(2).replace("_", ""))
            else:
                test_name = "unknown_test"
                gas_value = int(match.group(1).replace("_", ""))
            gas_entries.append(GasUsage(test_name=test_name, gas_used=gas_value))
            break

    return gas_entries


def simulate_with_tenderly(
    network_id: str,
    from_address: str,
    to_address: str,
    input_data: str,
    value: str = "0x0",
    gas: int = 8_000_000,
) -> TenderlyResult:
    account = os.getenv("TENDERLY_ACCOUNT")
    project = os.getenv("TENDERLY_PROJECT")
    access_key = os.getenv("TENDERLY_ACCESS_KEY")
    if not all([account, project, access_key]):
        raise RuntimeError("Tenderly credentials are missing")

    url = f"https://api.tenderly.co/api/v1/account/{account}/project/{project}/simulate"
    payload = {
        "network_id": network_id,
        "from": from_address,
        "to": to_address,
        "input": input_data,
        "value": value,
        "gas": gas,
        "save": False,
        "save_if_fails": True,
    }
    headers = {
        "X-Access-Key": access_key,
        "Content-Type": "application/json",
    }

    response = requests.post(url, json=payload, headers=headers, timeout=30)
    body = response.json() if response.content else {}
    sim = body.get("simulation", {}) if isinstance(body, dict) else {}

    return TenderlyResult(
        success=response.ok,
        status_code=response.status_code,
        simulation_id=str(sim.get("id", "")),
        gas_used=int(sim.get("gas_used", 0) or 0),
        state_diff=sim.get("state_diff", {}) if isinstance(sim, dict) else {},
        raw=body if isinstance(body, dict) else {},
    )


@tool("execute_foundry_poc")
def execute_foundry_poc(
    solidity_code: str,
    timeout_seconds: int,
    max_chars: int,
    fork_url: Optional[str] = None,
    sandbox_dir: str = "foundry_sandbox",
    fork_mode: str = "off",
    anvil_rpc_url: Optional[str] = None,
) -> FoundryResult:
    """Execute Solidity PoC test code via forge test in a constrained sandbox path."""
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be > 0")
    if max_chars <= 0:
        raise ValueError("max_chars must be > 0")

    if shutil.which("forge") is None:
        raise RuntimeError(
            "Foundry/forge not found. Install Foundry (https://book.getfoundry.sh/) "
            "and ensure `forge` is on your PATH before running PoCs."
        )

    sandbox_path = Path(sandbox_dir).resolve()
    sandbox_path.mkdir(parents=True, exist_ok=True)

    test_dir = (sandbox_path / "test").resolve()
    _ensure_within_sandbox(test_dir, sandbox_path)
    test_dir.mkdir(parents=True, exist_ok=True)

    test_file = (test_dir / "AgentExploit.t.sol").resolve()
    _ensure_within_sandbox(test_file, sandbox_path)
    test_file.write_text(solidity_code, encoding="utf-8")

    resolved_fork_url = resolve_fork_url(
        explicit_fork_url=fork_url,
        mode=fork_mode,
        anvil_rpc_url=anvil_rpc_url,
    )

    cmd = _build_forge_command(fork_url=resolved_fork_url)

    start = time.monotonic()
    try:
        result = subprocess.run(
            cmd,
            cwd=sandbox_path,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        exit_code = result.returncode
        stdout, stdout_truncated = _truncate_end(result.stdout, max_chars)
        stderr, stderr_truncated = _truncate_end(result.stderr, max_chars)
        truncated = stdout_truncated or stderr_truncated
    except subprocess.TimeoutExpired as exc:
        exit_code = None
        stdout, _ = _truncate_end(exc.stdout or "", max_chars)
        stderr, _ = _truncate_end(exc.stderr or "", max_chars)
        truncated = True

    duration = time.monotonic() - start

    return FoundryResult(
        success=exit_code == 0,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        truncated=truncated,
        duration_seconds=duration,
    )