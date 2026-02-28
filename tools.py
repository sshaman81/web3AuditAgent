import shutil
import subprocess
import time
from pathlib import Path
from typing import TypedDict

from langchain.tools import tool


class FoundryResult(TypedDict):
    success: bool
    exit_code: int | None
    stdout: str
    stderr: str
    truncated: bool
    duration_seconds: float


def _truncate_end(text: str, limit: int) -> tuple[str, bool]:
    if len(text) <= limit:
        return text, False
    return text[-limit:], True


@tool("execute_foundry_poc")
def execute_foundry_poc(
    solidity_code: str,
    timeout_seconds: int,
    max_chars: int,
) -> FoundryResult:
    """Execute the provided Solidity PoC with Forge and return stdout/exit metadata."""
    if shutil.which("forge") is None:
        raise RuntimeError(
            "Foundry/forge not found. Install Foundry (https://book.getfoundry.sh/) "
            "and ensure `forge` is on your PATH before running PoCs."
        )

    sandbox_path = Path("foundry_sandbox")
    test_dir = sandbox_path / "test"
    test_dir.mkdir(parents=True, exist_ok=True)
    test_file = test_dir / "AgentExploit.t.sol"
    test_file.write_text(solidity_code, encoding="utf-8")

    cmd = [
        "forge",
        "test",
        "--match-path",
        "test/AgentExploit.t.sol",
        "--no-match-test",
        "--fork-url",
        "",
        "-vvvv",
    ]

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
