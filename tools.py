import os
import subprocess
from pathlib import Path

from langchain.tools import tool

OUTPUT_LIMIT = 8000


def _truncate_middle(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    keep = limit - 40
    first = text[: keep // 2]
    last = text[- (keep - keep // 2) :]
    return f"{first}\n... [middle truncated] ...\n{last}"


@tool("execute_foundry_poc")
def execute_foundry_poc(solidity_code: str) -> str:
    sandbox_path = Path("foundry_sandbox")
    test_dir = sandbox_path / "test"
    test_dir.mkdir(parents=True, exist_ok=True)
    test_file = test_dir / "AgentExploit.t.sol"
    test_file.write_text(solidity_code, encoding="utf-8")

    cmd = ["forge", "test", "--match-path", "test/AgentExploit.t.sol", "-vvvv"]
    try:
        result = subprocess.run(
            cmd,
            cwd=sandbox_path,
            capture_output=True,
            text=True,
            timeout=45,
            check=False,
        )
        combined = "STDOUT:\n" + result.stdout + "\nSTDERR:\n" + result.stderr
    except subprocess.TimeoutExpired as exc:
        combined = f"Process timed out after 45s\n
" + exc.stdout + ("\n" + exc.stderr if exc.stderr else "")
    formatted = _truncate_middle(combined, OUTPUT_LIMIT)
    return formatted
