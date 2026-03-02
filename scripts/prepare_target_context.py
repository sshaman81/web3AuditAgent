from __future__ import annotations

import argparse
from pathlib import Path
from typing import Iterable


def _slurp_file(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _find_files(root: Path, patterns: Iterable[str]) -> list[Path]:
    matches: list[Path] = []
    for pattern in patterns:
        matches.extend(root.glob(pattern))
    return matches


def build_context(repo_path: Path, main_contract: Path | None = None) -> str:
    repo_path = repo_path.resolve()
    lines: list[str] = ["Target codebase context", f"Path: {repo_path}", ""]

    readme_candidates = [repo_path / "README.md", repo_path / "README.txt"]
    for candidate in readme_candidates:
        if candidate.is_file():
            lines.append("README:")
            lines.append(_slurp_file(candidate))
            lines.append("")
            break

    if main_contract:
        main_candidate = repo_path / main_contract
        if main_candidate.is_file():
            lines.append(f"Primary contract ({main_contract}):")
            lines.append(_slurp_file(main_candidate))
            lines.append("")

    sol_files = _find_files(repo_path, ("contracts/**/*.sol", "*.sol"))
    lines.append("All discovered Solidity files:")
    for sol in sorted({p.resolve() for p in sol_files}):
        rel = sol.relative_to(repo_path)
        lines.append(f"\n--- {rel} ---")
        lines.append(_slurp_file(sol))
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare a target codebase context file for the audit agent.")
    parser.add_argument("repo", type=Path, help="Path to the target repository root.")
    parser.add_argument("--main", type=Path, help="Relative path to the main Solidity file to highlight.")
    parser.add_argument("--output", type=Path, default=Path("target_context.txt"), help="Destination for the context text.")
    args = parser.parse_args()

    context = build_context(repo_path=args.repo, main_contract=args.main)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(context, encoding="utf-8")
    print(f"Wrote target context to {args.output}")


if __name__ == "__main__":
    main()
