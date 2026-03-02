#!/usr/bin/env python3
"""
harvest_context.py — Web3 codebase harvester and utility helpers for LLM auditing.
Concatenates protocol files into an LLM-ready context file and exposes helpers such as
fetch_contract_source with retry-aware rate-limit handling.
"""

import argparse
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional, TypeVar

import requests
from requests.exceptions import RequestException

# ── ANSI colours (auto-disabled if not a TTY) ────────────────────────────────
USE_COLOR = sys.stdout.isatty()
def c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text

GREEN  = lambda t: c("92", t)
YELLOW = lambda t: c("93", t)
RED    = lambda t: c("91", t)
CYAN   = lambda t: c("96", t)
BOLD   = lambda t: c("1",  t)
DIM    = lambda t: c("2",  t)

# ── Defaults ─────────────────────────────────────────────────────────────────
# Shared ignore dirs
IGNORE_DIRS_COMMON: set[str] = {
    ".git", "dist", "build", "coverage", ".yarn",
}

# EVM / Solidity-specific ignores
IGNORE_DIRS_EVM: set[str] = {
    "node_modules", "lib", "out", "cache",
    "broadcast", "artifacts", "typechain-types",
    ".forge-cache",
}

# Rust-specific ignores  ← new
IGNORE_DIRS_RUST: set[str] = {
    "target",           # compiled output (can be huge)
    ".cargo",           # local cargo cache
    "node_modules",     # JS tooling sometimes present in Anchor projects
}

# Combined by default; narrowed per project type at runtime
IGNORE_DIRS: set[str] = IGNORE_DIRS_COMMON | IGNORE_DIRS_EVM | IGNORE_DIRS_RUST

# ── Extension sets ────────────────────────────────────────────────────────────
EVM_EXTENSIONS: set[str] = {".sol", ".md"}

RUST_EXTENSIONS: set[str] = {".rs", ".md"}          # ← new

OPTIONAL_EXTENSIONS: dict[str, set[str]] = {
    "abi":    {".json"},
    "config": {".toml", ".yaml", ".yml"},            # Cargo.toml lives here too
    "ts":     {".ts", ".js"},
    "rust":   RUST_EXTENSIONS,                       # ← new flag
}

ETHERSCAN_API_URLS: dict[str, str] = {
    "mainnet": "https://api.etherscan.io/api",
    "goerli": "https://api-goerli.etherscan.io/api",
}

T = TypeVar("T")

class RateLimitError(RuntimeError):
    pass

# Rough tokens-per-char ratio for GPT/Claude models
CHARS_PER_TOKEN = 3.8

# Thresholds for colour-coded token warnings
WARN_TOKENS  = 80_000
LIMIT_TOKENS = 200_000

# ── Bug-bounty Rust vulnerability hint categories ─────────────────────────────
RUST_BUG_BOUNTY_HINTS = """
RUST / WEB3 BUG-BOUNTY FOCUS AREAS
------------------------------------
When reviewing Rust-based Web3 code, prioritise the following vulnerability
classes commonly found in Solana (Anchor/native), CosmWasm, and Substrate:

  ARITHMETIC & NUMERIC
  • Integer overflow / underflow (use checked_*, saturating_*, or u128 casts)
  • Precision loss in fixed-point math (token amounts, exchange rates)
  • Division-before-multiplication ordering errors

  ACCOUNT / STATE VALIDATION  (Solana-specific)
  • Missing owner checks — verify account.owner == expected_program_id
  • Missing signer checks — verify account.is_signer
  • Unchecked account discriminator (Anchor: #[account] constraint bypasses)
  • Re-initialisation attacks (init vs init_if_needed misuse)
  • Arbitrary CPI — calling user-supplied program IDs without validation
  • Sysvar spoofing — using raw AccountInfo instead of typed sysvars
  • PDA seed collisions / canonical bump not enforced

  ACCESS CONTROL
  • Missing authority / admin checks before privileged operations
  • Mutable borrow of shared state allowing reentrancy-like patterns
  • Cross-program invocation (CPI) privilege escalation

  COSMWASM-SPECIFIC
  • execute / instantiate / migrate entry-point auth gaps
  • Reply-handler state inconsistencies
  • Unvalidated CosmWasm message fields

  SUBSTRATE-SPECIFIC
  • Incorrect Weight annotations causing DoS
  • Unsafe storage migrations
  • Off-by-one errors in pallet logic

  GENERAL
  • Logic errors in token minting / burning / transfer paths
  • Flashloan-style single-transaction exploits
  • Timestamp / slot manipulation dependencies
  • Missing event emission after critical state changes
  • Unnecessary use of unsafe {} blocks

"""

# ── Data classes ──────────────────────────────────────────────────────────────
@dataclass
class FileEntry:
    rel_path: Path
    abs_path: Path
    size_bytes: int
    line_count: int
    char_count: int

    @property
    def token_estimate(self) -> int:
        return int(self.char_count / CHARS_PER_TOKEN)

    @property
    def ext(self) -> str:
        return self.abs_path.suffix.lower()


@dataclass
class HarvestStats:
    files: list[FileEntry] = field(default_factory=list)
    skipped_binary: int = 0
    skipped_too_large: int = 0
    errors: int = 0
    project_type: str = "unknown"     # ← new: "evm" | "rust" | "mixed"

    @property
    def total_chars(self) -> int:
        return sum(f.char_count for f in self.files)

    @property
    def total_tokens(self) -> int:
        return int(self.total_chars / CHARS_PER_TOKEN)

    @property
    def total_lines(self) -> int:
        return sum(f.line_count for f in self.files)


def _retry_with_backoff(
    func: Callable[[], T],
    retries: int = 3,
    base_delay: float = 1.0,
) -> T:
    for attempt in range(1, retries + 1):
        try:
            return func()
        except (RequestException, RateLimitError) as exc:
            if attempt == retries:
                raise
            delay = min(60, base_delay * 2 ** (attempt - 1))
            time.sleep(delay)




# ── Project-type auto-detection ───────────────────────────────────────────────
def detect_project_type(target: Path) -> str:
    """
    Heuristic: presence of Cargo.toml → Rust; foundry.toml / hardhat → EVM.
    Returns 'rust', 'evm', or 'mixed'.
    """
    has_cargo    = any(target.rglob("Cargo.toml"))
    has_solidity = any(target.rglob("*.sol"))

    if has_cargo and has_solidity:
        return "mixed"
    if has_cargo:
        return "rust"
    return "evm"


# ── Extension set builder ─────────────────────────────────────────────────────
def build_extension_set(args: argparse.Namespace, project_type: str) -> set[str]:
    # Start from EVM defaults
    exts = set(EVM_EXTENSIONS)

    # Auto-add Rust extensions based on detected type or explicit flag
    if project_type in ("rust", "mixed") or getattr(args, "rust", False):
        exts |= RUST_EXTENSIONS
        # Always pull in Cargo.toml / workspace manifests for Rust projects
        exts.add(".toml")

    for flag, ext_set in OPTIONAL_EXTENSIONS.items():
        if getattr(args, f"include_{flag}", False):
            exts |= ext_set

    if args.extensions:
        for e in args.extensions:
            exts.add(e if e.startswith(".") else f".{e}")

    return exts


# ── Core helpers ──────────────────────────────────────────────────────────────
def is_binary(path: Path, sample_size: int = 1024) -> bool:
    try:
        with open(path, "rb") as f:
            return b"\x00" in f.read(sample_size)
    except OSError:
        return True


def collect_files(
    target: Path,
    allowed_exts: set[str],
    max_file_kb: Optional[int],
    project_type: str,
) -> tuple[list[FileEntry], int, int, int]:
    entries: list[FileEntry] = []
    skip_bin = skip_large = errors = 0

    # Pick the right ignore-dir set for the project
    if project_type == "rust":
        ignore = IGNORE_DIRS_COMMON | IGNORE_DIRS_RUST
    elif project_type == "evm":
        ignore = IGNORE_DIRS_COMMON | IGNORE_DIRS_EVM
    else:  # mixed or unknown — be conservative
        ignore = IGNORE_DIRS

    for root, dirs, files in os.walk(target):
        dirs[:] = sorted(d for d in dirs if d not in ignore)

        for fname in sorted(files):
            abs_path = Path(root) / fname
            rel_path = abs_path.relative_to(target)

            if abs_path.suffix.lower() not in allowed_exts:
                continue

            # Skip Cargo.lock (large, not useful for audit)
            if fname == "Cargo.lock":
                continue

            size_bytes = abs_path.stat().st_size

            if max_file_kb and size_bytes > max_file_kb * 1024:
                print(f"  {YELLOW('SKIP (too large)')} {rel_path}  ({size_bytes // 1024} KB)")
                skip_large += 1
                continue

            if is_binary(abs_path):
                print(f"  {YELLOW('SKIP (binary)')} {rel_path}")
                skip_bin += 1
                continue

            try:
                content = abs_path.read_text(encoding="utf-8", errors="replace")
                entries.append(FileEntry(
                    rel_path=rel_path,
                    abs_path=abs_path,
                    size_bytes=size_bytes,
                    line_count=content.count("\n") + 1,
                    char_count=len(content),
                ))
            except Exception as e:
                print(f"  {RED('ERROR')} reading {rel_path}: {e}")
                errors += 1

    return entries, skip_bin, skip_large, errors


def sort_entries(entries: list[FileEntry], project_type: str) -> list[FileEntry]:
    """
    EVM:   .sol first → .md → everything else
    Rust:  .rs first  → Cargo.toml → .md → everything else
    Mixed: .sol → .rs → Cargo.toml → .md → everything else
    """
    if project_type == "rust":
        priority = {".rs": 0, ".toml": 1, ".md": 2}
    elif project_type == "mixed":
        priority = {".sol": 0, ".rs": 1, ".toml": 2, ".md": 3}
    else:
        priority = {".sol": 0, ".md": 1}

    return sorted(entries, key=lambda e: (priority.get(e.ext, 99), str(e.rel_path)))


# ── Output writer ─────────────────────────────────────────────────────────────
def write_output(
    target: Path,
    entries: list[FileEntry],
    output_path: Path,
    stats: HarvestStats,
    bug_bounty: bool,
) -> None:
    type_label = {
        "evm":   "EVM / Solidity",
        "rust":  "Rust (Solana / CosmWasm / Substrate)",
        "mixed": "Mixed EVM + Rust",
    }.get(stats.project_type, "Web3")

    with open(output_path, "w", encoding="utf-8") as out:

        # ── LLM Primer ───────────────────────────────────────────────────────
        out.write("=" * 72 + "\n")
        out.write("AUDIT CONTEXT — AI SYSTEM PRIMER\n")
        out.write("=" * 72 + "\n")
        out.write(
            f"This file is a concatenated snapshot of a {type_label} protocol\n"
            "codebase, prepared for smart contract security analysis"
            + (" and bug bounty hunting" if bug_bounty else "") + ".\n\n"
            "File boundaries are marked with:\n"
            "  ┌─ BEGIN FILE: <path> ─┐\n"
            "  └─ END FILE: <path>   ─┘\n\n"
        )
        if stats.project_type in ("rust", "mixed"):
            out.write(
                "Source files are ordered: Rust (.rs) → Cargo manifests (.toml)\n"
                "→ documentation (.md) → other.\n"
            )
        else:
            out.write(
                "Solidity source files appear first, followed by documentation.\n"
            )
        out.write(
            "Dependency / build directories are excluded.\n"
        )
        out.write("=" * 72 + "\n\n")

        # ── Bug-bounty hints (Rust) ───────────────────────────────────────────
        if bug_bounty and stats.project_type in ("rust", "mixed"):
            out.write(RUST_BUG_BOUNTY_HINTS)
            out.write("=" * 72 + "\n\n")

        # ── Manifest / Table of Contents ──────────────────────────────────────
        out.write("FILE MANIFEST\n")
        out.write("-" * 72 + "\n")
        ext_groups: dict[str, list[FileEntry]] = {}
        for e in entries:
            ext_groups.setdefault(e.ext, []).append(e)

        def ext_sort_key(x: str) -> tuple:
            order = {".sol": 0, ".rs": 1, ".toml": 2, ".md": 3}
            return (order.get(x, 99), x)

        for ext in sorted(ext_groups, key=ext_sort_key):
            out.write(f"\n  {ext.upper()} files ({len(ext_groups[ext])}):\n")
            for e in ext_groups[ext]:
                out.write(f"    {e.rel_path}  [{e.line_count} lines / ~{e.token_estimate:,} tokens]\n")

        out.write(f"\n  TOTAL: {len(entries)} files · "
                  f"{stats.total_lines:,} lines · "
                  f"~{stats.total_tokens:,} estimated tokens\n")
        out.write("-" * 72 + "\n\n")

        # ── File Contents ─────────────────────────────────────────────────────
        for entry in entries:
            content = entry.abs_path.read_text(encoding="utf-8", errors="replace")
            bar_len = max(2, 60 - len(str(entry.rel_path)))
            out.write(f"┌─ BEGIN FILE: {entry.rel_path} " + "─" * bar_len + "┐\n")
            out.write(content)
            if not content.endswith("\n"):
                out.write("\n")
            bar_len2 = max(4, 62 - len(str(entry.rel_path)))
            out.write(f"└─ END FILE: {entry.rel_path} " + "─" * bar_len2 + "┘\n\n")


# ── Summary printer ───────────────────────────────────────────────────────────
def print_summary(stats: HarvestStats, output_path: Path) -> None:
    tokens = stats.total_tokens
    if tokens > LIMIT_TOKENS:
        token_str = RED(f"~{tokens:,} tokens ⚠ OVER LIMIT")
    elif tokens > WARN_TOKENS:
        token_str = YELLOW(f"~{tokens:,} tokens ⚡ approaching limit")
    else:
        token_str = GREEN(f"~{tokens:,} tokens ✓")

    type_display = {
        "evm":   "EVM / Solidity",
        "rust":  "Rust Web3",
        "mixed": "Mixed EVM + Rust",
    }.get(stats.project_type, stats.project_type)

    print()
    print(BOLD("─" * 52))
    print(BOLD("  HARVEST SUMMARY"))
    print(BOLD("─" * 52))
    print(f"  Project type     : {CYAN(type_display)}")
    print(f"  Files included   : {GREEN(str(len(stats.files)))}")
    print(f"  Total lines      : {stats.total_lines:,}")
    print(f"  Token estimate   : {token_str}")
    print(f"  Output file      : {CYAN(str(output_path))}  ({output_path.stat().st_size // 1024} KB)")
    if stats.skipped_binary:
        print(f"  Skipped (binary) : {YELLOW(str(stats.skipped_binary))}")
    if stats.skipped_too_large:
        print(f"  Skipped (large)  : {YELLOW(str(stats.skipped_too_large))}")
    if stats.errors:
        print(f"  Read errors      : {RED(str(stats.errors))}")

    if tokens > LIMIT_TOKENS:
        print()
        print(RED("  ⚠  Token count exceeds ~200K. Consider:"))
        print(RED("       --max-file-kb 50    to drop large files"))
        print(RED("       --extensions rs     to limit to Rust source only"))
        print(RED("       --extensions sol    to limit to Solidity only"))
    print(BOLD("─" * 52))
    print()


# ── Entry point ───────────────────────────────────────────────────────────────
def fetch_contract_source(address: str, chain: str = "mainnet") -> dict[str, Any]:
    """
    Fetch a verified contract source from Etherscan and provide metadata.
    """
    if not re.fullmatch(r"0x[a-fA-F0-9]{40}", address):
        raise ValueError("Address must be a 0x-prefixed 40-hex character string.")
    api_url = ETHERSCAN_API_URLS.get(chain)
    if api_url is None:
        raise ValueError(f"Unsupported chain '{chain}'.")
    api_key = os.getenv("ETHERSCAN_API_KEY")
    if not api_key:
        raise RuntimeError("Set ETHERSCAN_API_KEY in the environment before fetching contracts.")

    def _request() -> dict[str, Any]:
        response = requests.get(
            api_url,
            params={
                "module": "contract",
                "action": "getsourcecode",
                "address": address,
                "apikey": api_key,
            },
            timeout=30,
        )
        if response.status_code == 429:
            raise RateLimitError("Etherscan returned HTTP 429.")
        response.raise_for_status()
        payload = response.json()
        if payload.get("status") != "1":
            raise RuntimeError(f"Etherscan responded with error: {payload.get('message')}")
        items = payload.get("result", [])
        if not items:
            raise RuntimeError("Etherscan returned no contract data.")
        result = items[0]
        return {
            "source_code": result.get("SourceCode", ""),
            "contract_name": result.get("ContractName", ""),
            "abi": result.get("ABI", ""),
            "compiler_version": result.get("CompilerVersion", ""),
        }

    return _retry_with_backoff(_request)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Harvest a Web3 codebase (EVM or Rust) into a single LLM-ready audit/bug-bounty context file.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  # EVM / Solidity project (default behaviour)
  python harvest_context.py ./my-evm-protocol

  # Rust / Anchor / Solana project
  python harvest_context.py ./my-anchor-program --rust

  # Auto-detect project type + add bug-bounty hints in output
  python harvest_context.py ./my-protocol --auto --bug-bounty

  # Mixed repo, custom output, cap large files
  python harvest_context.py ./my-protocol -o audit.txt --auto --max-file-kb 100

  # Explicit extension list
  python harvest_context.py ./my-protocol --extensions rs toml md
        """,
    )
    parser.add_argument("target_dir", help="Root directory of the protocol repo")
    parser.add_argument("-o", "--output", default="llm_context.txt",
                        help="Output file name (default: llm_context.txt)")

    # ── Project-type flags ────────────────────────────────────────────────────
    type_group = parser.add_mutually_exclusive_group()
    type_group.add_argument("--rust", action="store_true",
                            help="Treat as a Rust Web3 project (Solana/Anchor/CosmWasm/Substrate)")
    type_group.add_argument("--evm", action="store_true",
                            help="Treat as an EVM/Solidity project (default)")
    type_group.add_argument("--auto", action="store_true",
                            help="Auto-detect project type from repo contents")

    # ── Optional file-type flags ──────────────────────────────────────────────
    parser.add_argument("--extensions", nargs="+", metavar="EXT",
                        help="Extra extensions to include, e.g. --extensions ts toml")
    parser.add_argument("--include-abi", action="store_true",
                        help="Include .json ABI files")
    parser.add_argument("--include-config", action="store_true",
                        help="Include .toml / .yaml config files")
    parser.add_argument("--include-ts", action="store_true",
                        help="Include .ts / .js files")

    # ── Other flags ───────────────────────────────────────────────────────────
    parser.add_argument("--bug-bounty", action="store_true",
                        help="Prepend bug-bounty vulnerability hints to the output for the LLM")
    parser.add_argument("--max-file-kb", type=int, default=None, metavar="KB",
                        help="Skip individual files larger than this size in KB")
    parser.add_argument("--stats", action="store_true",
                        help="Print per-extension breakdown in summary")

    args = parser.parse_args()
    target = Path(args.target_dir).resolve()
    output_path = Path(args.output)

    if not target.is_dir():
        print(RED(f"Error: '{target}' is not a valid directory."))
        sys.exit(1)

    # ── Determine project type ────────────────────────────────────────────────
    if args.auto:
        project_type = detect_project_type(target)
        print(BOLD(f"\n🔎 Auto-detected project type: {CYAN(project_type)}"))
    elif args.rust:
        project_type = "rust"
    else:
        project_type = "evm"   # default

    allowed_exts = build_extension_set(args, project_type)

    print(BOLD(f"\n🔍 Harvesting: {target}"))
    print(DIM(f"   Project type : {project_type}"))
    print(DIM(f"   Extensions   : {', '.join(sorted(allowed_exts))}"))
    if args.max_file_kb:
        print(DIM(f"   Max file     : {args.max_file_kb} KB"))
    if args.bug_bounty:
        print(DIM(f"   Mode         : bug-bounty (vulnerability hints included)"))
    print()

    entries, skip_bin, skip_large, errors = collect_files(
        target, allowed_exts, args.max_file_kb, project_type
    )
    entries = sort_entries(entries, project_type)

    stats = HarvestStats(
        files=entries,
        skipped_binary=skip_bin,
        skipped_too_large=skip_large,
        errors=errors,
        project_type=project_type,
    )

    if not entries:
        print(YELLOW("No files matched. Check your target directory or --extensions flags."))
        sys.exit(0)

    write_output(target, entries, output_path, stats, bug_bounty=args.bug_bounty)
    print_summary(stats, output_path)


if __name__ == "__main__":
    main()
