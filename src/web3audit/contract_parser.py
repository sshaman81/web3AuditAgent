from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Sequence

TOKEN_CHAR_RATIO = 4.0
FUNCTION_SIGNATURE_RE = re.compile(
    r"\b(function|constructor|modifier)\s+([A-Za-z_][A-Za-z0-9_]*)?\s*\([^\)]*\)\s*[^\{;]*\{",
    re.MULTILINE,
)


@dataclass(frozen=True)
class CodeChunk:
    name: str
    source: str


def estimate_tokens(text: str) -> int:
    if not text:
        return 0
    return int(len(text) / TOKEN_CHAR_RATIO)


def _extract_block(code: str, start_index: int) -> str:
    depth = 0
    for idx in range(start_index, len(code)):
        char = code[idx]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return code[start_index : idx + 1]
    return code[start_index:]


def extract_solidity_chunks(code: str) -> list[CodeChunk]:
    chunks: list[CodeChunk] = []
    for match in FUNCTION_SIGNATURE_RE.finditer(code):
        function_name = match.group(2) or match.group(1)
        block = _extract_block(code, match.start())
        if block:
            chunks.append(CodeChunk(name=function_name, source=block.strip()))

    if not chunks:
        return [CodeChunk(name="contract_snippet", source=code.strip())]
    return chunks


def _score_chunk(chunk: CodeChunk, terms: Sequence[str]) -> int:
    text = f"{chunk.name} {chunk.source}".lower()
    return sum(1 for term in terms if term and term.lower() in text)


def select_semantic_chunks(
    code: str,
    token_limit: int,
    focus_terms: Iterable[str] | None = None,
) -> str:
    if estimate_tokens(code) <= token_limit:
        return code

    chunks = extract_solidity_chunks(code)
    terms = [term.strip().lower() for term in (focus_terms or []) if term and term.strip()]

    ranked = sorted(
        chunks,
        key=lambda chunk: (_score_chunk(chunk, terms), len(chunk.source)),
        reverse=True,
    )

    selected: list[str] = []
    used_tokens = 0
    for chunk in ranked:
        chunk_tokens = estimate_tokens(chunk.source)
        if used_tokens + chunk_tokens > token_limit and selected:
            continue
        selected.append(chunk.source)
        used_tokens += chunk_tokens
        if used_tokens >= token_limit:
            break

    if not selected:
        fallback_chars = max(128, int(token_limit * TOKEN_CHAR_RATIO))
        return code[:fallback_chars]

    return "\n\n".join(selected)