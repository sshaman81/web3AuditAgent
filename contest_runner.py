from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime
from typing import Awaitable, Callable


@dataclass
class ContestTarget:
    contract_name: str
    contract_address: str
    tvl_usd: float
    complexity_score: float
    deadline_utc: datetime


@dataclass
class ContestTriageResult:
    target: ContestTarget
    triage_result: str
    score: float
    notes: str


def _priority_score(target: ContestTarget) -> float:
    hours_left = max(1.0, (target.deadline_utc - datetime.utcnow()).total_seconds() / 3600)
    urgency = 100.0 / hours_left
    return target.tvl_usd * 0.0001 + target.complexity_score * 2.0 + urgency


async def _triage_one(
    target: ContestTarget,
    triage_callback: Callable[[ContestTarget], Awaitable[tuple[str, str]]],
    semaphore: asyncio.Semaphore,
) -> ContestTriageResult:
    async with semaphore:
        triage_result, notes = await triage_callback(target)
    score = _priority_score(target)
    if triage_result == "promising":
        score += 25.0
    return ContestTriageResult(target=target, triage_result=triage_result, score=score, notes=notes)


async def run_contest_triage(
    targets: list[ContestTarget],
    triage_callback: Callable[[ContestTarget], Awaitable[tuple[str, str]]],
    max_parallel: int = 10,
) -> list[ContestTriageResult]:
    semaphore = asyncio.Semaphore(max_parallel)
    tasks = [_triage_one(target, triage_callback, semaphore) for target in targets]
    results = await asyncio.gather(*tasks)
    return sorted(results, key=lambda item: item.score, reverse=True)


def select_top_targets(results: list[ContestTriageResult], top_n: int = 3) -> list[ContestTriageResult]:
    promising = [item for item in results if item.triage_result == "promising"]
    selected = promising[:top_n]
    if len(selected) < top_n:
        fallback = [item for item in results if item not in selected]
        selected.extend(fallback[: top_n - len(selected)])
    return selected