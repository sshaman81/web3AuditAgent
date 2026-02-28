from __future__ import annotations

import asyncio
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from langchain_anthropic import ChatAnthropic
from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage
from langgraph.constants import Send
from langgraph.graph import END, StateGraph
from langgraph.graph.state import CompiledStateGraph

from bounty_platforms import (
    CantinaClient,
    HackenProofClient,
    ImmunefiClient,
    check_duplicate_across_platforms,
    report_fingerprint,
)
from cache_manager import CacheManager
from config import settings
from contract_parser import select_semantic_chunks
from error_handler import ErrorHandlingMiddleware
from exploit_economics import EconomicInput, LiquiditySource, assess_exploit_economics
from harvester import fetch_contract_source
from logger import get_logger, setup_logging
from prompts import AUDITOR_PROMPT, EXPLOIT_DEV_PROMPT, RECON_PROMPT
from report_generator import generate_report_bundle
from schemas import Severity, VulnerabilityHypothesis
from state import (
    AuditGraphState,
    AuditState,
    ExploitAttemptResult,
    FailureAnalysis,
    FoundryRun,
    GasReport,
    as_graph_state,
    build_initial_state,
    validate_graph_state,
)
from tools import FoundryResult, execute_foundry_poc, extract_gas_usage
from utils import word_overlap

setup_logging(level=settings.log_level, json_logs=settings.log_json)
logger = get_logger(__name__)

recon_llm = ChatAnthropic(model=settings.recon_model)
auditor_llm = ChatAnthropic(model=settings.audit_model)
exploit_llm = ChatAnthropic(model=settings.exploit_model)

middleware = ErrorHandlingMiddleware(
    max_attempts=settings.max_node_attempts,
    breaker_failure_threshold=settings.circuit_breaker_failure_threshold,
    breaker_recovery_seconds=settings.circuit_breaker_recovery_seconds,
)
cache_manager = CacheManager(db_path=settings.cache_db_path)

immunefi_client = ImmunefiClient(settings.immunefi_api_base, settings.immunefi_api_key)
hackenproof_client = HackenProofClient(settings.hackenproof_api_base, settings.hackenproof_api_key)
cantina_client = CantinaClient(settings.cantina_base_url)

TRIAGE_PATTERNS: dict[str, re.Pattern[str]] = {
    "reentrancy": re.compile(r"call\s*\{|\.call\(|delegatecall\(|callcode\(", re.IGNORECASE),
    "flash_loan": re.compile(r"flash\s*loan|Aave|Balancer|uniswapV2Call|executeOperation", re.IGNORECASE),
    "oracle_manipulation": re.compile(r"TWAP|oracle|latestRoundData|getReserves", re.IGNORECASE),
    "access_control": re.compile(r"onlyOwner|Ownable|AccessControl|set[A-Z]\w+", re.IGNORECASE),
}


async def parallel_triage_contracts(contract_payloads: list[dict[str, Any]]) -> list[dict[str, Any]]:
    semaphore = asyncio.Semaphore(settings.max_parallel_contracts)

    async def _run_one(payload: dict[str, Any]) -> dict[str, Any]:
        async with semaphore:
            code = payload.get("raw_code", "")
            result, reasons = triage_contract_code(code)
            output = payload.copy()
            output["triage_result"] = result
            output["triage_reasons"] = reasons
            return output

    tasks = [_run_one(payload) for payload in contract_payloads]
    return await asyncio.gather(*tasks)


def triage_contract_code(raw_code: str) -> tuple[str, list[str]]:
    if not raw_code.strip():
        return "skip", ["No code provided"]

    reasons: list[str] = []
    score = 0
    lowered = raw_code.lower()

    if settings.skip_known_contract_types:
        if "contract" in lowered and "erc20" in lowered and "override" in lowered and "permit" not in lowered:
            return "skip", ["Likely standard ERC20 implementation"]
        if "erc721" in lowered and "safeTransferFrom" in lowered and "_mint" in lowered:
            return "skip", ["Likely standard ERC721 implementation"]

    for label, pattern in TRIAGE_PATTERNS.items():
        matches = len(pattern.findall(raw_code))
        if matches <= 0:
            continue
        score += matches
        reasons.append(f"{label} signal x{matches}")

    if "unchecked" in lowered:
        score += 1
        reasons.append("unchecked arithmetic usage")
    if "tx.origin" in lowered:
        score += 2
        reasons.append("tx.origin usage")

    if score >= 3:
        return "promising", reasons
    return "skip", reasons or ["No high-value heuristic signal found"]


def _state_from_graph(state: AuditGraphState) -> AuditState:
    return validate_graph_state(dict(state))


def _active_code(state: AuditState) -> str:
    return state.working_raw_code or state.raw_code or ""


def _semantic_context_update(state: AuditState) -> dict[str, Any]:
    reduced = select_semantic_chunks(
        code=_active_code(state),
        token_limit=settings.code_context_token_limit,
        focus_terms=[state.current_hypothesis or ""],
    )
    return {"working_raw_code": reduced}


def _parse_hypothesis_payload(payload: str) -> list[VulnerabilityHypothesis]:
    data = json.loads(payload)
    items: list[dict[str, Any]]
    if isinstance(data, dict):
        items = [data]
    elif isinstance(data, list):
        items = [item for item in data if isinstance(item, dict)]
    else:
        raise ValueError("Auditor returned non-JSON hypothesis payload")
    return [VulnerabilityHypothesis.model_validate(item) for item in items]


def _dedupe_hypotheses(
    candidate_hypotheses: list[VulnerabilityHypothesis],
    history: list[str],
) -> tuple[list[VulnerabilityHypothesis], list[str]]:
    accepted: list[VulnerabilityHypothesis] = []
    history_updates: list[str] = []
    for hypothesis in candidate_hypotheses:
        if hypothesis.severity not in {Severity.high, Severity.critical}:
            continue
        text = f"{hypothesis.title} {hypothesis.description}".strip()
        if any(word_overlap(text, existing) > 0.8 for existing in history + history_updates):
            continue
        accepted.append(hypothesis)
        history_updates.append(text)
        if len(accepted) >= settings.max_parallel_hypotheses:
            break
    return accepted, history_updates


def _ensure_report_dir(state: AuditState) -> Path:
    started = datetime.fromisoformat(state.audit_started_at.replace("Z", "+00:00"))
    stamp = started.strftime("%Y%m%d_%H%M%S")
    contract_name = (state.contract_name or "contract").strip() or "contract"
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", contract_name)
    report_dir = Path("reports") / f"{stamp}_{safe_name}"
    report_dir.mkdir(parents=True, exist_ok=True)
    return report_dir


def harvester_node(state: AuditGraphState) -> dict[str, Any]:
    model = _state_from_graph(state)

    def action() -> dict[str, Any]:
        if not model.contract_address:
            return {"working_raw_code": _active_code(model)}

        payload = fetch_contract_source(address=model.contract_address, chain=model.contract_chain)
        source_code = payload.get("source_code") or model.raw_code or ""
        return {
            "raw_code": source_code,
            "working_raw_code": source_code,
            "contract_name": payload.get("contract_name") or model.contract_name,
        }

    return middleware.run_with_retries(
        node_name="harvester_node",
        action=action,
        error_log=dict(model.node_errors),
    )


def duplicate_guard_node(state: AuditGraphState) -> dict[str, Any]:
    model = _state_from_graph(state)
    if not model.contract_address:
        return {"duplicate_report_exists": False, "duplicate_report_reason": "No contract address provided"}

    fp = report_fingerprint(model.contract_address, model.contract_name or "unknown")
    if cache_manager.has_duplicate_fingerprint(fp):
        return {
            "duplicate_report_exists": True,
            "duplicate_report_reason": "Found cached duplicate fingerprint",
        }

    exists, reason = check_duplicate_across_platforms(
        contract_address=model.contract_address,
        immunefi_client=immunefi_client,
        hackenproof_client=hackenproof_client,
        cantina_client=cantina_client,
    )

    if exists:
        cache_manager.set_duplicate_fingerprint(
            fingerprint=fp,
            platform=model.platform_name or "unknown",
            payload={"reason": reason},
        )

    return {
        "duplicate_report_exists": exists,
        "duplicate_report_reason": reason,
    }


def triage_node(state: AuditGraphState) -> dict[str, Any]:
    model = _state_from_graph(state)
    result, reasons = triage_contract_code(_active_code(model))
    return {
        "triage_result": result,
        "triage_reasons": reasons,
        "skip_recon": settings.fast_mode and result == "skip",
    }


def route_after_triage(state: AuditGraphState) -> str:
    model = _state_from_graph(state)
    if model.duplicate_report_exists:
        return "reviewer_node"
    if model.skip_recon:
        return "reviewer_node"
    return "recon_node"


def recon_node(state: AuditGraphState) -> dict[str, Any]:
    model = _state_from_graph(state)
    error_log = dict(model.node_errors)
    working_code = _active_code(model)

    cache_key = hashlib.sha256(working_code.encode("utf-8")).hexdigest()
    cached = cache_manager.get_contract_analysis(cache_key)
    if cached and isinstance(cached.get("recon_summary"), str):
        return {"recon_summary": cached["recon_summary"]}

    def action() -> dict[str, Any]:
        messages: list[BaseMessage] = [
            SystemMessage(content=RECON_PROMPT),
            HumanMessage(content=working_code),
        ]
        response = recon_llm.invoke(messages)
        summary = str(response.content).strip()
        cache_manager.set_contract_analysis(cache_key, {"recon_summary": summary})
        return {"recon_summary": summary}

    def on_context_overflow(_: Exception) -> dict[str, Any]:
        nonlocal working_code
        updates = _semantic_context_update(model)
        working_code = updates["working_raw_code"]
        return updates

    return middleware.run_with_retries(
        node_name="recon_node",
        action=action,
        error_log=error_log,
        on_context_overflow=on_context_overflow,
    )


def auditor_node(state: AuditGraphState) -> dict[str, Any]:
    model = _state_from_graph(state)
    error_log = dict(model.node_errors)
    working_code = _active_code(model)

    def action() -> dict[str, Any]:
        prompt = (
            f"{AUDITOR_PROMPT}\n"
            f"Return a JSON array of up to {settings.max_parallel_hypotheses} distinct hypotheses."
        )
        messages: list[BaseMessage] = [
            SystemMessage(content=prompt),
            HumanMessage(content=f"Recon summary:\n{model.recon_summary}"),
            HumanMessage(content=f"Raw code:\n{working_code}"),
        ]
        response = auditor_llm.invoke(messages)
        hypotheses = _parse_hypothesis_payload(str(response.content).strip())
        accepted, history_updates = _dedupe_hypotheses(hypotheses, model.hypothesis_history)
        if not accepted:
            raise ValueError("No novel High/Critical hypotheses generated")
        return {
            "vulnerability_hypotheses": accepted,
            "hypotheses_batch": [f"{hyp.title} {hyp.description}".strip() for hyp in accepted],
            "current_hypothesis": f"{accepted[0].title} {accepted[0].description}".strip(),
            "funds_at_risk_usd": max(hyp.funds_at_risk_usd for hyp in accepted),
            "hypothesis_history": model.hypothesis_history + history_updates,
            "retry_count": model.retry_count + 1,
            "exploit_attempt_results": [],
            "failure_analysis": None,
        }

    def on_context_overflow(_: Exception) -> dict[str, Any]:
        nonlocal working_code
        updates = _semantic_context_update(model)
        working_code = updates["working_raw_code"]
        return updates

    return middleware.run_with_retries(
        node_name="auditor_node",
        action=action,
        error_log=error_log,
        on_context_overflow=on_context_overflow,
    )


def exploit_fanout_node(state: AuditGraphState) -> dict[str, Any]:
    model = _state_from_graph(state)
    batch = model.hypotheses_batch[: settings.max_parallel_hypotheses]
    return {
        "hypotheses_batch": batch,
        "current_hypothesis": batch[0] if batch else model.current_hypothesis,
    }


def exploit_fanout_router(state: AuditGraphState) -> list[Send] | str:
    model = _state_from_graph(state)
    batch = model.hypotheses_batch[: settings.max_parallel_hypotheses]
    if not batch:
        return "auditor_node"
    round_index = model.retry_count
    return [
        Send(
            "exploit_dev_node",
            {
                "current_hypothesis": hypothesis,
                "retry_count": round_index,
            },
        )
        for hypothesis in batch
    ]


def exploit_dev_node(state: AuditGraphState) -> dict[str, Any]:
    model = _state_from_graph(state)
    error_log = dict(model.node_errors)
    working_code = _active_code(model)
    hypothesis = model.current_hypothesis or ""
    round_index = model.retry_count

    def action() -> dict[str, Any]:
        static_messages: list[BaseMessage] = [
            SystemMessage(content=EXPLOIT_DEV_PROMPT),
            HumanMessage(content=working_code),
            HumanMessage(content=f"Attack hypothesis:\n{hypothesis}"),
        ]

        if model.failure_analysis and model.failure_analysis.actionable_feedback:
            static_messages.append(
                HumanMessage(content=f"Previous failure feedback:\n{model.failure_analysis.actionable_feedback}")
            )

        response = exploit_llm.invoke(static_messages)
        poc_code = str(response.content).strip()
        result: FoundryResult = execute_foundry_poc.func(
            solidity_code=poc_code,
            timeout_seconds=settings.forge_timeout_seconds,
            max_chars=settings.max_forge_log_chars,
            fork_url=settings.forge_fork_url,
            fork_mode=settings.forge_mode,
            anvil_rpc_url=settings.anvil_rpc_url,
        )
        logs = f"STDOUT:\n{result['stdout']}\nSTDERR:\n{result['stderr']}"

        run = FoundryRun(
            hypothesis=hypothesis,
            round_index=round_index,
            exit_code=result["exit_code"],
            stdout_snippet=result["stdout"],
            stderr_snippet=result["stderr"],
            success=result["success"],
            duration_seconds=result["duration_seconds"],
        )

        gas_reports: list[GasReport] = [
            GasReport(
                hypothesis=hypothesis,
                round_index=round_index,
                test_name=entry["test_name"],
                gas_used=entry["gas_used"],
            )
            for entry in extract_gas_usage(result["stdout"])
        ]

        attempt = ExploitAttemptResult(
            hypothesis=hypothesis,
            round_index=round_index,
            success=result["success"],
            foundry_poc_code=poc_code,
            poc_execution_logs=logs,
            run=run,
            gas_reports=gas_reports,
        )

        return {
            "exploit_attempt_results": [attempt],
            "forge_runs": [run],
            "gas_reports": gas_reports,
        }

    def on_context_overflow(_: Exception) -> dict[str, Any]:
        nonlocal working_code
        updates = _semantic_context_update(model)
        working_code = updates["working_raw_code"]
        return updates

    def on_tool_error(exc: Exception) -> dict[str, Any]:
        failed_run = FoundryRun(
            hypothesis=hypothesis,
            round_index=round_index,
            success=False,
            stdout_snippet="",
            stderr_snippet=str(exc),
        )
        attempt = ExploitAttemptResult(
            hypothesis=hypothesis,
            round_index=round_index,
            success=False,
            foundry_poc_code="",
            poc_execution_logs=str(exc),
            run=failed_run,
            gas_reports=[],
        )
        return {
            "exploit_attempt_results": [attempt],
            "forge_runs": [failed_run],
        }

    return middleware.run_with_retries(
        node_name="exploit_dev_node",
        action=action,
        error_log=error_log,
        on_context_overflow=on_context_overflow,
        on_tool_error=on_tool_error,
    )


def aggregate_exploits_node(state: AuditGraphState) -> dict[str, Any]:
    model = _state_from_graph(state)
    round_results = [attempt for attempt in model.exploit_attempt_results if attempt.round_index == model.retry_count]

    if not round_results:
        return {
            "is_vulnerable": False,
            "poc_execution_logs": "No verification attempts were executed.",
        }

    successful = [attempt for attempt in round_results if attempt.success]
    selected = successful[0] if successful else round_results[0]

    return {
        "is_vulnerable": bool(successful),
        "current_hypothesis": selected.hypothesis,
        "foundry_poc_code": selected.foundry_poc_code,
        "poc_execution_logs": selected.poc_execution_logs,
    }


def failure_analyzer_node(state: AuditGraphState) -> dict[str, Any]:
    model = _state_from_graph(state)
    if model.is_vulnerable:
        return {"failure_analysis": None}

    logs = model.poc_execution_logs.lower()
    category = "unknown"
    summary = "Verification failed without a recognized signature."
    guidance = "Reduce test scope and add deterministic preconditions."

    if "compiler error" in logs or "parsererror" in logs or "declarationerror" in logs:
        category = "compilation_error"
        summary = "Verification test did not compile."
        guidance = "Fix syntax and dependency imports first."
    elif "assertion failed" in logs or "asserteq" in logs or "asserttrue" in logs:
        category = "assertion_failure"
        summary = "Execution completed but expected impact was not observed."
        guidance = "Re-check invariant assumptions and actor setup."
    elif "revert" in logs or "panic" in logs:
        category = "revert"
        summary = "Execution reverted during validation path."
        guidance = "Confirm preconditions and role permissions."
    elif "timeout" in logs:
        category = "timeout"
        summary = "Execution timed out."
        guidance = "Constrain loops and reduce scenario complexity."

    failure = FailureAnalysis(category=category, summary=summary, actionable_feedback=guidance)
    return {"failure_analysis": failure}


def economics_node(state: AuditGraphState) -> dict[str, Any]:
    model = _state_from_graph(state)
    if not model.vulnerability_hypotheses:
        return {
            "economic_viable": False,
            "economic_notes": "No vulnerability hypothesis to score economically.",
        }

    hypothesis = model.vulnerability_hypotheses[0]
    representative_gas = max((entry.gas_used for entry in model.gas_reports), default=500_000)
    econ_input = EconomicInput(
        estimated_stolen_value_usd=max(hypothesis.funds_at_risk_usd, 1.0),
        required_capital_usd=max(hypothesis.funds_at_risk_usd * 0.15, 1_000.0),
        estimated_gas_units=representative_gas,
        gas_price_gwei=25.0,
        eth_price_usd=3000.0,
        liquidity_sources=[
            LiquiditySource(source="Balancer", available_usd=30_000_000.0),
            LiquiditySource(source="Aave", available_usd=50_000_000.0),
        ],
    )
    assessment = assess_exploit_economics(econ_input)
    return {
        "economic_viable": assessment.viable,
        "economic_notes": assessment.notes,
    }


def route_after_economics(state: AuditGraphState) -> str:
    model = _state_from_graph(state)
    if model.duplicate_report_exists:
        return "reviewer_node"
    if model.is_vulnerable and model.economic_viable:
        return "reviewer_node"
    if model.retry_count >= settings.max_hypotheses:
        return "reviewer_node"
    return "auditor_node"


def reviewer_node(state: AuditGraphState) -> dict[str, Any]:
    model = _state_from_graph(state)
    if model.duplicate_report_exists:
        status = "SKIPPED_DUPLICATE"
    elif model.is_vulnerable and model.economic_viable:
        status = "HIGH_VALUE_FINDING"
    elif model.is_vulnerable:
        status = "FINDING_NOT_ECONOMICALLY_VIABLE"
    elif model.skip_recon:
        status = "TRIAGE_SKIPPED"
    else:
        status = "NO_HIGH_CONFIDENCE_FINDING"

    report_bundle = generate_report_bundle(model)

    report = (
        f"# Bug Bounty Audit Report\n"
        f"Started: {model.audit_started_at}\n"
        f"Status: {status}\n"
        f"Platform: {model.platform_name or 'unspecified'}\n\n"
        f"## Duplicate Check\n"
        f"Duplicate: {model.duplicate_report_exists}\n"
        f"Reason: {model.duplicate_report_reason}\n\n"
        f"## Triage\n"
        f"Result: {model.triage_result}\n"
        + "\n".join(f"- {reason}" for reason in model.triage_reasons)
        + "\n\n"
        f"## Recon Summary\n{model.recon_summary}\n\n"
        f"## Economics\n"
        f"Viable: {model.economic_viable}\n"
        f"Notes: {model.economic_notes}\n\n"
        f"## Summary\n{report_bundle['summary']}\n"
    )

    report_dir = _ensure_report_dir(model)
    markdown_path = report_dir / "report.md"
    json_path = report_dir / "report.json"
    immunefi_path = report_dir / "immunefi.md"
    cantina_path = report_dir / "cantina.md"

    payload = {
        "status": status,
        "duplicate_report_exists": model.duplicate_report_exists,
        "duplicate_report_reason": model.duplicate_report_reason,
        "triage_result": model.triage_result,
        "triage_reasons": model.triage_reasons,
        "economic_viable": model.economic_viable,
        "economic_notes": model.economic_notes,
        "vulnerability_hypotheses": [hyp.model_dump() for hyp in model.vulnerability_hypotheses],
        "forge_runs": [run.model_dump() for run in model.forge_runs],
        "gas_reports": [entry.model_dump() for entry in model.gas_reports],
        "report_markdown": report,
    }

    markdown_path.write_text(report, encoding="utf-8")
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    immunefi_path.write_text(report_bundle["immunefi"], encoding="utf-8")
    cantina_path.write_text(report_bundle["cantina"], encoding="utf-8")

    logger.info("Persisted report artifacts", extra={"context": {"report_dir": str(report_dir), "status": status}})
    return {"final_report": report, "report_directory": str(report_dir)}


def build_graph() -> CompiledStateGraph[AuditGraphState, None, AuditGraphState, AuditGraphState]:
    builder = StateGraph(state_schema=AuditGraphState)

    builder.add_node(harvester_node)
    builder.add_node(duplicate_guard_node)
    builder.add_node(triage_node)
    builder.add_node(recon_node)
    builder.add_node(auditor_node)
    builder.add_node(exploit_fanout_node)
    builder.add_node(exploit_dev_node)
    builder.add_node(aggregate_exploits_node)
    builder.add_node(failure_analyzer_node)
    builder.add_node(economics_node)
    builder.add_node(reviewer_node)

    builder.set_entry_point("harvester_node")
    builder.add_edge("harvester_node", "duplicate_guard_node")
    builder.add_edge("duplicate_guard_node", "triage_node")
    builder.add_conditional_edges(
        "triage_node",
        route_after_triage,
        path_map={
            "recon_node": "recon_node",
            "reviewer_node": "reviewer_node",
        },
    )

    builder.add_edge("recon_node", "auditor_node")
    builder.add_edge("auditor_node", "exploit_fanout_node")

    builder.add_conditional_edges(
        "exploit_fanout_node",
        exploit_fanout_router,
        path_map={
            "auditor_node": "auditor_node",
            "exploit_dev_node": "exploit_dev_node",
        },
    )

    builder.add_edge("exploit_dev_node", "aggregate_exploits_node")
    builder.add_edge("aggregate_exploits_node", "failure_analyzer_node")
    builder.add_edge("failure_analyzer_node", "economics_node")

    builder.add_conditional_edges(
        "economics_node",
        route_after_economics,
        path_map={
            "reviewer_node": "reviewer_node",
            "auditor_node": "auditor_node",
        },
    )

    builder.add_edge("reviewer_node", END)
    return builder.compile()


if __name__ == "__main__":
    graph = build_graph()
    initial = build_initial_state(
        raw_code="contract Sample { function run() public {} }",
        platform_name="immunefi",
    )
    result = graph.invoke(as_graph_state(initial))
    logger.info("Run complete", extra={"context": {"report_dir": result.get("report_directory", "")}})