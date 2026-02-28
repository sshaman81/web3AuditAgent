from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from langchain_anthropic import ChatAnthropic
from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage
from langgraph.constants import Send
from langgraph.graph import END, StateGraph
from langgraph.graph.state import CompiledStateGraph

from config import settings
from contract_parser import select_semantic_chunks
from error_handler import ErrorHandlingMiddleware
from harvester import fetch_contract_source
from logger import get_logger, setup_logging
from prompts import AUDITOR_PROMPT, EXPLOIT_DEV_PROMPT, RECON_PROMPT
from schemas import VulnerabilityHypothesis
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

        payload = fetch_contract_source(
            address=model.contract_address,
            chain=model.contract_chain,
        )
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


def recon_node(state: AuditGraphState) -> dict[str, Any]:
    model = _state_from_graph(state)
    error_log = dict(model.node_errors)
    working_code = _active_code(model)

    def action() -> dict[str, Any]:
        messages: list[BaseMessage] = [
            SystemMessage(content=RECON_PROMPT),
            HumanMessage(content=working_code),
        ]
        response = recon_llm.invoke(messages)
        return {"recon_summary": str(response.content).strip()}

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
            raise ValueError("No novel hypotheses generated")
        return {
            "vulnerability_hypotheses": accepted,
            "hypotheses_batch": [f"{hyp.title} {hyp.description}".strip() for hyp in accepted],
            "current_hypothesis": f"{accepted[0].title} {accepted[0].description}".strip(),
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
                HumanMessage(
                    content=f"Previous failure feedback:\n{model.failure_analysis.actionable_feedback}"
                )
            )

        response = exploit_llm.invoke(static_messages)
        poc_code = str(response.content).strip()
        result: FoundryResult = execute_foundry_poc.func(
            solidity_code=poc_code,
            timeout_seconds=settings.forge_timeout_seconds,
            max_chars=settings.max_forge_log_chars,
            fork_url=settings.forge_fork_url,
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
    round_results = [
        attempt
        for attempt in model.exploit_attempt_results
        if attempt.round_index == model.retry_count
    ]

    if not round_results:
        return {
            "is_vulnerable": False,
            "poc_execution_logs": "No exploit attempts were executed.",
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
    summary = "Forge execution failed without a recognized signature."
    guidance = "Rebuild the test with minimal setup and clearer assertions."

    if "compiler error" in logs or "parsererror" in logs or "declarationerror" in logs:
        category = "compilation_error"
        summary = "PoC did not compile."
        guidance = "Fix imports, pragma versions, and syntax before exploit logic."
    elif "assertion failed" in logs or "asserteq" in logs or "asserttrue" in logs:
        category = "assertion_failure"
        summary = "Exploit test ran but assertions failed."
        guidance = "Align assertions with expected state transitions after exploit path."
    elif "revert" in logs or "panic" in logs:
        category = "revert"
        summary = "Transaction reverted during exploit path."
        guidance = "Use setup cheatcodes and role impersonation to satisfy preconditions."
    elif "timed out" in logs or "timeout" in logs:
        category = "timeout"
        summary = "Forge execution timed out."
        guidance = "Reduce test complexity and avoid unbounded loops."

    failure = FailureAnalysis(
        category=category,
        summary=summary,
        actionable_feedback=guidance,
    )
    return {"failure_analysis": failure}


def route_after_failure(state: AuditGraphState) -> str:
    model = _state_from_graph(state)
    if model.is_vulnerable:
        return "reviewer_node"
    if model.retry_count >= settings.max_hypotheses:
        return "reviewer_node"
    return "auditor_node"


def reviewer_node(state: AuditGraphState) -> dict[str, Any]:
    model = _state_from_graph(state)
    status = "VULNERABLE" if model.is_vulnerable else "NO ISSUES FOUND"

    hypotheses_lines = "\n".join(
        f"- {idx + 1}. {hyp.title} ({hyp.severity})"
        for idx, hyp in enumerate(model.vulnerability_hypotheses)
    ) or "- None"

    run_lines = "\n".join(
        f"- Round {run.round_index} | Hypothesis: {run.hypothesis} | Success: {run.success} | Exit: {run.exit_code}"
        for run in model.forge_runs
    ) or "- None"

    gas_lines = "\n".join(
        f"- Round {entry.round_index} | {entry.test_name}: {entry.gas_used}"
        for entry in model.gas_reports
    ) or "- None"

    failure_block = ""
    if model.failure_analysis:
        failure_block = (
            "\n## Failure Analysis\n"
            f"Category: {model.failure_analysis.category}\n"
            f"Summary: {model.failure_analysis.summary}\n"
            f"Feedback: {model.failure_analysis.actionable_feedback}\n"
        )

    report = (
        f"# Audit Report\n"
        f"Started: {model.audit_started_at}\n"
        f"Status: {status}\n\n"
        f"## Recon Summary\n{model.recon_summary}\n\n"
        f"## Hypotheses\n{hypotheses_lines}\n\n"
        f"## Forge Runs\n{run_lines}\n\n"
        f"## Gas Usage\n{gas_lines}\n\n"
        f"## PoC\n```solidity\n{model.foundry_poc_code}\n```\n\n"
        f"## Logs\n```text\n{model.poc_execution_logs}\n```\n"
        f"{failure_block}"
    )

    report_dir = _ensure_report_dir(model)
    markdown_path = report_dir / "report.md"
    json_path = report_dir / "report.json"

    json_payload = {
        "status": status,
        "contract_name": model.contract_name,
        "audit_started_at": model.audit_started_at,
        "recon_summary": model.recon_summary,
        "is_vulnerable": model.is_vulnerable,
        "hypotheses": [hyp.model_dump() for hyp in model.vulnerability_hypotheses],
        "forge_runs": [run.model_dump() for run in model.forge_runs],
        "gas_reports": [entry.model_dump() for entry in model.gas_reports],
        "failure_analysis": model.failure_analysis.model_dump() if model.failure_analysis else None,
        "report_markdown": report,
    }

    markdown_path.write_text(report, encoding="utf-8")
    json_path.write_text(json.dumps(json_payload, indent=2), encoding="utf-8")

    logger.info(
        "Persisted audit report",
        extra={"context": {"report_dir": str(report_dir), "status": status}},
    )

    return {
        "final_report": report,
        "report_directory": str(report_dir),
    }


def build_graph() -> CompiledStateGraph[AuditGraphState, None, AuditGraphState, AuditGraphState]:
    builder = StateGraph(state_schema=AuditGraphState)

    builder.add_node(harvester_node)
    builder.add_node(recon_node)
    builder.add_node(auditor_node)
    builder.add_node(exploit_fanout_node)
    builder.add_node(exploit_dev_node)
    builder.add_node(aggregate_exploits_node)
    builder.add_node(failure_analyzer_node)
    builder.add_node(reviewer_node)

    builder.set_entry_point("harvester_node")
    builder.add_edge("harvester_node", "recon_node")
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

    builder.add_conditional_edges(
        "failure_analyzer_node",
        route_after_failure,
        path_map={
            "reviewer_node": "reviewer_node",
            "auditor_node": "auditor_node",
        },
    )
    builder.add_edge("reviewer_node", END)

    return builder.compile()


if __name__ == "__main__":
    graph = build_graph()
    initial = build_initial_state(raw_code="contract Sample { function run() public {} }")
    result = graph.invoke(as_graph_state(initial))
    report = result.get("final_report", "")
    logger.info("Audit graph execution completed", extra={"context": {"report_chars": len(report)}})
