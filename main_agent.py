import sys
import time
from datetime import datetime
from typing import Any, Callable, Dict, Literal

from pydantic import ValidationError
from langchain.chat_models import ChatAnthropic
from langchain.schema import BaseMessage, HumanMessage, SystemMessage
from langgraph.graph import StateGraph
from langgraph.graph.state import CompiledStateGraph

from config import Settings
from prompts import AUDITOR_PROMPT, EXPLOIT_DEV_PROMPT, RECON_PROMPT
from schemas import VulnerabilityHypothesis
from state import AuditState, FoundryRun
from tools import FoundryResult, execute_foundry_poc
from utils import DuplicateHypothesisError, word_overlap


settings = Settings()

recon_llm = ChatAnthropic(model=settings.recon_model)
auditor_llm = ChatAnthropic(model=settings.audit_model)
exploit_llm = ChatAnthropic(model=settings.exploit_model)


MAX_BACKOFF_SECONDS = 60



def classify_error(exception: Exception) -> Literal[
    "rate_limit",
    "context_overflow",
    "model_error",
    "tool_error",
    "unknown",
]:
    message = str(exception).lower()
    if "rate limit" in message or "too many requests" in message or "quota" in message:
        return "rate_limit"
    if "context" in message and ("length" in message or "overflow" in message or "token" in message):
        return "context_overflow"
    if "forge" in message or "foundry" in message or isinstance(exception, RuntimeError):
        return "tool_error"
    if "model" in message or "anthropic" in message or isinstance(exception, ValidationError):
        return "model_error"
    return "unknown"


def log_node_error(state: AuditState, node: str, attempt: int, err_type: str, exception: Exception) -> None:
    entry = f"{node} attempt {attempt} [{err_type}]: {type(exception).__name__} - {exception}"
    state.setdefault("node_errors", {}).setdefault(node, []).append(entry)
    print(entry, file=sys.stderr)


def shrink_raw_code(state: AuditState) -> None:
    code = state["raw_code"]
    target_len = max(64, int(len(code) * 0.8))
    state["raw_code"] = code[:target_len]



def safe_run(
    node_name: str,
    state: AuditState,
    action: Callable[[], Dict[str, Any]],
) -> Dict[str, Any]:
    state.setdefault("node_errors", {})
    state.setdefault("hypothesis_history", [])
    state.setdefault("poc_execution_logs", "")
    state.setdefault("foundry_poc_code", "")
    state.setdefault("forge_runs", [])

    attempt = len(state["node_errors"].get(node_name, [])) + 1
    while True:
        try:
            return action()
        except DuplicateHypothesisError as exc:
            log_node_error(state, node_name, attempt, "model_error", exc)
            attempt += 1
            continue
        except Exception as exc:
            err_type = classify_error(exc)
            log_node_error(state, node_name, attempt, err_type, exc)
            if err_type == "rate_limit":
                delay = min(MAX_BACKOFF_SECONDS, 2 ** attempt)
                time.sleep(delay)
                attempt += 1
                continue
            if err_type == "context_overflow":
                shrink_raw_code(state)
                attempt += 1
                continue
            if err_type == "tool_error":
                state["retry_count"] = settings.max_hypotheses
                state["current_hypothesis"] = ""
                state["is_vulnerable"] = False
                state["poc_execution_logs"] = str(exc)
                return {}
            raise


def recon_node(state: AuditState) -> Dict[str, str]:
    def action() -> Dict[str, str]:
        messages: list[BaseMessage] = [
            SystemMessage(content=RECON_PROMPT),
            HumanMessage(content=state["raw_code"]),
        ]
        response = recon_llm(messages)
        summary = response.content.strip()
        return {"recon_summary": summary}

    return safe_run("recon_node", state, action)


def auditor_node(state: AuditState) -> Dict[str, str]:
    def action() -> Dict[str, str]:
        messages: list[BaseMessage] = [
            SystemMessage(content=AUDITOR_PROMPT),
            HumanMessage(content=f"Recon summary:\n{state['recon_summary']}"),
            HumanMessage(content=f"Raw code:\n{state['raw_code']}"),
        ]
        response = auditor_llm(messages)
        hypothesis = VulnerabilityHypothesis.parse_raw(response.content.strip())
        hypothesis_text = f"{hypothesis.title} {hypothesis.description}"
        for seen in state["hypothesis_history"]:
            if word_overlap(hypothesis_text, seen) > 0.8:
                raise DuplicateHypothesisError("Hypothesis similar to previous one")
        state["current_hypothesis"] = hypothesis_text
        state["hypothesis_history"].append(hypothesis_text)
        state["vulnerability_hypotheses"].append(hypothesis)
        state["retry_count"] = 0
        return {"current_hypothesis": hypothesis_text}

    return safe_run("auditor_node", state, action)


def exploit_dev_node(state: AuditState) -> Dict[str, Any]:
    def action() -> Dict[str, Any]:
        static: list[BaseMessage] = [
            SystemMessage(content=EXPLOIT_DEV_PROMPT),
            HumanMessage(content=state["raw_code"]),
            HumanMessage(content=f"Attack hypothesis:\n{state['current_hypothesis']}"),
        ]
        if state["poc_execution_logs"]:
            messages = static + [
                HumanMessage(content=f"Latest Foundry logs:\n{state['poc_execution_logs']}"),
            ]
        else:
            messages = static

        response = exploit_llm(messages)
        poc_code = response.content.strip()
        result: FoundryResult = execute_foundry_poc.func(
            solidity_code=poc_code,
            timeout_seconds=settings.forge_timeout_seconds,
            max_chars=settings.max_forge_log_chars,
        )
        log_text = f"STDOUT:\n{result['stdout']}\nSTDERR:\n{result['stderr']}"
        state["poc_execution_logs"] = log_text
        state["foundry_poc_code"] = poc_code
        state["retry_count"] += 1
        run_entry: FoundryRun = {
            "hypothesis": state["current_hypothesis"],
            "exit_code": result["exit_code"],
            "stdout_snippet": result["stdout"],
            "success": result["success"],
        }
        state["forge_runs"].append(run_entry)
        if not result["success"]:
            raise RuntimeError("Foundry PoC failed; see logs for details")
        state["is_vulnerable"] = True
        return {
            "foundry_poc_code": poc_code,
            "poc_execution_logs": log_text,
            "retry_count": state["retry_count"],
            "is_vulnerable": state["is_vulnerable"],
        }

    return safe_run("exploit_dev_node", state, action)


def reviewer_node(state: AuditState) -> Dict[str, str]:
    def action() -> Dict[str, str]:
        title = "VULNERABLE" if state["is_vulnerable"] else "NO ISSUES FOUND"
        header = f"# Audit Report\nStarted: {state['audit_started_at']}\nStatus: {title}\n"
        vulnerability_block = "\n".join(
            f"- {idx + 1}. {hyp.title} ({hyp.severity})" for idx, hyp in enumerate(state["vulnerability_hypotheses"])
        )
        runs = "\n".join(
            f"- Hypothesis: {run['hypothesis']} | Success: {run['success']} | Exit: {run['exit_code']}" for run in state["forge_runs"]
        )
        report = (
            f"{header}\n## Recon Summary\n{state['recon_summary']}\n\n"
            f"## Hypotheses\n{vulnerability_block}\n\n"
            f"## Forge Runs\n{runs}\n\n## PoC\n```
{state['foundry_poc_code']}
```
\n## Logs\n```
{state['poc_execution_logs']}
```
"
        )
        state["final_report"] = report
        return {"final_report": report}

    return safe_run("reviewer_node", state, action)


def should_continue(state: AuditState) -> str:
    if state["is_vulnerable"]:
        return "reviewer_node"
    if state["retry_count"] >= settings.max_hypotheses:
        return "auditor_node"
    return "exploit_dev_node"


def build_graph() -> CompiledStateGraph[AuditState, None, AuditState, AuditState]:
    builder = StateGraph(state_schema=AuditState)
    builder.add_node(recon_node)
    builder.add_node(auditor_node)
    builder.add_node(exploit_dev_node)
    builder.add_node(reviewer_node)

    builder.set_entry_point("recon_node")
    builder.add_edge("recon_node", "auditor_node")
    builder.add_edge("auditor_node", "exploit_dev_node")
    builder.add_conditional_edges(
        "exploit_dev_node",
        should_continue,
        path_map={
            "reviewer_node": "reviewer_node",
            "auditor_node": "auditor_node",
            "exploit_dev_node": "exploit_dev_node",
        },
    )
    builder.add_edge("reviewer_node", "END")

    return builder.compile()


if __name__ == "__main__":
    graph = build_graph()
    dummy_state: AuditState = {
        "raw_code": "contract Sample { function run() public {} }",
        "recon_summary": "",
        "vulnerability_hypotheses": [],
        "current_hypothesis": "",
        "foundry_poc_code": "",
        "poc_execution_logs": "",
        "is_vulnerable": False,
        "retry_count": 0,
        "final_report": "",
        "hypothesis_history": [],
        "node_errors": {},
        "audit_started_at": datetime.utcnow().isoformat() + "Z",
        "forge_runs": [],
    }
    print("Starting multi-agent audit graph...")
    result = graph.invoke(dummy_state)
    print("Final report:\n", result.get("final_report", ""))
