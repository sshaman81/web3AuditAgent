from typing import Dict

from langchain.chat_models import ChatAnthropic
from langchain.schema import BaseMessage, HumanMessage, SystemMessage
from langgraph.graph import StateGraph
from langgraph.graph.state import CompiledStateGraph

from prompts import EXPLOIT_DEV_PROMPT, AUDITOR_PROMPT, RECON_PROMPT
from state import AuditState
from tools import execute_foundry_poc


haiku_llm = ChatAnthropic(model="claude-3-5-haiku-latest")
sonnet_llm = ChatAnthropic(model="claude-3-5-sonnet-latest")


RETRY_LIMIT = 5


def recon_node(state: AuditState) -> Dict[str, str]:
    messages: list[BaseMessage] = [
        SystemMessage(content=RECON_PROMPT),
        HumanMessage(content=state["raw_code"]),
    ]
    response = haiku_llm(messages)
    return {"recon_summary": response.content}


def auditor_node(state: AuditState) -> Dict[str, object]:
    messages: list[BaseMessage] = [
        SystemMessage(content=AUDITOR_PROMPT),
        HumanMessage(content=f"Protocol summary:\n{state['recon_summary']}"),
        HumanMessage(content=f"Raw code:\n{state['raw_code']}"),
    ]
    response = sonnet_llm(messages)
    hypothesis = response.content.strip()
    updated_hypotheses = state["vulnerability_hypotheses"] + [hypothesis]
    return {
        "current_hypothesis": hypothesis,
        "retry_count": 0,
        "vulnerability_hypotheses": updated_hypotheses,
    }


def exploit_dev_node(state: AuditState) -> Dict[str, object]:
    static_messages: list[BaseMessage] = [
        SystemMessage(content=EXPLOIT_DEV_PROMPT),
        HumanMessage(content=state["raw_code"]),
        HumanMessage(content=f"Attack hypothesis:\n{state['current_hypothesis']}"),
    ]
    if state["poc_execution_logs"]:
        dynamic_message = HumanMessage(
            content=f"Latest Foundry logs:\n{state['poc_execution_logs']}"
        )
        messages = static_messages + [dynamic_message]
    else:
        messages = static_messages

    poc_response = sonnet_llm(messages)
    poc_code = poc_response.content.strip()
    execution_logs = execute_foundry_poc(poc_code)
    is_vulnerable = "fail" not in execution_logs.lower()
    return {
        "foundry_poc_code": poc_code,
        "poc_execution_logs": execution_logs,
        "retry_count": state["retry_count"] + 1,
        "is_vulnerable": is_vulnerable,
    }


def reviewer_node(state: AuditState) -> Dict[str, str]:
    status = "VULNERABLE" if state["is_vulnerable"] else "NO ISSUES FOUND"
    body = f"""# Audit Report\n\n**Status:** {status}\n\n**Recon:**\n{state['recon_summary']}\n\n**Hypotheses:**\n"""
    for idx, hypothesis in enumerate(state["vulnerability_hypotheses"], 1):
        body += f"{idx}. {hypothesis}\n"
    body += f"\n**PoC:**\n```solidity\n{state['foundry_poc_code']}\n```\n\n**Execution Logs:**\n```\n{state['poc_execution_logs']}\n```\n"
    return {
        "final_report": body,
    }


def should_continue(state: AuditState) -> str:
    if state["is_vulnerable"]:
        return "reviewer_node"
    if state["retry_count"] >= RETRY_LIMIT:
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
    }
    print("Starting recon...")
    result = graph.invoke(dummy_state)
    print("Graph run completed. Final report:\n", result["final_report"])
