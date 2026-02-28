from __future__ import annotations

import operator
from datetime import datetime, timezone
from typing import Annotated, Any, Optional, TypedDict

from pydantic import BaseModel, Field, field_validator

from schemas import VulnerabilityHypothesis


class FoundryRun(BaseModel):
    hypothesis: str
    round_index: int = 0
    exit_code: Optional[int] = None
    stdout_snippet: str = ""
    stderr_snippet: str = ""
    success: bool = False
    duration_seconds: float = 0.0


class GasReport(BaseModel):
    hypothesis: str
    round_index: int = 0
    test_name: str
    gas_used: int


class FailureAnalysis(BaseModel):
    category: str = "unknown"
    summary: str = ""
    actionable_feedback: str = ""


class ExploitAttemptResult(BaseModel):
    hypothesis: str
    round_index: int = 0
    success: bool
    foundry_poc_code: str
    poc_execution_logs: str
    failure_analysis: Optional[FailureAnalysis] = None
    run: FoundryRun
    gas_reports: list[GasReport] = Field(default_factory=list)


class AuditState(BaseModel):
    raw_code: Optional[str] = None
    working_raw_code: Optional[str] = None
    recon_summary: str = ""
    vulnerability_hypotheses: list[VulnerabilityHypothesis] = Field(default_factory=list)
    current_hypothesis: Optional[str] = None
    hypotheses_batch: list[str] = Field(default_factory=list)
    foundry_poc_code: str = ""
    poc_execution_logs: str = ""
    is_vulnerable: bool = False
    retry_count: int = 0
    final_report: str = ""
    hypothesis_history: list[str] = Field(default_factory=list)
    node_errors: dict[str, list[str]] = Field(default_factory=dict)
    audit_started_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    contract_address: Optional[str] = None
    contract_chain: str = "mainnet"
    contract_name: Optional[str] = None
    platform_name: Optional[str] = None
    duplicate_report_exists: bool = False
    duplicate_report_reason: str = ""
    triage_result: str = "pending"
    triage_reasons: list[str] = Field(default_factory=list)
    skip_recon: bool = False
    failure_analysis: Optional[FailureAnalysis] = None
    forge_runs: list[FoundryRun] = Field(default_factory=list)
    gas_reports: list[GasReport] = Field(default_factory=list)
    exploit_attempt_results: list[ExploitAttemptResult] = Field(default_factory=list)
    report_directory: Optional[str] = None
    funds_at_risk_usd: float = 0.0
    economic_viable: bool = False
    economic_notes: str = ""

    @field_validator("retry_count")
    @classmethod
    def validate_retry_count(cls, value: int) -> int:
        if value < 0:
            raise ValueError("retry_count must be >= 0")
        return value


class AuditGraphState(TypedDict, total=False):
    raw_code: Optional[str]
    working_raw_code: Optional[str]
    recon_summary: str
    vulnerability_hypotheses: list[VulnerabilityHypothesis]
    current_hypothesis: Optional[str]
    hypotheses_batch: list[str]
    foundry_poc_code: str
    poc_execution_logs: str
    is_vulnerable: bool
    retry_count: int
    final_report: str
    hypothesis_history: list[str]
    node_errors: dict[str, list[str]]
    audit_started_at: str
    contract_address: Optional[str]
    contract_chain: str
    contract_name: Optional[str]
    platform_name: Optional[str]
    duplicate_report_exists: bool
    duplicate_report_reason: str
    triage_result: str
    triage_reasons: list[str]
    skip_recon: bool
    failure_analysis: Optional[FailureAnalysis]
    forge_runs: Annotated[list[FoundryRun], operator.add]
    gas_reports: Annotated[list[GasReport], operator.add]
    exploit_attempt_results: Annotated[list[ExploitAttemptResult], operator.add]
    report_directory: Optional[str]
    funds_at_risk_usd: float
    economic_viable: bool
    economic_notes: str


def build_initial_state(
    raw_code: Optional[str] = None,
    contract_address: Optional[str] = None,
    platform_name: Optional[str] = None,
) -> AuditState:
    return AuditState(
        raw_code=raw_code,
        working_raw_code=raw_code,
        contract_address=contract_address,
        platform_name=platform_name,
    )


def as_graph_state(state: AuditState) -> AuditGraphState:
    return state.model_dump()


def validate_graph_state(state: dict[str, Any]) -> AuditState:
    return AuditState.model_validate(state)