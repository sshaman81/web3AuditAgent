from typing import TypedDict, List, Dict

from schemas import VulnerabilityHypothesis


class FoundryRun(TypedDict):
    hypothesis: str
    exit_code: int | None
    stdout_snippet: str
    success: bool


class AuditState(TypedDict):
    raw_code: str
    recon_summary: str
    vulnerability_hypotheses: List[VulnerabilityHypothesis]
    current_hypothesis: str
    foundry_poc_code: str
    poc_execution_logs: str
    is_vulnerable: bool
    retry_count: int
    final_report: str
    hypothesis_history: List[str]
    node_errors: Dict[str, List[str]]
    audit_started_at: str
    forge_runs: List[FoundryRun]
