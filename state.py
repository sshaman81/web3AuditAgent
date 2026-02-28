from typing import TypedDict, List

class AuditState(TypedDict):
    raw_code: str
    recon_summary: str
    vulnerability_hypotheses: List[str]
    current_hypothesis: str
    foundry_poc_code: str
    poc_execution_logs: str
    is_vulnerable: bool
    retry_count: int
    final_report: str
