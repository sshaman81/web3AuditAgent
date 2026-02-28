from enum import Enum
from typing import List

from pydantic import BaseModel


class VulnerabilityType(str, Enum):
    reentrancy = "reentrancy"
    overflow = "overflow"
    access_control = "access_control"
    logic_error = "logic_error"
    oracle_manipulation = "oracle_manipulation"
    other = "other"


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class VulnerabilityHypothesis(BaseModel):
    title: str
    description: str
    vulnerability_type: VulnerabilityType
    severity: Severity
    affected_functions: List[str]
    suggested_poc_approach: str


class AuditReport(BaseModel):
    contract_name: str
    vulnerabilities: List[VulnerabilityHypothesis]
    confirmed_vulnerabilities: List[str]
    summary: str
    timestamp: str


class ReconSummary(BaseModel):
    protocol_name: str
    contract_count: int
    key_functions: List[str]
    external_dependencies: List[str]
    potential_risk_areas: List[str]
