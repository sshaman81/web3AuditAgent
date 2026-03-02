from enum import Enum
from typing import List

from pydantic import BaseModel, Field, field_validator


class VulnerabilityType(str, Enum):
    reentrancy = "reentrancy"
    overflow = "overflow"
    access_control = "access_control"
    logic_error = "logic_error"
    oracle_manipulation = "oracle_manipulation"
    flash_loan = "flash_loan"
    front_running = "front_running"
    other = "other"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class VulnerabilityHypothesis(BaseModel):
    title: str
    description: str
    vulnerability_type: VulnerabilityType
    severity: Severity
    affected_functions: List[str]
    suggested_poc_approach: str
    funds_at_risk_usd: float = Field(default=0.0, ge=0.0)
    ease_of_exploitation: int = Field(default=5, ge=1, le=10)
    attack_preconditions: List[str] = Field(default_factory=list)

    @field_validator("funds_at_risk_usd")
    @classmethod
    def validate_funds_at_risk(cls, value: float) -> float:
        if value < 0:
            raise ValueError("funds_at_risk_usd must be >= 0")
        return value


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
