from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from schemas import Severity, VulnerabilityHypothesis
from state import AuditState


def _severity_to_label(severity: Severity) -> str:
    if severity == Severity.CRITICAL:
        return "Critical"
    if severity == Severity.HIGH:
        return "High"
    if severity == Severity.MEDIUM:
        return "Medium"
    return "Low"


def generate_immunefi_report(state: AuditState, hypothesis: VulnerabilityHypothesis) -> str:
    return (
        "# Immunefi Submission Draft\n"
        f"Generated: {datetime.now(timezone.utc).isoformat()}\n\n"
        f"## Severity\n{_severity_to_label(hypothesis.severity)}\n\n"
        f"## Impact\n{hypothesis.description}\n\n"
        "## Funds At Risk (USD)\n"
        f"{hypothesis.funds_at_risk_usd:,.2f}\n\n"
        "## Ease Of Exploitation (1-10)\n"
        f"{hypothesis.ease_of_exploitation}\n\n"
        "## Proof Of Concept\n"
        "A deterministic Foundry test is attached in the audit artifacts.\n\n"
        "## Recommended Fix\n"
        "Apply strict access controls and invariant checks around affected state transitions.\n"
    )


def generate_cantina_report(state: AuditState, hypothesis: VulnerabilityHypothesis) -> str:
    return (
        "# Cantina Finding Draft\n"
        f"Generated: {datetime.now(timezone.utc).isoformat()}\n\n"
        f"## Title\n{hypothesis.title}\n\n"
        f"## Technical Details\n{hypothesis.description}\n\n"
        "## Exploit Scenario\n"
        "The issue can be reproduced with controlled preconditions in a local fork test.\n\n"
        "## Affected Functions\n"
        + "\n".join(f"- {item}" for item in hypothesis.affected_functions)
        + "\n\n## Recommended Fix\n"
        "Introduce validation and defensive checks before external calls and state updates.\n"
    )


def generate_report_bundle(state: AuditState) -> dict[str, Any]:
    if not state.vulnerability_hypotheses:
        return {
            "summary": "No High/Critical findings generated.",
            "immunefi": "",
            "cantina": "",
        }

    top = state.vulnerability_hypotheses[0]
    return {
        "summary": f"Top finding: {top.title} ({top.severity})",
        "immunefi": generate_immunefi_report(state, top),
        "cantina": generate_cantina_report(state, top),
    }
