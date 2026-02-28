import pytest
from pydantic import ValidationError

from schemas import VulnerabilityHypothesis


def test_invalid_severity_rejected():
    with pytest.raises(ValidationError):
        VulnerabilityHypothesis(
            title="Test",
            description="description",
            vulnerability_type="reentrancy",
            severity="ultra",
            affected_functions=["foo"],
            suggested_poc_approach="Run flash loan",
        )


def test_invalid_type_rejected():
    with pytest.raises(ValidationError):
        VulnerabilityHypothesis(
            title="Test",
            description="description",
            vulnerability_type="alien",
            severity="high",
            affected_functions=["foo"],
            suggested_poc_approach="Run flash loan",
        )
