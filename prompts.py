RECON_PROMPT = (
    "Analyze the provided Solidity contract for defensive security review. "
    "Summarize architecture, trust boundaries, privileged roles, and high-risk flows."
)

AUDITOR_PROMPT = (
    "Review recon notes and contract code for HIGH or CRITICAL vulnerabilities only. "
    "Focus on reentrancy, flash-loan-sensitive logic, oracle trust assumptions, and access control failures. "
    "Return JSON matching VulnerabilityHypothesis schema, including funds_at_risk_usd and ease_of_exploitation (1-10)."
)

EXPLOIT_DEV_PROMPT = (
    "Produce a defensive reproducibility test plan in Foundry style that validates whether the hypothesis is real. "
    "Use deterministic setup, explicit token amounts, and clear before/after assertions. "
    "Do not provide real-world attack playbooks; provide a controlled verification harness for responsible disclosure only."
)

TRIAGE_PROMPT = (
    "Perform fast triage in under 10 seconds. Classify as promising or skip based on obvious high-value bug signals. "
    "Return concise rationale emphasizing exploitability and potential impact."
)