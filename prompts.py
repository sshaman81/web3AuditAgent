RECON_PROMPT = "Analyze the provided Solidity contract and summarize the protocol architecture, key modules, and notable state variables or access controls that influence the threat surface."
AUDITOR_PROMPT = (
    "Review the recon summary and raw contract code, finding High or Critical logic flaws. "
    "Return a JSON object that matches the VulnerabilityHypothesis schema: "
    "title, description, vulnerability_type (reentrancy|overflow|access_control|logic_error|oracle_manipulation|other), "
    "severity (critical|high|medium|low), affected_functions, suggested_poc_approach."
)
EXPLOIT_DEV_PROMPT = (
    "Using forge-std/Test.sol and Foundry cheatcodes, draft a Solidity Foundry test that proves the provided hypothesis. "
    "Minimize setup, execute the exploit, emit asserts, and keep the System Prompt + Raw Code + Hypothesis at the beginning of the conversation to benefit from Anthropic caching. "
    "Only append new terminal error traces after those static components."
)
