# Multi-Agent Smart Contract Audit System

This workspace scaffolds a LangGraph and LangChain-powered multi-agent pipeline that audits Solidity contracts and generates Foundry proofs of concept (PoCs).

## Key Components

- `state.py`: Defines the `AuditState` typed dict modeling all stages of the audit workflow.
- `prompts.py`: System/assistant prompts for recon, auditing, and exploit development steps.
- `tools.py`: Provides the `execute_foundry_poc` LangChain tool that writes a Foundry test, runs `forge test`, and truncates logs for tooling efficiency.
- `main_agent.py`: Builds a LangGraph `StateGraph` with recon, auditor, exploit, and reviewer nodes, orchestrates Claude-3.5 routing, enforces prompt-caching order, and loops with retry-safe transitions.

## Workflow

1. Recon node summarizes protocol architecture using `claude-3-5-haiku-latest`.
2. Auditor node uses `claude-3-5-sonnet-latest` to generate vulnerability hypotheses.
3. Exploit node invokes the expensive Claude model with cached static content (system prompt, raw code, hypothesis) and only appends dynamic console logs last, then runs the generated PoC via Forge.
4. Reviewer node compiles a markdown report when a vulnerability is confirmed.

## Setup

1. Install dependencies: `pip install -r requirements.txt`.
2. Set `ANTHROPIC_API_KEY` in `.env`.
3. Run `python main_agent.py` once `forge` is available and configured.

## Notes

- The `tools.execute_foundry_poc` helper ensures logs stay within Anthropic's context limits by truncating mid-output when needed.
- Retry logic routes back to the auditor for up to five hypotheses before re-running the exploit node.
