# Multi-Agent Smart Contract Audit System

This repository scaffolds a LangGraph + LangChain-driven audit pipeline that routes Claude 3.5 models through recon, auditing, exploit generation, and review, and wires Forge Proof-of-Concept execution into the loop.

## Key Components

- `config.py`: Environment-aware settings for each Claude endpoint and execution parameters so you can tweak models/timeout/log limits without touching logic.
- `state.py`: Typed-state schema (`AuditState`) capturing the raw code, hypothesis history, Forge runs, error logs, and final report.
- `prompts.py`: System prompts for recon, auditing, and exploit development, explicitly prescribing the structured JSON output needed by the auditor.
- `schemas.py`: Pydantic models that describe the recon summary, vulnerability hypotheses, and audit report to keep LangGraph outputs structured.
- `tools.py`: LangChain tool wrapping `forge test` with timeout handling, missing-Forge detection, log truncation, and typed `FoundryResult` telemetry.
- `main_agent.py`: LangGraph `StateGraph` wiring the recon ? auditor ? exploit ? reviewer nodes, enforcing caching order, deduplicating hypotheses, and handling model/tool errors with retry/backoff logic.
- `harvester.py`: Legacy context harvester plus the `fetch_contract_source` helper that retrieves verified Solidity code from Etherscan with retry-aware rate-limit handling.

## Architecture

```
              +----------------+
              |    Recon       |
              | (haiku model)  |
              +--------+-------+
                       |
                       v
              +--------+-------+
              |    Auditor     |<----------------------------+
              | (sonnet model) |                             |
              +--------+-------+                             |
                       |                                     |
                       v                                     |
              +--------+-------+             retry when       |
              |   Exploit      |<------------ hypothesis      |
              | (sonnet model) |             limit reached     |
              +----+---+-------+                             |
                   |   |                                     |
                   |   +---------------------------+         |
                   |                               |         |
                   v                               v         |
              +----+---+-------+                  [vulnerable]|
              |  Reviewer      |<-----------------------------+
              +----------------+
```

The conditional routing keeps the exploit node looping until a PoC succeeds or the retry counter hits `MAX_HYPOTHESES`, at which point the auditor spins up a new hypothesis. All Claude calls preserve the prompt order required for Anthropic prompt caching.

## Prerequisites

- Python **3.11+**
- Foundry (`forge`) installed and available on `PATH`
- Anthropic API key (set `ANTHROPIC_API_KEY` before running the agents)

## Setup

1. Copy the secure template: `cp .env.example .env` (or on Windows `copy .env.example .env`).
2. Populate `.env` with your keys (`ANTHROPIC_API_KEY`, `ETHERSCAN_API_KEY` if you plan to use `harvester.fetch_contract_source`).
3. Install dependencies: `pip install -r requirements.txt`.
4. Run the graph once Forge is configured: `python main_agent.py`.
5. For regenerating context data, use `python harvester.py <path>` or call `fetch_contract_source` directly for verified contracts.

## Troubleshooting

1. **Missing `forge` binary**: `tools.execute_foundry_poc` raises a `RuntimeError` if Forge is not installed. Install Foundry (`curl -L https://foundry.paradigm.xyz | bash`) and re-open the shell so `forge` is on your `PATH`.
2. **`ANTHROPIC_API_KEY` not set**: The LangChain Anthropic wrappers and `config.py` will fail fast if `.env` does not provide the key. Ensure `.env` exists and contains `ANTHROPIC_API_KEY=your_key` before running the graph.
3. **Context overflow errors**: If Claude rejections cite context limits, the error handler trims 20% of `raw_code` and retries. Consider limiting the target contract size, or feed smaller slices from the harvester before running the agents.

## Example Output

```
# Audit Report
Started: 2026-02-28T23:52:00Z
Status: VULNERABLE

## Recon Summary
[LLM recon summary text...]

## Hypotheses
- 1. EmergencyPause bypass (critical)

## Forge Runs
- Hypothesis: EmergencyPause bypass (critical) | Success: True | Exit: 0

## PoC
```solidity
contract AgentExploit is Test { ... }
```

## Logs
```
STDOUT:
Forge test output ...
STDERR:
```
```
```

## Testing

Run `pytest` to execute the validation suite (`tests/test_tools.py`, `tests/test_schemas.py`, `tests/test_state.py`).
