# web3AuditAgent (Bug Bounty Assistant, Defensive Mode)

LangGraph-based smart contract security assistant optimized for fast bug bounty triage and responsible disclosure workflows.

## Safety Scope

This project is designed for:
- Defensive vulnerability discovery
- Duplicate-checking against bounty platforms
- Controlled reproducibility testing in local/forked environments
- Report generation for responsible submission

It is **not** intended to automate real-world exploitation.

## Core Workflow

The graph keeps the core pipeline and adds speed gates:

`harvester -> duplicate_guard -> triage -> recon -> auditor -> exploit -> failure_analyzer -> economics -> reviewer`

Fast exits:
- Duplicate found: skip deep run
- Triage says low value: skip deep run in fast mode

## Key Features

- Validated Anthropic model configuration (`claude-3-5-haiku-20241022`, `claude-3-5-sonnet-20241022`, `claude-3-opus-20240229`)
- Triage-first routing for <10s signal checks
- Platform duplicate checks for Immunefi, HackenProof, and Cantina
- Parallel hypothesis testing with LangGraph fan-out
- Economic viability scoring (`funds_at_risk_usd`, profitability assumptions)
- Foundry execution with fork modes:
  - `off`
  - `mainnet` (Alchemy/Infura/env URL)
  - `anvil` (local RPC)
- Optional Tenderly simulation helper
- Structured report bundle output:
  - `report.md`
  - `report.json`
  - `immunefi.md`
  - `cantina.md`
- SQLite caching for analysis/pattern/duplicate fingerprints

## Project Structure

- `main_agent.py`: LangGraph orchestration + routing logic
- `config.py`: strict settings + validation
- `tools.py`: Foundry execution, gas parsing, fork URL resolution, Tenderly helper
- `bounty_platforms.py`: platform clients and duplicate checks
- `exploit_economics.py`: viability calculations
- `report_generator.py`: platform-oriented report templates
- `contest_runner.py`: async batch triage and top-3 selection
- `cache_manager.py`: SQLite cache layer
- `state.py`: Pydantic state models + typed graph state
- `schemas.py`: vulnerability schema with risk/ease fields
- `prompts.py`: defensive triage/audit/exploit-validation prompts

## Requirements

- Python 3.11+
- Foundry (`forge`) on PATH
- Anthropic API key

Install:

```bash
pip install -r requirements.txt
```

## Environment Setup

Copy the template:

```bash
cp .env.example .env
```

(or Windows: `copy .env.example .env`)

Important vars:
- `ANTHROPIC_API_KEY`
- `RECON_MODEL`, `AUDIT_MODEL`, `EXPLOIT_MODEL`
- `FAST_MODE`, `MAX_HYPOTHESES`, `MAX_PARALLEL_CONTRACTS`
- `FORGE_MODE`, `FORGE_FORK_URL`, `ALCHEMY_MAINNET_URL`, `INFURA_MAINNET_URL`, `ANVIL_RPC_URL`
- `IMMUNEFI_API_KEY`, `HACKENPROOF_API_KEY` (optional depending on endpoint access)
- `TENDERLY_*` (optional)

## Running

Single run:

```bash
python main_agent.py
```

Programmatic usage:

```python
from main_agent import build_graph
from state import build_initial_state, as_graph_state

graph = build_graph()
state = build_initial_state(raw_code="contract Sample { function run() public {} }", platform_name="immunefi")
result = graph.invoke(as_graph_state(state))
print(result.get("report_directory"))
```

## Contest Batch Triage

Use `contest_runner.py` utilities to triage many targets in parallel (up to `MAX_PARALLEL_CONTRACTS`) and pick top candidates for deeper analysis.

## Testing

Run:

```bash
pytest -q
```

Current suite includes:
- schema validation
- tool execution behavior
- utility/state checks
- exploit economics calculations

## Output Artifacts

Reports are saved under:

`./reports/{timestamp}_{contract_name}/`

With:
- `report.md`
- `report.json`
- `immunefi.md`
- `cantina.md`