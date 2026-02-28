# web3AuditAgent (Bug Bounty Assistant, Defensive Mode)

LangGraph-based smart contract security assistant optimized for fast bug bounty triage and responsible disclosure workflows.

## Safety Scope

This project supports defensive work only:
- vulnerability triage
- duplicate-checking
- controlled reproducibility harnesses
- disclosure report drafting

It is not intended for real-world exploit automation.

## Pipeline

`harvester -> duplicate_guard -> triage -> recon -> auditor -> exploit -> failure_analyzer -> economics -> reviewer`

Fast exits:
- duplicate signal -> reviewer
- triage `skip` in fast mode -> reviewer

## Prompt Contract (Important)

`prompts.py` is JSON-first. Nodes should parse structured JSON, not free text.

### Auditor hypothesis JSON fields
- `title`
- `description`
- `vulnerability_type`: `reentrancy|overflow|access_control|oracle_manipulation|logic_error|flash_loan|front_running|other`
- `severity`: `CRITICAL|HIGH|MEDIUM|LOW`
- `affected_functions`: `string[]`
- `funds_at_risk_usd`: `number|null`
- `ease_of_exploitation`: `1..10`
- `attack_preconditions`: `string[]`
- `suggested_poc_approach`

### Other prompt-driven envelopes
- `triage`: `{ decision, rationale, confidence, signals[] }`
- `failure_analyzer`: `{ classification, root_cause, suggested_fix, confidence }`
- `economics`: `{ funds_at_risk_usd, estimated_bounty_usd, ... , recommendation }`
- `reviewer`: `{ report_md, platform_md, report_json }`

## Key Features

- Validated Anthropic model IDs:
  - `claude-3-5-haiku-20241022`
  - `claude-3-5-sonnet-20241022`
  - `claude-3-opus-20240229`
- Duplicate checks across Immunefi / HackenProof / Cantina (with fallback handling)
- Triage-first routing and parallel hypothesis fan-out
- Fork modes: `off`, `mainnet`, `anvil`
- Optional Tenderly simulation helper
- Economic viability scoring and recommendation
- SQLite caching for prior analysis and duplicate fingerprints
- Report bundle output (`report.md`, `report.json`, `immunefi.md`, `cantina.md`)

## File Map

- `main_agent.py`: graph orchestration + routing
- `prompts.py`: authoritative node prompt contracts
- `schemas.py`: vulnerability schema (uppercase severity + `attack_preconditions`)
- `state.py`: typed graph state models
- `tools.py`: Foundry execution + fork URL resolution + gas parsing
- `bounty_platforms.py`: platform clients and duplicate checks
- `exploit_economics.py`: viability calculations
- `report_generator.py`: report template helpers
- `contest_runner.py`: async batch triage/top-N selection
- `cache_manager.py`: SQLite cache layer

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env
```

Windows copy command:

```powershell
copy .env.example .env
```

## Required Environment Variables

- `ANTHROPIC_API_KEY`
- `RECON_MODEL`, `AUDIT_MODEL`, `EXPLOIT_MODEL`
- `FORGE_MODE` + one of `FORGE_FORK_URL|ALCHEMY_MAINNET_URL|INFURA_MAINNET_URL` (for `mainnet` mode)
- `ANVIL_RPC_URL` (for `anvil` mode)

Optional:
- `IMMUNEFI_API_KEY`, `HACKENPROOF_API_KEY`
- `TENDERLY_ENABLED`, `TENDERLY_ACCOUNT`, `TENDERLY_PROJECT`, `TENDERLY_ACCESS_KEY`

## Run

```bash
python main_agent.py
```

Programmatic:

```python
from main_agent import build_graph
from state import build_initial_state, as_graph_state

graph = build_graph()
state = build_initial_state(raw_code="contract Sample { function run() public {} }", platform_name="immunefi")
result = graph.invoke(as_graph_state(state))
print(result.get("report_directory"))
```

## Testing

```bash
pytest -q
```

## Outputs

Reports are written to:

`./reports/{timestamp}_{contract_name}/`

Artifacts:
- `report.md`
- `report.json`
- `immunefi.md`
- `cantina.md`