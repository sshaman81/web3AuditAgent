# web3AuditAgent — Defensive Bug Bounty Assistant

LangGraph-based smart contract security assistant tuned for confident triage, duplicate detection, reproducible PoCs, and structured disclosure drafts. It is intentionally defensive — no exploit automation.

## Overview

- **Zero surprise**: prompts and nodes only speak JSON, so downstream routing stays deterministic.
- **LLM agnostic**: supported Anthropic/Claude models plus Codex/OpenAI options via `LLM_PROVIDER`.
- **Evidence-rich**: includes past comparison/precision bugs from [EVM Research](https://evmresearch.io/index) and caches LLM replies to minimize cost.
- **Language-safe**: all prompts rehydrate through LangChain/Anthropic or LangChain/OpenAI wrappers with a shared memory bank and circuit-breaker middleware.

## Quick Start

1. Install dependencies:

    ```bash
    pip install -r requirements.txt
    ```

2. Copy the environment template:

    ```bash
    cp .env.example .env
    ```

    On Windows (PowerShell):

    ```powershell
    copy .env.example .env
    ```

3. Fill the required API keys (Anthropic or OpenAI) and model IDs.

## Project Layout

- `src/web3audit/` — packaged agent logic (nodes, prompts, cache, platform clients, helpers). Import it via `from web3audit import ...`.
- `tests/` — pytest suite now imports through `web3audit.*`.
- `reports/` — runtime artifact directory (`report.md`, `report.json`, `immunefi.md`, `cantina.md` per run).
- `main_agent.py` — legacy wrapper that prepends `src` to `sys.path` and gates `python main_agent.py`.

## Architecture

1. **Graph orchestration** (`StateGraph` pipeline) runs: harvester → duplicate guard → triage → recon → auditor → exploit → failure analysis → economics → reviewer.
2. **LLM wrappers** use `_build_llm()` to instantiate Anthropic or OpenAI clients and `_invoke_llm_cached()` to consult the memory bank before invoking.
3. **Cache layer** (SQLite) stores recon summaries, duplicate fingerprints, and LLM responses (`CacheManager` in `src/web3audit/cache_manager.py`).
4. **EVM Research context** optionally appends curated comparison-bug links to recon/auditor prompts.

## Environment Variables

### Required

- `LLM_PROVIDER`: `anthropic` or `openai`.
- `ANTHROPIC_API_KEY` *or* `OPENAI_API_KEY` depending on provider.
- `RECON_MODEL`, `AUDIT_MODEL`, `EXPLOIT_MODEL` set to the model IDs you want to run (Claude IDs are enforced while `LLM_PROVIDER=anthropic`).

### Optional but recommended

- `OPENAI_BASE_URL`: for Codex gateways/proxies.
- `EVMRESEARCH_ENABLED`, `EVMRESEARCH_INDEX_URL`, `EVMRESEARCH_TIMEOUT_SECONDS`, `EVMRESEARCH_MAX_REFS`: control the historical comparison-bug feed.
- `MEMORY_BANK_ENABLED`, `MEMORY_BANK_VERSION`: toggle and version the LLM memory cache.
- `FORGE_MODE`, `FORGE_FORK_URL`, `ALCHEMY_MAINNET_URL`, `INFURA_MAINNET_URL`, `ANVIL_RPC_URL`: configure Foundry forks.
- `TARGET_CONTEXT_FILE`: path to a reusable context file produced by `scripts/prepare_target_context.py`.

## Target context cache

1. Clone or copy the Solidity target repository somewhere (for example `targets/my-target/`).
2. Run `python scripts/prepare_target_context.py targets/my-target --main contracts/Main.sol --output targets/my-target/context.txt`.
   This bundles the README plus every `.sol` file into `context.txt`.
3. Point the agent to it:

   ```
   TARGET_CONTEXT_FILE=/full/path/targets/my-target/context.txt PYTHONPATH=src python -m web3audit.main_agent
   ```
- `IMMUNEFI_API_KEY`, `HACKENPROOF_API_KEY`, `TENDERLY_*`: optional platform integrations.

## Running

### Preferred

```bash
PYTHONPATH=src python -m web3audit.main_agent
```

### Legacy-compatible

```bash
python main_agent.py
```

`main_agent.py` monkey-patches `sys.path` so the legacy entrypoint resolves even without `PYTHONPATH`.

## Programmatic Usage

```python
from web3audit.main_agent import build_graph
from web3audit.state import build_initial_state, as_graph_state

graph = build_graph()
state = build_initial_state(
    raw_code="contract Sample { function run() public {} }",
    platform_name="immunefi",
)
result = graph.invoke(as_graph_state(state))
print(result["report_directory"])
```

## Testing

```bash
PYTHONPATH=src pytest -q
```

## Outputs

Results live under:

```text
./reports/{timestamp}_{contract_name}/
```

Artifacts per run:

- `report.md`: final markdown narrative.
- `report.json`: structured audit payload.
- `immunefi.md` / `cantina.md`: platform-specific drafts.

## Troubleshooting & Tips

- **Memory collisions**: bump `MEMORY_BANK_VERSION` when you change prompt wording to force LLM cache invalidation.
- **Slow recon**: check `CACHE_DB_PATH` (default `./audit_cache.sqlite3`) to reuse previous summaries.
- **Failed forks**: ensure `ANVIL_RPC_URL` or valid mainnet fork URLs are reachable when `FORGE_MODE=anvil/mainnet`.
- **LLM failures**: the circuit-breaker middleware logs per-node failures in structured JSON via the `pythonjsonlogger` formatter.

## Contribution & Tracking

- Keep tests green (`PYTHONPATH=src pytest -q`) before merging.
- Add new prompt contracts under `src/web3audit/prompts.py` and document schema changes in README.
- For new nodes add targeted tests in `tests/` and update `tests/test_evmresearch.py` or `tests/test_cache_manager.py` as needed.

## License

No license yet. Add `LICENSE` if you plan to publish this repository publicly.
