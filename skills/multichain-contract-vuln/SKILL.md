---
name: multichain-contract-vuln
description: "AI-powered smart contract security audit: analyzes EVM (Solidity/Vyper) and Solana (Anchor/Rust) contracts using LLM semantic analysis, producing multi-dimensional risk scores and a detailed vulnerability report."
---

## When to Use
- Audit a single Solidity/Vyper contract or Solana Anchor/Rust program.
- Batch-scan a directory of contract files.
- Generate structured vulnerability reports with risk scores and fix recommendations.

## Quick Start

```bash
# Analyze a local contract package (zip or directory)
python3 scripts/run_cli.py --input /path/to/contracts --chain evm --scope MyProject

# Fetch and audit an on-chain contract (requires ETHERSCAN_API_KEY)
python3 scripts/run_cli.py --evm-address 0x... --network mainnet --chain evm
```

## Analysis Method

This skill uses **LLM-only semantic analysis** (no Slither, Mythril, or Foundry required).

For each contract file the LLM evaluates five security dimensions:

| Dimension | What It Checks |
| --- | --- |
| Access Control | Ownership, roles, permission guards |
| Financial Security | Arithmetic safety, token transfer correctness |
| Randomness & Oracle | Weak randomness sources, oracle manipulation |
| DoS Resistance | Gas limits, griefing, blocking patterns |
| Business Logic | Logic flaws, invariant violations |

Each dimension receives a score (0–100). An overall score is derived from the dimension scores.

## On-Chain Source Retrieval (EVM)

When `--evm-address` is provided:
1. Fetches verified source from **Etherscan** (requires `ETHERSCAN_API_KEY` env var).
2. Falls back to **Sourcify** if no API key or Etherscan returns no result.
3. Writes sources to a temp directory and proceeds with LLM analysis.

## Output

- **`contract_audit.md`** — Full Markdown report with risk scores, critical findings, per-file analysis, and recommendations.
- **`contract_audit.log`** — Execution log for debugging.

## Notes
- Maximum 10 contract files per ZIP upload.
- Each file is truncated to 8 000 characters before being sent to the LLM; very large files may have reduced analysis coverage.
- Reports are always in English.
