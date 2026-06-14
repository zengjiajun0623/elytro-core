# elytro-core

A from-first-principles, **agent-native** Ethereum smart account. Clean-room rebuild — not derived from the existing Elytro CLI/contracts.

## Thesis

An AI agent should be able to operate a wallet on a human's behalf, but its authority must be bounded by **the contract refusing**, not by an LLM obeying prose or a backend staying honest.

The one hard invariant:

> A compromised agent can move at most its remaining per-tx / per-period / total budget of each protected asset, and nothing else — **regardless of how the value is routed.**

## The novel mechanism: realized-value enforcement

Every "agent spending limit" people ship tries to *decode the agent's calldata* to estimate how much value it moves. That is unsound: a router, a `multicall`, or an obfuscated/malicious token can move arbitrary value the decoder never sees. Allowlisting one DEX router authorizes unbounded movement.

`AgentAccount` does the opposite. Before the agent's calls it **snapshots the account's protected-asset balances**, executes, then asserts the **realized outflow** (balance delta) against the agent's caps. Value is bounded by what actually left, so the bound holds through any router, swap, or DeFi path.

The headline test, [`test_RealizedValueBeatsLyingCalldata`](test/AgentAccount.t.sol): a token whose `transfer(to, 1)` actually moves `1000` is still capped at `100` and reverts. A calldata-decoding limit would wave it through.

## Principals (on-chain-distinct)

| Principal | Authority | Enforcement |
|---|---|---|
| **owner (root)** | Anything. The human's cold key. Manages agents, caps, protected assets, recovery. Sole ERC-1271 signer. | `executeAsOwner` (onlyOwner); management `onlyOwnerOrSelf`. |
| **agent** | Only allowlisted `(target, selector)` calls, bounded by realized-value caps. Never the account itself, never ERC-20 approvals, never ERC-1271. | `executeAsAgent`: allowlist + forbidden-surface checks + realized-value charge. |

Why the agent restrictions matter:
- **No self-calls** → an agent can never reach an owner-management function.
- **No approvals** → no standing allowance, the canonical approve-then-drain primitive (a future pull the realized-value check wouldn't see).
- **Excluded from ERC-1271** → an agent that could sign off-chain (Permit / Permit2 / EIP-3009) would bypass every on-chain cap with zero on-chain footprint.
- **Uncapped protected asset must not decrease** → fail-safe: if the owner allowlists a token but forgets a cap, the account refuses rather than leaking.

## Status

- `src/AgentAccount.sol` — the account. ✅ 19/19 tests pass (`forge test`).
- Recovery (agent can *drive* but never *authorize*) — next.
- ERC-4337 EntryPoint integration, passkey (P256) root, on-chain capability as a 4337 validator — see the rebuild blueprint.

This is the spend-safety core (Phase 1 of the blueprint): a real on-chain cap that holds even if every off-chain service is gone.

## Run

```bash
forge test -vv
```
