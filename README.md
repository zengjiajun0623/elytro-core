# elytro-core

A from-first-principles, **agent-native** Ethereum smart account. Clean-room rebuild — not derived from the existing Elytro CLI/contracts.

## Thesis

An AI agent should be able to operate a wallet on a human's behalf, but its authority must be bounded by **the contract refusing**, not by an LLM obeying prose or a backend staying honest.

The one hard invariant:

> A compromised agent can move at most its remaining per-tx / per-period / total budget of each protected asset, and nothing else — **regardless of how the value is routed.**

## The novel mechanism: realized-value enforcement

Every "agent spending limit" people ship tries to *decode the agent's calldata* to estimate how much value it moves. That is unsound: a router, a `multicall`, or an obfuscated/malicious token can move arbitrary value the decoder never sees. Allowlisting one DEX router authorizes unbounded movement.

`AgentAccount` does the opposite. It snapshots the account's protected-asset balances **immediately before each call**, executes, and accumulates the **gross realized outflow** (per-call balance decrease) against the agent's caps. Value is bounded by what actually left, through any router, swap, or DeFi path — and because accounting is *gross-per-call*, not net-per-batch, a later inflow / rebase / yield-claim can never retroactively mask an earlier outflow.

The headline test, [`test_RealizedValueBeatsLyingCalldata`](test/AgentAccount.t.sol): a token whose `transfer(to, 1)` actually moves `1000` is still capped at `100` and reverts. A calldata-decoding limit would wave it through.

## Principals (on-chain-distinct)

| Principal | Authority | Enforcement |
|---|---|---|
| **owner (root)** | Anything. The human's cold key. Manages agents, caps, protected assets, recovery. Sole ERC-1271 signer. | `executeAsOwner` (onlyOwner); management `onlyOwnerOrSelf`. |
| **agent** | Only allowlisted `(target, selector)` calls, bounded by realized-value caps. Never the account itself, never ERC-20 approvals, never ERC-1271. | `executeAsAgent`: allowlist + forbidden-surface checks + realized-value charge. |

Why the agent restrictions matter:
- **No self-calls** → an agent can never reach an owner-management function.
- **Protected tokens only, `transfer` only** → an agent may move an ERC-20 only via `transfer` on a token in the protected set (so every move is measured + capped). It cannot move tokens outside that set, and cannot grant any standing allowance: `approve` / `increaseAllowance` / `setApprovalForAll` / `permit` / DAI-`permit` / Permit2-`approve` / `transferFrom` are all forbidden selectors — closing the approve-then-drain primitive a future pull would otherwise hide.
- **Excluded from ERC-1271** → an agent that could sign off-chain (Permit / Permit2 / EIP-3009) would bypass every on-chain cap with zero on-chain footprint.
- **Uncapped protected asset must not decrease** → fail-safe: if the owner allowlists a token but forgets a cap, the account refuses rather than leaking.
- **Malformed (1-3 byte) calldata rejected** → a "native send" grant can't be turned into a fallback call.

## Recovery: agent drives, guardians authorize

`src/GuardianRecovery.sol` proves the other half of the goal — **recover by agent**:

> The agent can *drive* recovery (assemble guardian signatures off-chain and submit the permissionless on-chain txs) but can never *authorize* it — only a threshold of distinct guardians can, after a time-delay during which the owner or any guardian may veto.

- `scheduleRecovery` is permissionless (the agent is a courier); it requires ≥ threshold distinct guardian signatures over an EIP-712 digest binding the full params (account, newOwner, nonce, delay).
- `cancelRecovery` (owner or any guardian) bumps a nonce, invalidating the scheduled recovery *and* any collected signatures.
- `executeRecovery` is permissionless after the delay; it rotates the owner via the account's `recoverOwner`, callable only by the wired module.

A successful owner rotation is total control, so the entire safety budget lives in (unforgeable cross-guardian sigs) + (delay) + (reachable veto). Tests cover courier-not-authorizer, below-threshold, duplicate-signer, delay, owner/guardian veto, replay-invalidation, and post-recovery control.

## ERC-4337

`AgentAccount` implements `IAccount` (v0.7/0.8 `PackedUserOperation`), so an agent operates it as a real account-abstraction wallet — gasless `UserOps` through a bundler — and is *still* bounded by the realized-value engine:

- `validateUserOp` recovers the signer and classifies it: **owner** → unrestricted (validationData 0); **active agent** → validationData packs the agent's `validAfter`/`validUntil` for the EntryPoint to enforce; anyone else → `SIG_VALIDATION_FAILED`. It's ERC-7562-clean (only own-storage reads, no external calls bar the EntryPoint prefund), so the capability/value checks run at *execution*, not validation.
- A transient operator hand-off carries the classified principal from `validateUserOp` to `executeUserOp`; `executeUserOp` then routes through the same owner / agent-capability paths. A second same-sender op in one bundle reverts rather than reuse the first's authority.
- Tested against a faithful `MockEntryPoint` (single-op validate→execute, sig + time-window honored). Wiring the canonical EntryPoint is a deploy-time step.

## Status

✅ **44/44 tests pass** (`forge test`) — `AgentAccount` (24) + `GuardianRecovery` (13) + `ERC4337` (7).

This is the on-chain core (blueprint Phases 1 + 3 + 4337 surface): caps and recovery that hold even if every off-chain Elytro service is gone.

### Security review

A multi-agent adversarial red-team (4 attacker lenses → skeptic verification → synthesis) was run against this code. It surfaced 15 verified findings; the exploitable ones are **fixed and regression-tested**:

| ID | Sev | Issue | Fix |
|----|-----|-------|-----|
| C1 | HIGH | Net-per-batch accounting let an in-batch inflow/rebase mask an outflow (charge ≈0) | Gross **per-call** accounting |
| C2 | HIGH | Approval ban was a 2-selector blocklist; `permit`/`setApprovalForAll`/Permit2 bypassed it | Expanded forbidden set + protected-token `transfer`-only |
| C3 | HIGH | `setGuardians` never cleared old guardians → removed guardians kept authority | Store + clear the active set |
| C4 | MED | Value exfil through a token outside the protected set | Agent `transfer` requires a protected token |
| C5 | LOW | 1-3 byte calldata routed to fallback under a NATIVE grant | Reject malformed calldata |
| C6 | LOW | `scheduleRecovery` replay reset the delay clock | Block reschedule while pending |
| U2 | LOW | Absurd delay could truncate (uint64) to the past | `MAX_DELAY` bound |

### Remaining (by design / documented)
- **Single-guardian veto** can grief recovery liveness (C7) — the deliberate veto tradeoff; harden with a veto quorum/cooldown later.
- **Fixed-window period cap** allows ~2× across a boundary (C8); the lifetime `total` cap bounds the worst case. A sliding window is the upgrade.
- **Compromised (not lost) owner key** can veto a guardian rescue — answered by step-up on high value, not yet built.
- Not yet: passkey (P256/WebAuthn) root, a CREATE2 factory for counterfactual deploys, integration against the canonical EntryPoint, USD-denominated caps, weighted/class-diverse guardians.

## Run

```bash
forge test -vv
```
