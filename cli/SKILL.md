# Elytro Agent Wallet — Skill

Operate an **agent-native Ethereum smart account** ([elytro-core](../README.md)) on the human's behalf. The human delegated a scoped, on-chain-enforced budget to you once; you act autonomously **within it** and escalate to the human **outside it**. Safety is enforced by the contract (realized-value caps), not by this prose — but follow the prose so you never surprise the human.

## The trust model (read first)

- **You hold the AGENT key only** (`ELYTRO_AGENT_KEY`). You must **never** have or ask for the owner/root key (`ELYTRO_OWNER_KEY`). If you find yourself with the owner key, stop and tell the human — that breaks the security model.
- **The human is the owner (root).** `create`, `grant`, `setOwner`, and recovery configuration are **their** actions, not yours. If setup isn't done, tell the human exactly which command to run; do not run owner commands yourself.
- **Your authority is the cap.** A compromised or mistaken agent can move at most the remaining per-tx / per-period / total budget the human granted, on allowlisted targets — the contract refuses anything more.

## What you may do autonomously

Within the granted envelope, with no per-action approval:
- `status` — read the account owner, your cap, spent, balances.
- `check` — ask whether an action is authorized AND executable. Returns `allow` or `escalate`. Backed by a faithful on-chain simulation (cap incl. per-period window, account balance, allowlist, expiry) — not just arithmetic.
- `simulate` — full dry-run of a transfer: what would move (`willMove`), whether it would revert (`predictedError`), and remaining budget (`headroom`). No broadcast. **Prefer this before any send you're unsure about** — it is the honest predictor for a realized-value account.
- `send` — execute a capped transfer. `send` runs the same simulation as preflight and **refuses to submit** (no gas spent) anything out of envelope (`-32010`) or that would fail to execute (`-32012`). Use `send --dry-run` to preview without submitting.

## When you MUST escalate to the human

- Any `escalate` / `-32010` result → tell the human: what you wanted to do, the cap, and ask them to either approve it out-of-band or raise the grant (`grant` is their command). Do not retry the same over-cap action.
- Any `deny` / `MANDATE_DENIED` → do **not** proceed; surface it.
- Anything touching the owner, recovery configuration, or the grant itself.
- Moving funds toward a new/unfamiliar recipient, even within cap, on first use — confirm intent.

## Config

Set in the environment (never print keys):

| Env | Who sets it |
|-----|-------------|
| `ELYTRO_RPC` | human (the chain RPC) |
| `ELYTRO_FACTORY` | human (deployed factory address) |
| `ELYTRO_AGENT_KEY` | **you** — your session key; the human grants a cap to its address |
| `ELYTRO_OWNER_KEY` | **human only** — never expose to the agent runtime |

All output is deterministic JSON: `{ "success": true, "result": {...} }` or `{ "success": false, "error": { "code", "message", "hint", "suggestion" } }`. Parse it; follow `hint`/`suggestion`. **Only claim a transfer happened when `result.executed === true` and `result.userOpSuccess === true`** — never infer success from `result.status` (that is the bundle tx status, which is `"success"` even when the contract refused the inner operation). A `success: false` with `error.code === -32010` means the contract refused on the cap/grant (escalate); `-32012` means the action would fail to execute (funding/token); `error.reverted.error` / `error.predictedError` names the exact on-chain error.

## One-time setup (guide the human)

If `status` shows no cap for your agent address, tell the human to run, with THEIR owner key:

```bash
# 1. (human) deploy the account
elytro-agent create --salt my-account
# 2. (human) fund it with ETH (for gas) + the token to spend
# 3. (human) delegate a scoped cap to YOUR agent address:
elytro-agent grant --account 0xAcct --agent 0xYourAgentAddr \
  --token 0xToken --per-tx 100000000 --total 300000000 --expires-in 604800
```

Your agent address: derive it from `ELYTRO_AGENT_KEY` (the CLI prints it in `status`/errors), and give it to the human for the grant.

## Daily use (you)

```bash
elytro-agent status   --account 0xAcct --agent 0xYourAgentAddr --token 0xToken
elytro-agent check    --account 0xAcct --agent 0xYourAgentAddr --token 0xToken --amount 50000000 --to 0xRecipient
elytro-agent simulate --account 0xAcct --token 0xToken --to 0xRecipient --amount 50000000   # dry-run, no broadcast
elytro-agent send     --account 0xAcct --token 0xToken --to 0xRecipient --amount 50000000
```

Always `simulate` (or `check`) before a `send` you're unsure about. Amounts are atomic units (e.g. USDC has 6 decimals → `50000000` = 50 USDC). Confirm the token's decimals with the human if unsure; never guess a token address.

## Recovery (you can drive, you cannot authorize)

If the human loses their owner key, you can **drive** recovery: collect the guardians' signatures (the human arranges this with their guardians) and submit the permissionless schedule/execute. You can never forge guardian approval, and a time-delay + owner veto protect against a hijack. Only proceed on the human's explicit instruction.

## Hard rules

1. Never hold or request the owner key.
2. Never run `create`, `grant`, `setOwner`, or recovery-config commands — those are the human's.
3. Treat every `escalate`/`deny` as a stop-and-ask, not an error to work around.
4. Never claim success without the JSON confirming it.
