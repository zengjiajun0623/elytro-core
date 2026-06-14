# Let your Claude Code use the Elytro agent wallet (Cleave testnet)

This sets up an **agent-native smart account** on the Cleave testnet (chain `73571`, an anvil mainnet fork — test funds only, no real money). You (the human) stay the cold **owner**; your Claude Code becomes a **bounded agent** that can spend only within a cap you grant — enforced on-chain.

## Prereqs
- Node ≥ 18, and Claude Code.
- Test funds come from the faucet (free). No real ETH/USDC.

## 1. Install the CLI
```bash
npm i -g @elytro/agent-cli      # provides `elytro-agent`
```
The Cleave testnet RPC + factory are baked in as defaults — nothing else to configure.

## 2. Give Claude Code the skill
Copy this package's `SKILL.md` into your Claude Code skills (so your Claude knows the safe usage rules). Find it at:
```bash
npm root -g | xargs -I{} echo {}/@elytro/agent-cli/SKILL.md
```
Drop it in your project's `.claude/skills/elytro/SKILL.md` (or your global skills dir).

## 3. You (the human, owner) do the one-time setup

> Keep your **owner key secret** — never give it to Claude. Claude only ever gets the agent (session) key it generates itself.

```bash
# a) Make an owner key (or use any wallet) and export it (this shell only):
export ELYTRO_OWNER_KEY=0x...            # YOUR secret root key
OWNER=$(cast wallet address --private-key $ELYTRO_OWNER_KEY)   # or your wallet address

# b) Fund your owner address (for gas) via the faucet:
curl -s -X POST https://testnet.cleave.market/api/faucet \
  -H "Content-Type: application/json" -d "{\"address\":\"$OWNER\"}"

# c) Have Claude generate its agent key and tell you the address:
elytro-agent keygen          # prints { agent: 0xAGENT... }   (run as Claude / on Claude's machine)
AGENT=0x...                  # the printed agent address

# d) Create the smart account:
elytro-agent create --salt my-wallet      # prints { account: 0xACCT... }
ACCT=0x...

# e) Fund the account (USDC + gas) AND the agent (a little gas it fronts + gets refunded):
USDC=0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48
for a in $ACCT $AGENT; do
  curl -s -X POST https://testnet.cleave.market/api/faucet \
    -H "Content-Type: application/json" -d "{\"address\":\"$a\"}"; echo
done

# f) Delegate a scoped cap to the agent (100 USDC/tx, 300 total, 7-day expiry; USDC = 6 decimals):
elytro-agent grant --account $ACCT --agent $AGENT --token $USDC \
  --per-tx 100000000 --total 300000000 --expires-in 604800
```

## 4. Your Claude Code can now operate it

With **only** the agent key (no owner key in its environment):
```bash
elytro-agent status   --account $ACCT --agent $AGENT --token $USDC
elytro-agent check    --account $ACCT --agent $AGENT --token $USDC --amount 50000000   # allow | escalate
elytro-agent simulate --account $ACCT --token $USDC --to 0xRecipient --amount 50000000 # dry-run, no broadcast
elytro-agent send     --account $ACCT --token $USDC --to 0xRecipient --amount 50000000
```
- Within the cap → it just executes (no asking you).
- Over the cap → it refuses (`-32010`) and asks you to approve or raise the grant.
- It can never touch your owner key, raise its own cap, or rotate the owner.

## Reference (Cleave testnet)
| | |
|---|---|
| Chain id | `73571` |
| RPC (default) | `https://foundry-production-85dd.up.railway.app` |
| Factory (default) | `0xd7D5f4A79c5042161324376F37Dd3Db7bd3E5C2F` |
| EntryPoint v0.8 | `0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108` |
| USDC (6 dp) | `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48` |
| Faucet | `POST https://testnet.cleave.market/api/faucet {"address":...}` (needs `Content-Type: application/json`) → 10 ETH + 10k USDC |

This is a testnet. The agent's worst case is bounded by the cap you grant; your owner key (and real funds, if you ever deploy to mainnet) stay with you.
