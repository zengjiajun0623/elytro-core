Confirmed the 1271 binding: line 665 binds `domSep` and `structHash` to `hash`, but `typeHash` (line 667) is read independently from calldata bytes [64:96] and never bound into `hash` — so a caller supplies an honest-looking benign typeHash while the structHash is actually a Permit. The blocklist at 667 inspects an unbound, attacker-supplied value. Decorative, as the finding states. And the CLI (line 698-704, 766) advertises "Call any Ethereum app out of the box (open mode), bounded by the realized-value cap" with no owed-value or recipient warning.

I have verified every load-bearing claim against the actual code and confirmed all PoCs pass. I now have everything needed to write the report.

I've verified the findings against the actual code and test suite. Here is the audit report.

---

## RESOLUTION STATUS — updated 2026-06-15 (post-audit fixes)

| Finding | Status |
|---|---|
| **HIGH-1** native prefund drain | **FIXED** — agent gas prefund is charged against the native cap in `validateUserOp` (reverts if uncapped/over-cap); owner unbounded. 4 regression tests; full suite green. |
| **HIGH-2** owed-value redirect | **PARTIALLY FIXED** — ERC-777 `operatorSend` added to the measured value-mover set; **target-scoped open mode** added to bound the agent's reach; invariant copy corrected to "bounds HELD assets, not OWED value". Residual (`claim`/`getReward`/`withdrawTo` to an attacker on an *approved* protocol) is structural to balance-based accounting — full closure needs per-protocol `recipient == self` pinning when real protocols are wired in. |
| **HIGH-3** standing-allowance sweep | **MITIGATED** — target-scoped open mode (`setOpenModeScoped` + `setOpenAllowedTarget`) bounds the agent to vetted targets, so it cannot reach an arbitrary sweep-router; docstring corrected. Operational precondition for *whole-chain* open mode remains: enable only when every held/approved token is protected. |
| **MEDIUM-1** 1271 typehash decorative | **DOC-CORRECTED** — the approved-DOMAIN allowlist is stated as the load-bearing bound; the typehash blocklist is labelled best-effort defense-in-depth (not bound to structHash). The CLI refuses to *produce* a value-auth signature. |
| **MEDIUM-2** JIT trusts `allowance()` | **DOC-CORRECTED** — the reset-assert is sound under an honest `allowance()` view (same trust class as the `balanceOf` oracle); JIT requires a protected (vetted) token. |

Full suite after fixes: **96 pass / 0 fail / 1 skipped.**

---

# elytro-core Security Audit — Agent-Native Smart Account (`AgentAccount.sol`)

**Date:** 2026-06-15 · **Scope:** `src/AgentAccount.sol`, the ERC-4337 paths, the ERC-1271 bounded-signing surface, and the `cli/elytro.ts` driver. **Threat model audited:** the one the contract states — the agent key is compromised; the owner (cold key) and the EntryPoint are honest.

---

## 1. HEADLINE — for the founder

**Verdict: keep it on testnet, do NOT take it to mainnet or real funds yet.** This is the right posture for a testnet, and the core idea is sound — but the contract's central marketing claim is currently overstated, and that gap is the thing to fix before anyone trusts it with money.

The whole pitch of this wallet is one promise: *"a compromised agent can move at most its remaining budget of each protected asset, no matter how the value is routed."* The audit found **3 confirmed HIGH-severity ways that promise is broken today**, plus several mediums. Every one of them is backed by an exploit test that actually runs and passes in this repo — I ran them. The good news: the failures are not random bugs, they are the *known edges* of the "measure the balance" approach, and the engine itself is correct for the assets it actually watches. The defenses that matter most (you can't grant a standing approval, the agent can't touch owner functions, the agent can't forge a real Permit signature, recovery can't be hijacked) all held under attack.

So: the foundation is real and the red-team was real. But the headline number you should remember is **3 confirmed HIGH issues where the cap can be skipped**, and until those are fixed, "bounded by the realized-value cap" is a claim the contract cannot fully back. Confirmed counts: **0 critical, 3 high, ~3 distinct medium, plus low/info.**

---

## 2. CONFIRMED ISSUES

### HIGH-1 — Native ETH drains through the 4337 prefund, skipping the native cap
**What the attacker does:** A compromised agent submits a UserOp with a huge `maxFeePerGas`. During `validateUserOp` (`AgentAccount.sol:406-409`), the account pays `missingAccountFunds` straight to the EntryPoint with `call{value: ...}`. This happens in the *validation* phase, before any cap logic runs, and is never charged against the agent's native cap. The PoC `test_PoC_AgentDrainsNativeViaPrefund_BypassingCap` passes — the agent moves native ETH the cap was supposed to bound.
**Fix:** In `validateUserOp`, when the operator is an agent (not the owner), bound the prefund: charge `missingAccountFunds` against the agent's native cap (`_charge(signer, address(0), missingAccountFunds)`) and revert if it exceeds the remaining budget, or cap the agent's permitted `maxFeePerGas × gasLimit` at validation time.
**Blocks further work?** **Yes for any deployment holding native ETH.** This is the cleanest, most direct cap bypass and the easiest to fix.

### HIGH-2 — Owed/deposited value redirected to an attacker recipient is uncharged, in BOTH modes, even when the token is protected
**What the attacker does:** The agent calls a protocol function that pays out to a *named recipient* — `claim(attacker)`, `getReward(attacker)`, `withdrawTo(attacker, amt)`, ERC-777 `operatorSend(...)`. The value (accrued rewards, or principal staked in a farm/vault) flows **protocol → attacker** and never transits the account's own balance. The realized-value engine only snapshots `address(this).balance` and `balanceOf(address(this))` over `protectedTokens` (`:524-548`), so the measured delta is zero, `_charge` returns early on `outflow == 0` (`:564`), and `spentTotal` stays 0. Confirmed: `test_Exfil_ClaimRewardsToAttacker`, `test_Exfil_WithdrawStakedPrincipalToAttacker`, `test_Exfil_ERC777_OperatorSend` all pass. **Protecting the token does not close it** — `test_ProtectedRewardStillLeaks` passes with the reward token protected and capped, because protecting a token bounds what the account *holds*, not what it is *owed* inside an external protocol. It also bites in **default allowlist mode**, not just open mode: `test_Exfil_AllowlistedClaim_AttackerRecipient` shows that an owner who allowlists a benign self-harvest `claim(address)` cannot stop the recipient arg being swapped, because the contract cannot inspect the argument by design.
**Fix:** This is a structural limitation of realized-balance accounting (it bounds held assets, not owed assets) — it cannot be closed by adding selectors. Mitigations, in order: (a) for recipient-taking functions, require the recipient argument to equal `address(this)` where the ABI is known, or maintain an allowlisted-recipient set; (b) most importantly, **correct the contract header (`:14-18`) and CLI copy** so the invariant is stated honestly as "bounds assets the account *holds*, not value it is *owed* inside external protocols." The current header and `cli/elytro.ts:698-704,766` ("Call any Ethereum app out of the box, bounded by the realized-value cap") materially overstate the guarantee for owed value.
**Blocks further work?** **Yes as a documentation/claims fix** (must ship before the invariant is advertised to users or investors). The full technical mitigation can be staged, but the overstated claim must be corrected now.

### HIGH-3 — Open-mode agent sweeps a held, unprotected token via a pre-existing standing allowance
**What the attacker does:** The owner once set a standing ERC-20 allowance on a token (e.g. DAI) that is held but **not** in `protectedTokens` — extremely common, since the product *itself relies on standing approvals* (`cli/elytro.ts:191,474`, `yieldBuy` pulls USDC via a standing approval). With open mode on and the agent compromised, the agent calls a router's `sweep(dai, account, attacker, amt)`. `sweep` is not forbidden, not a recognized value-mover (`_isValueMover`, `:598-606`), and the snapshot engine only iterates `protectedTokens`, so DAI is never measured. It leaves entirely uncharged via the router's internal `transferFrom`. PoC `test_Exfil_SweepUnprotectedViaStandingAllowance` passes with `spentTotal == 0`. This directly **falsifies the open-mode docstring claim** (`:505-507`: "a value-mover selector on a non-protected target still reverts ... so an unmeasured asset cannot leave unseen") — the asset leaves via a *non*-value-mover selector through indirection. Notably, this one *is* closed by protecting the token (the `transferFrom` then transits the account balance and is measured/capped), unlike HIGH-2.
**Fix:** Before open mode can be enabled for an agent, require that all held/approved tokens be in the protected (measured) set, and revoke standing allowances on unprotected tokens. Correct the overstated open-mode docstring.
**Blocks further work?** **Yes for open mode with real funds.** Open mode is the "call any app" surface, and the precondition (a live approval on an unprotected token) is the product's own normal state.

### MEDIUM-1 — ERC-1271 bounded-signing typehash blocklist is decorative, not cryptographically bound
**What the attacker does:** `isValidSignature` (`:649-669`) binds `domainSeparator` and `structHash` into the signed `hash` (`:665`), but reads `typeHash` from a *separate, attacker-controlled* calldata slice (`:661`, bytes [64:96]) and never binds it into `hash`. So an agent allowed to sign logins supplies a benign-looking `typeHash` to pass the `_isValueAuthTypehash` blocklist (`:667`) while the `structHash` is actually a value-authorizing Permit. The blocklist inspects a value the signer fully controls and that the signature does not commit to. PoC `test_PoC_TypehashBlocklistBypassed_RealPermitSignedAsBenign` passes. (The real safety here comes from the *approved-domain* gate at `:666` — a value type lives on a token/Permit2 domain the owner never approves — so this is defense-in-depth that doesn't work, not the last line.)
**Fix:** Derive `typeHash` from `structHash`'s actual leading word, or drop the blocklist and rely solely on the approved-domain bound (and document that the domain allowlist is the real control). Do not present the typehash blocklist as a security boundary.
**Blocks further work?** No, but fix before enabling agent signing broadly, and remove any copy that implies the typehash check protects users.

### MEDIUM-2 — JIT approve/reset side effects run outside the snapshot frame
**What the attacker does:** In `executeAsAgentJIT` (`:456-471`), `_approveChecked(token, spender, exactAllowance)` and the post-reset run *outside* the `_execAsAgent` snapshot window. The approve itself is an outflow-of-authority that the realized-value engine never sees; the rail's safety depends entirely on the post-call reset-and-assert (`:470-471`) succeeding. A token whose `allowance()` view lies (returns 0 while a real allowance persists) defeats the assert, leaving a standing allowance behind — the one thing the whole design forbids. This requires a malicious/non-standard token, but the JIT rail is sold as "provably leaves none behind."
**Fix:** Restrict JIT to a vetted, standards-compliant token set (already partly true: token must be protected), and document that the reset-assert's soundness is conditional on an honest `allowance()` view — same trust class as the realized-value `balanceOf` oracle.
**Blocks further work?** No. Bounded to malicious-token cases; track it.

---

## 3. WHAT WAS CHECKED AND HELD (the red-team was real)

These were attacked and survived — the audit tried to break each and failed:

- **Standing-allowance primitive is genuinely absent on the plain path.** `approve`, `increaseAllowance`, `setApprovalForAll`, both `permit` variants, `Permit2.approve`, and `transferFrom` are all forbidden selectors (`:592-595`). An agent cannot mint a standing drain on the normal rail. (`test_OpenMode_ApproveStillForbidden` passes.)
- **The realized-value engine is correct for the assets it watches.** Per-call gross netting means a later inflow/rebase/yield-claim cannot retroactively mask an earlier outflow (`:483-486`). Round-trips charge the account's real loss; self-minting a protected token costs the account nothing (dilution, not theft). No undercharge of *held* value was found.
- **In-call reentrancy cannot do a second outflow inside a snapshot window** — single shared `_locked` guard via `nonReentrant`.
- **The agent cannot forge a real Permit/3009 digest or a guardian/recovery digest.** The 1271 binding check (`:665`) is sound for what it binds; the agent cannot be made to sign an arbitrary external value digest. Length discriminator, signature malleability, off-length blobs, and the 256-byte slice handling all hold.
- **Open-mode agent stays a courier.** Self-call is forbidden (agent can never reach owner functions), the agent cannot self-enable open mode (`test_SetOpenMode_AgentCannotSelfEnable`), an unmeasured NFT cannot walk, ERC-777 `send` (the recognized mover) IS blocked on a non-protected target (control test passes), and over-cap transfers revert.
- **Guardian recovery is robust.** Threshold, class diversity, delay enforcement, owner veto, no-reschedule-while-pending, cancellation invalidating collected sigs, and post-rotation authority all pass (16/16 in `GuardianRecovery.t.sol`). The agent can *drive* recovery but cannot *authorize* it.
- **Storage layout of the appended open-mode/signing mappings does not collide** with `_caps` or existing storage; the monetary invariants still bound spend on the new paths.

---

## 4. PRIORITIZED FIX LIST

1. **HIGH-1 (prefund native drain)** — charge the agent prefund against the native cap in `validateUserOp`. Smallest, highest-leverage fix. Do first.
2. **HIGH-2 / HIGH-3 claims correction** — rewrite the contract header invariant (`:14-18`), the open-mode docstring (`:505-507`), and CLI copy (`elytro.ts:698-704,766`) to state the true boundary: *bounds held assets, not owed/external value*. This is a same-day change and stops the wallet from over-promising.
3. **HIGH-3 (unprotected standing-allowance sweep)** — gate open mode behind "all held/approved tokens are protected," and add allowance-hygiene to the CLI.
4. **HIGH-2 technical mitigation** — recipient-pinning (`recipient == address(this)`) or a recipient allowlist for recipient-taking selectors where the ABI is known.
5. **MEDIUM-1 (1271 typehash)** — bind typeHash to structHash or remove the decorative blocklist; lean on the domain allowlist and say so.
6. **MEDIUM-2 (JIT frame)** — document the JIT reset-assert trust assumption; keep JIT to vetted tokens.
7. **Housekeeping:** `test/RedTeamSigning.t.sol` does not compile and blocks a clean full `forge test` — fix or remove it so CI is green and future regressions are visible.

---

## 5. RESIDUAL RISKS TO WATCH AS THE PROJECT EVOLVES

- **Realized-value accounting is an oracle, and the oracle is `balanceOf`/`allowance`.** Every guarantee assumes protected tokens report balances honestly. A protected token with a lying `balanceOf` undercharges (owner-controlled trust assumption, but worth stating to users: protect only tokens you trust).
- **Owed-value is the permanent blind spot.** Any future integration where the account is *owed* value inside a protocol (staking rewards, vault shares redeemed to a recipient, options payouts) sits outside the cap. As Cleave-style options/positions get wired in, re-examine every recipient-taking call.
- **Selector blocklists are open-ended by nature.** New value-mover standards (more ERC-777-like `operatorSend` analogues, new Permit2 batch types — `PermitBatch`/`PermitBatchTransferFrom`/`AllowanceTransfer` are not in the 1271 blocklist even for an honest caller, Seaport/0x/CowSwap/4337 likewise) will need maintenance. Treat the blocklist as defense-in-depth, never as the boundary.
- **Open mode + standing approvals is structurally hazardous.** The product leans on standing approvals for yield flows; open mode removes the allowlist. The two together are the soil HIGH-3 grows in. Keep them apart, or keep every approved token measured.
- **Owner rotation leaves agent authority live** (bounded re-drain within caps) — expected, but note it in recovery UX so a recovered owner remembers to re-scope agents.

**Bottom line for the founder:** the engine is honest about the assets it watches and the red-team confirmed the hard parts hold. Fix HIGH-1, correct the over-stated invariant copy, and gate open mode — then "bounded by the realized-value cap" becomes a claim you can defend.

*Key files:* `/Users/jiajunzeng/elytro-core/src/AgentAccount.sol` (engine `:476-558`, charge `:563-589`, gates `:592-606`, prefund `:406-409`, JIT `:456-472`, 1271 `:649-675`), `/Users/jiajunzeng/elytro-core/cli/elytro.ts` (claims `:698-766`), PoCs under `/Users/jiajunzeng/elytro-core/test/` (`PrefundDrainPoC`, `PoCOpenModeExfil`, `PoCProtectedRewardStillLeaks`, `PoCUnprotectedPull`, `Sig1271TypehashPoC` — all passing).