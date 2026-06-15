// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IAccount, PackedUserOperation} from "./interfaces/IERC4337.sol";

/**
 * @title AgentAccount
 * @notice A from-first-principles, agent-native smart account.
 *
 * The thesis: an AI agent should be able to operate a wallet on a human's
 * behalf, but its authority must be bounded by *the contract refusing*, not
 * by an LLM obeying prose or a backend staying honest. The single hard
 * invariant this contract enforces:
 *
 *   A compromised agent can move at most its remaining per-tx / per-period /
 *   total budget of each protected asset, and nothing else — regardless of
 *   how the value is routed.
 *
 * The novel mechanism is REALIZED-VALUE enforcement: instead of trying to
 * decode an agent's calldata to guess how much value it moves (which is
 * unsound — a router, a multicall, or an obfuscated call can move arbitrary
 * value the decoder never sees), the account snapshots its protected-asset
 * balances before the agent's calls and asserts the realized outflow after.
 * Value is bounded by the balance delta, so it holds through any router or
 * DeFi path.
 *
 * Principals are on-chain-distinct:
 *   - owner (root): full power; the human's cold key. Manages agents, caps,
 *     the protected-asset set, and (later) recovery. Sole ERC-1271 signer.
 *   - agent(s): may only call allowlisted (target, selector) pairs, may never
 *     call this account itself (so it can never reach owner functions), may
 *     never grant ERC-20 allowances (no standing drain primitive), and is
 *     excluded from the ERC-1271 surface (no off-chain Permit/3009 bypass).
 */
contract AgentAccount is IAccount {
    // ─── Types ──────────────────────────────────────────────────────

    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    struct Agent {
        bool active;
        uint48 notBefore;
        uint48 expiresAt;
    }

    /// Per-(agent, asset) spend cap with running accounting. asset == address(0) is native.
    struct Cap {
        bool set;
        uint256 perTx; // max realized outflow per executeAsAgent call (0 = unlimited)
        uint256 perPeriod; // max realized outflow per rolling window (0 = unlimited)
        uint256 period; // window length in seconds (0 = no window)
        uint256 total; // max realized outflow over the cap's lifetime (0 = unlimited)
        // running state
        uint256 spentPeriod;
        uint48 periodStart;
        uint256 spentTotal;
    }

    // ─── Constants ──────────────────────────────────────────────────

    /// Selector used in the allowlist for a plain native-value send (empty calldata).
    bytes4 public constant NATIVE_SELECTOR = 0x00000000;
    /// Bound on the protected-asset set: caps per-call gas and the blast radius
    /// of a single sick token on the agent path (see _execAsAgent). (I3)
    uint256 public constant MAX_PROTECTED_TOKENS = 32;
    bytes4 private constant TRANSFER_SEL = 0xa9059cbb; // transfer(address,uint256)
    bytes4 private constant ERC1271_MAGIC = 0x1626ba7e;
    bytes4 private constant ERC20_BALANCEOF = 0x70a08231; // balanceOf(address)
    uint256 private constant SIG_VALIDATION_FAILED = 1; // ERC-4337 sentinel

    // Authorization-granting / pull selectors an agent may NEVER call. Selector
    // blocklists are open-ended by nature, so this is defense-in-depth on top of
    // the real control: an agent may only move PROTECTED tokens, and only via
    // `transfer` (see executeAsAgent), so a standing allowance can never form.
    bytes4 private constant APPROVE_SEL = 0x095ea7b3; // approve(address,uint256)
    bytes4 private constant INCREASE_ALLOWANCE_SEL = 0x39509351; // increaseAllowance(address,uint256)
    bytes4 private constant SET_APPROVAL_FOR_ALL_SEL = 0xa22cb465; // setApprovalForAll(address,bool)
    bytes4 private constant PERMIT_SEL = 0xd505accf; // EIP-2612 permit
    bytes4 private constant DAI_PERMIT_SEL = 0x8fcbaf0c; // DAI-style permit
    bytes4 private constant PERMIT2_APPROVE_SEL = 0x87517c45; // Permit2 approve
    bytes4 private constant TRANSFER_FROM_SEL = 0x23b872dd; // transferFrom(address,address,uint256)
    // Known token value-movers an agent may use only on a PROTECTED (measured) token.
    bytes4 private constant ERC777_SEND_SEL = 0x9bd9bbc6; // send(address,uint256,bytes)
    bytes4 private constant TRANSFER_AND_CALL_SEL = 0x4000aea0; // transferAndCall(address,uint256,bytes)
    bytes4 private constant TRANSFER_AND_CALL2_SEL = 0x1296ee62; // transferAndCall(address,uint256)
    // Additional value-mover selectors measured so an UNMEASURED asset cannot leave
    // unseen once the allowlist is optional (OPEN mode). Deny-default: each reverts
    // on a non-protected target via the value-mover gate in _execAsAgent.
    bytes4 private constant SAFE_TRANSFER_FROM_721_SEL = 0x42842e0e; // safeTransferFrom(address,address,uint256)
    bytes4 private constant SAFE_TRANSFER_FROM_721_DATA_SEL = 0xb88d4fde; // safeTransferFrom(address,address,uint256,bytes)
    bytes4 private constant SAFE_TRANSFER_FROM_1155_SEL = 0xf242432a; // safeTransferFrom(address,address,uint256,uint256,bytes)
    bytes4 private constant SAFE_BATCH_TRANSFER_1155_SEL = 0x2eb2c2d6; // safeBatchTransferFrom(...)
    bytes4 private constant ERC4626_WITHDRAW_SEL = 0xb460af94; // withdraw(uint256,address,address)
    bytes4 private constant ERC4626_REDEEM_SEL = 0xba087652; // redeem(uint256,address,address)
    bytes4 private constant WETH_WITHDRAW_SEL = 0x2e1a7d4d; // withdraw(uint256)
    bytes4 private constant ALLOWANCE_SELECTOR = 0xdd62ed3e; // allowance(address,address)
    // Value-authorizing EIP-712 primaryType hashes an agent may NEVER sign (these
    // move value off-chain with no on-chain footprint). Defense-in-depth on top of
    // the approved-domain bound (a value type lives on a token/Permit2 domain the
    // owner never approves anyway).
    bytes32 private constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
    bytes32 private constant DAI_PERMIT_TYPEHASH =
        keccak256("Permit(address holder,address spender,uint256 nonce,uint256 expiry,bool allowed)");
    bytes32 private constant TRANSFER_WITH_AUTH_TYPEHASH = keccak256(
        "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );
    bytes32 private constant RECEIVE_WITH_AUTH_TYPEHASH = keccak256(
        "ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );
    bytes32 private constant PERMIT2_TRANSFER_FROM_TYPEHASH = keccak256(
        "PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)TokenPermissions(address token,uint256 amount)"
    );
    bytes32 private constant PERMIT2_SINGLE_TYPEHASH = keccak256(
        "PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)"
    );

    // ─── Storage ────────────────────────────────────────────────────

    address public owner;

    /// The ERC-4337 EntryPoint allowed to drive validateUserOp / executeUserOp.
    address public immutable entryPoint;

    /// Authorized recovery module (a GuardianRecovery). The ONLY non-owner that
    /// may rotate the owner, and only via recoverOwner(). Set by root.
    address public recoveryModule;

    // Transient operator hand-off between validateUserOp and executeUserOp within
    // one tx. Transient storage auto-clears at tx end, so a failed/abandoned op
    // never bricks the account across txs. _operatorPending guards against a
    // second same-sender op in one bundle silently reusing the first's operator.
    address private transient _operator;
    bool private transient _operatorIsOwner;
    bool private transient _operatorPending;

    mapping(address => Agent) public agents;

    /// agent => target => selector => allowed
    mapping(address => mapping(address => mapping(bytes4 => bool))) public allowedCall;

    /// agent => asset(0=native) => cap
    mapping(address => mapping(address => Cap)) internal _caps;

    /// The set of assets whose outflow the realized-value check measures.
    /// Native is always protected implicitly; this list covers ERC-20s the
    /// account meaningfully holds. A protected ERC-20 with no cap for an agent
    /// MUST NOT decrease during that agent's execution.
    address[] public protectedTokens;
    mapping(address => bool) public isProtected;

    bool private _locked;

    /// agent => OPEN mode. When true, _execAsAgent skips the per-(target,selector)
    /// allowlist so the agent may call ANY non-self target — still bounded by the
    /// realized-value caps (only WHICH calls may be attempted widens, never how much
    /// value may leave). Appended at the end of storage to preserve the existing
    /// slot layout (and the Lean-proven _charge accounting it sits beside).
    mapping(address => bool) public openMode;

    /// agent => may produce BOUNDED ERC-1271 signatures (login / typed-data on an
    /// owner-approved domain). Off by default. The agent can never produce a
    /// value-authorizing signature; see isValidSignature.
    mapping(address => bool) public agentCanSign;
    /// EIP-712 domainSeparators the owner approved for agent signing. Approve ONLY
    /// login/session app domains, NEVER a token or Permit2 domain: that is the bound.
    mapping(bytes32 => bool) public approvedSignDomain;

    // ─── Events ─────────────────────────────────────────────────────

    event OwnerSet(address indexed previous, address indexed current);
    event RecoveryModuleSet(address indexed module);
    event AgentSet(address indexed agent, uint48 notBefore, uint48 expiresAt, bool active);
    event AgentRevoked(address indexed agent);
    event AllowedCallSet(address indexed agent, address indexed target, bytes4 selector, bool allowed);
    event CapSet(address indexed agent, address indexed asset, uint256 perTx, uint256 perPeriod, uint256 period, uint256 total);
    event ProtectedTokenSet(address indexed token, bool protectedState);
    event AgentExecuted(address indexed agent, uint256 calls);
    event Outflow(address indexed agent, address indexed asset, uint256 amount);
    event OpenModeSet(address indexed agent, bool on);
    event AgentCanSignSet(address indexed agent, bool on);
    event ApprovedSignDomainSet(bytes32 indexed domainSeparator, bool on);

    // ─── Errors ─────────────────────────────────────────────────────

    error NotOwner();
    error NotOwnerOrSelf();
    error NotRecoveryModule();
    error NotEntryPoint();
    error NoOperator();
    error OperatorPending();
    error Reentrancy();
    error AgentInactive();
    error AgentNotYetValid();
    error AgentExpired();
    error SelfCallForbidden();
    error ApprovalForbidden();
    error MalformedCalldata();
    error UnprotectedTokenTransfer(address token);
    error CallNotAllowlisted(address target, bytes4 selector);
    error CallFailed(uint256 index, bytes ret);
    error UncappedProtectedAssetMoved(address asset);
    error PerTxCapExceeded(address asset, uint256 outflow, uint256 cap);
    error PerPeriodCapExceeded(address asset, uint256 wouldSpend, uint256 cap);
    error TotalCapExceeded(address asset, uint256 wouldSpend, uint256 cap);
    error BalanceQueryFailed(address token);
    error ApproveResetFailed(address token, address spender);

    // ─── Constructor ────────────────────────────────────────────────

    constructor(address _owner, address _entryPoint) {
        require(_owner != address(0), "owner=0");
        owner = _owner;
        entryPoint = _entryPoint;
        emit OwnerSet(address(0), _owner);
    }

    // ─── Modifiers ──────────────────────────────────────────────────

    modifier onlyOwnerOrSelf() {
        if (msg.sender != owner && msg.sender != address(this)) revert NotOwnerOrSelf();
        _;
    }

    modifier onlyEntryPoint() {
        if (msg.sender != entryPoint) revert NotEntryPoint();
        _;
    }

    modifier nonReentrant() {
        if (_locked) revert Reentrancy();
        _locked = true;
        _;
        _locked = false;
    }

    // ─── Owner (root) management ────────────────────────────────────

    function setOwner(address newOwner) external onlyOwnerOrSelf {
        require(newOwner != address(0), "owner=0");
        require(!agents[newOwner].active, "owner is active agent"); // (I1) keep principals disjoint
        emit OwnerSet(owner, newOwner);
        owner = newOwner;
    }

    function setRecoveryModule(address module) external onlyOwnerOrSelf {
        recoveryModule = module;
        emit RecoveryModuleSet(module);
    }

    /**
     * @notice Rotate the owner via the authorized recovery module ONLY.
     * @dev This is how guardians restore access without the current owner key.
     *      The module enforces guardian threshold + time-delay + veto; this
     *      account just trusts the wired module to call it after that process.
     */
    function recoverOwner(address newOwner) external {
        if (recoveryModule == address(0) || msg.sender != recoveryModule) revert NotRecoveryModule();
        require(newOwner != address(0), "owner=0");
        require(!agents[newOwner].active, "owner is active agent"); // (I1) keep principals disjoint
        emit OwnerSet(owner, newOwner);
        owner = newOwner;
    }

    function setAgent(address agent, uint48 notBefore, uint48 expiresAt, bool active) external onlyOwnerOrSelf {
        require(agent != address(0) && agent != owner, "bad agent");
        agents[agent] = Agent({active: active, notBefore: notBefore, expiresAt: expiresAt});
        emit AgentSet(agent, notBefore, expiresAt, active);
    }

    function revokeAgent(address agent) external onlyOwnerOrSelf {
        agents[agent].active = false;
        emit AgentRevoked(agent);
    }

    function setAllowedCall(address agent, address target, bytes4 selector, bool allowed) external onlyOwnerOrSelf {
        require(target != address(this), "cannot allow self");
        allowedCall[agent][target][selector] = allowed;
        emit AllowedCallSet(agent, target, selector, allowed);
    }

    /// Enable OPEN mode for an agent: _execAsAgent skips the per-(target,selector)
    /// allowlist so the agent may interact with any Ethereum app out of the box —
    /// still bounded by the realized-value caps. Approvals stay reachable only via
    /// the reset-guaranteed executeAsAgentJIT rail, and value-mover selectors still
    /// revert on a non-protected target, so an unmeasured asset cannot leave.
    function setOpenMode(address agent, bool on) external onlyOwnerOrSelf {
        require(agent != address(0) && agent != owner, "bad agent");
        openMode[agent] = on;
        emit OpenModeSet(agent, on);
    }

    /// Let an agent produce BOUNDED ERC-1271 signatures (login/typed-data). The
    /// agent can sign only on owner-approved domains and never a value-authorizing
    /// message; see isValidSignature. Off by default.
    function setAgentCanSign(address agent, bool on) external onlyOwnerOrSelf {
        require(agent != address(0) && agent != owner, "bad agent");
        agentCanSign[agent] = on;
        emit AgentCanSignSet(agent, on);
    }

    /// Approve an EIP-712 domainSeparator the agent may sign for. Approve ONLY a
    /// login/session app domain; NEVER a token (Permit) or Permit2 domain.
    function setApprovedSignDomain(bytes32 domainSeparator, bool on) external onlyOwnerOrSelf {
        approvedSignDomain[domainSeparator] = on;
        emit ApprovedSignDomainSet(domainSeparator, on);
    }

    function setCap(
        address agent,
        address asset,
        uint256 perTx,
        uint256 perPeriod,
        uint256 period,
        uint256 total
    ) external onlyOwnerOrSelf {
        require(period != 0 || perPeriod == 0, "period required for perPeriod");
        Cap storage c = _caps[agent][asset];
        c.set = true;
        c.perTx = perTx;
        c.perPeriod = perPeriod;
        c.period = period;
        c.total = total;
        // reset running accounting on (re)configuration
        c.spentPeriod = 0;
        c.periodStart = uint48(block.timestamp);
        c.spentTotal = 0;
        emit CapSet(agent, asset, perTx, perPeriod, period, total);
    }

    function setProtectedToken(address token, bool protectedState) external onlyOwnerOrSelf {
        require(token != address(0), "native always protected");
        if (isProtected[token] == protectedState) return;
        isProtected[token] = protectedState;
        if (protectedState) {
            require(protectedTokens.length < MAX_PROTECTED_TOKENS, "too many protected tokens"); // (I3)
            protectedTokens.push(token);
        } else {
            uint256 n = protectedTokens.length;
            for (uint256 i; i < n; i++) {
                if (protectedTokens[i] == token) {
                    protectedTokens[i] = protectedTokens[n - 1];
                    protectedTokens.pop();
                    break;
                }
            }
        }
        emit ProtectedTokenSet(token, protectedState);
    }

    // ─── Execution: root ────────────────────────────────────────────

    /// Root path: the human's cold key can do anything. No value checks.
    function executeAsOwner(Call[] calldata calls) external nonReentrant returns (bytes[] memory) {
        if (msg.sender != owner) revert NotOwner();
        return _execArbitrary(calls);
    }

    /// Unrestricted execution (root authority). No caps.
    function _execArbitrary(Call[] calldata calls) internal returns (bytes[] memory results) {
        results = new bytes[](calls.length);
        for (uint256 i; i < calls.length; i++) {
            (bool ok, bytes memory ret) = calls[i].target.call{value: calls[i].value}(calls[i].data);
            if (!ok) revert CallFailed(i, ret);
            results[i] = ret;
        }
    }

    // ─── ERC-4337 (EntryPoint-driven) ───────────────────────────────

    /**
     * @notice Validate a UserOp for the EntryPoint. Stateless w.r.t. external
     *         calls (ERC-7562-clean): recover the signer and classify it as the
     *         owner (root) or an active agent. The capability + realized-value
     *         enforcement happens later, in executeUserOp.
     * @return validationData 0 (owner) | packed(validAfter,validUntil) (agent) |
     *         SIG_VALIDATION_FAILED.
     */
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        onlyEntryPoint
        returns (uint256 validationData)
    {
        // Refuse to overwrite an operator that a prior op in this bundle has not
        // yet consumed — prevents one op's authority being reused by another.
        if (_operatorPending) revert OperatorPending();

        address signer = _recover(userOpHash, userOp.signature);
        if (signer != address(0) && signer == owner) {
            _operatorIsOwner = true;
            _operatorPending = true;
            validationData = 0;
        } else if (signer != address(0) && agents[signer].active) {
            _operator = signer;
            _operatorPending = true;
            // EntryPoint enforces the time window from the packed validationData.
            validationData = _packValidation(agents[signer].notBefore, agents[signer].expiresAt);
        } else {
            validationData = SIG_VALIDATION_FAILED;
        }

        if (missingAccountFunds > 0) {
            (bool ok,) = payable(msg.sender).call{value: missingAccountFunds}("");
            ok; // ignore; EntryPoint reverts on its own accounting if underpaid
        }
    }

    /// Execution entry the EntryPoint calls. Applies the authority that
    /// validateUserOp classified for this op (owner = unrestricted, agent =
    /// capability + realized-value bounded).
    function executeUserOp(Call[] calldata calls) external onlyEntryPoint nonReentrant returns (bytes[] memory) {
        if (!_operatorPending) revert NoOperator();
        bool isOwner = _operatorIsOwner;
        address op = _operator;
        _operatorPending = false;
        _operatorIsOwner = false;
        _operator = address(0);
        return isOwner ? _execArbitrary(calls) : _execAsAgent(op, calls);
    }

    function _packValidation(uint48 validAfter, uint48 validUntil) internal pure returns (uint256) {
        // ERC-4337 layout: authorizer(160) | validUntil(48) | validAfter(48).
        // authorizer = 0 on success.
        return (uint256(validAfter) << 208) | (uint256(validUntil) << 160);
    }

    // ─── Execution: agent (capability-bounded) ──────────────────────

    /**
     * @notice Execute calls under the caller's agent capability.
     * @dev Authority is bounded by realized balance delta over the protected
     *      asset set — not by trusting calldata. A compromised agent cannot
     *      exceed its caps via any routing.
     */
    function executeAsAgent(Call[] calldata calls) external nonReentrant returns (bytes[] memory) {
        return _execAsAgent(msg.sender, calls);
    }

    /**
     * @notice Execute agent calls behind a JUST-IN-TIME, self-resetting allowance,
     *         so deposit/swap apps that pull via transferFrom work out of the box
     *         without a standing allowance ever forming.
     * @dev Approves EXACTLY `exactAllowance` of a MEASURED `token` to `spender`,
     *      runs `calls` under the same realized-value frame as executeAsAgent, then
     *      forces the allowance back to 0 and ASSERTS it. The spender's transferFrom
     *      pull is measured as a token outflow and charged against the agent's cap,
     *      so the worst case is unchanged: at most the remaining cap of `token`
     *      leaves. The plain-path approve ban (_isForbiddenSelector) stays intact —
     *      this is the ONLY route by which an agent allowance exists, and it provably
     *      leaves none behind.
     */
    function executeAsAgentJIT(address spender, address token, uint256 exactAllowance, Call[] calldata calls)
        external
        nonReentrant
        returns (bytes[] memory results)
    {
        if (spender == address(this) || spender == owner) revert SelfCallForbidden();
        // token must be measured (so the pull is charged via the realized-value engine).
        if (!isProtected[token]) revert UnprotectedTokenTransfer(token);
        // never stack on an existing standing allowance.
        if (_readAllowance(token, spender) != 0) revert ApproveResetFailed(token, spender);
        // approve EXACTLY the batch's required pull (not max) to bound the mid-tx window.
        _approveChecked(token, spender, exactAllowance);
        results = _execAsAgent(msg.sender, calls);
        // force the allowance back to zero and PROVE none survives.
        _approveChecked(token, spender, 0);
        if (_readAllowance(token, spender) != 0) revert ApproveResetFailed(token, spender);
    }

    /// Capability + realized-value enforcement, shared by the direct path
    /// (executeAsAgent) and the EntryPoint path (executeUserOp, agent-mode).
    function _execAsAgent(address agent, Call[] calldata calls) internal returns (bytes[] memory results) {
        Agent memory a = agents[agent];
        if (!a.active) revert AgentInactive();
        if (block.timestamp < a.notBefore) revert AgentNotYetValid();
        if (block.timestamp > a.expiresAt) revert AgentExpired();

        uint256 n = protectedTokens.length;
        // Accumulated GROSS outflow: index 0 = native, 1..n = protectedTokens[i-1].
        // Gross-per-call (not net-per-batch): a later inflow / rebase / yield-claim
        // can never retroactively mask an earlier outflow.
        uint256[] memory outflow = new uint256[](n + 1);

        results = new bytes[](calls.length);
        for (uint256 i; i < calls.length; i++) {
            Call calldata c = calls[i];

            // ── Per-call authorization ──
            if (c.target == address(this)) revert SelfCallForbidden();
            // 1-3 bytes of data is neither a clean 4-byte selector nor a native
            // send; it would route to the target fallback under a NATIVE-only
            // grant. Reject so a value-send grant cannot authorize a fallback call.
            if (c.data.length > 0 && c.data.length < 4) revert MalformedCalldata();
            bytes4 sel = c.data.length == 0 ? NATIVE_SELECTOR : bytes4(c.data);
            // (L1) A NATIVE (value-send) grant must authorize ONLY genuinely
            // empty calldata — never a zero-prefixed 4+ byte fallback call.
            if (sel == NATIVE_SELECTOR && c.data.length != 0) revert MalformedCalldata();
            if (_isForbiddenSelector(sel)) revert ApprovalForbidden();
            // OPEN mode skips the per-(target,selector) allowlist. The realized-value
            // engine below stays the value bound: any outflow of a measured asset is
            // charged against the cap, and a value-mover selector on a NON-protected
            // target still reverts (UnprotectedTokenTransfer), so an unmeasured asset
            // cannot leave unseen. Approvals are unreachable here (forbidden above) and
            // exist only via the reset-guaranteed executeAsAgentJIT rail.
            if (!openMode[agent] && !allowedCall[agent][c.target][sel]) revert CallNotAllowlisted(c.target, sel);
            // An agent may only move tokens it is value-accounted for: a known
            // value-mover selector is permitted only on a PROTECTED token
            // (measured + capped below). Closes value exfiltration through tokens
            // outside the protected set. NOTE: this is a best-effort blocklist of
            // common movers; the owner remains responsible for not allowlisting an
            // exotic value-mover on a non-protected token (see setAllowedCall).
            if (_isValueMover(sel) && !isProtected[c.target]) revert UnprotectedTokenTransfer(c.target);
            // (M1) Moving a PROTECTED token requires a readable balance so its cap
            // can be enforced; if unreadable, block THIS call only.
            if (_isValueMover(sel) && isProtected[c.target]) {
                (bool okTarget,) = _tryBalanceOf(c.target);
                if (!okTarget) revert BalanceQueryFailed(c.target);
            }

            // ── Snapshot protected balances immediately BEFORE this call ──
            uint256 nativeBefore = address(this).balance;
            uint256[] memory tokBefore = new uint256[](n);
            bool[] memory okBefore = new bool[](n);
            for (uint256 j; j < n; j++) {
                (okBefore[j], tokBefore[j]) = _tryBalanceOf(protectedTokens[j]);
            }

            // ── Execute ──
            (bool ok, bytes memory ret) = c.target.call{value: c.value}(c.data);
            if (!ok) revert CallFailed(i, ret);
            results[i] = ret;

            // ── Accumulate this call's gross decrease per protected asset ──
            // (M1) A token unreadable before OR after is skipped, not fatal: a sick
            // token cannot be moved by an agent call that does not target it (only
            // the account can move its own tokens, and that path is checked above).
            uint256 nativeAfter = address(this).balance;
            if (nativeBefore > nativeAfter) outflow[0] += nativeBefore - nativeAfter;
            for (uint256 j; j < n; j++) {
                (bool okAfter, uint256 tokAfter) = _tryBalanceOf(protectedTokens[j]);
                if (okBefore[j] && okAfter && tokBefore[j] > tokAfter) {
                    outflow[j + 1] += tokBefore[j] - tokAfter;
                }
            }
        }

        // ── Enforce caps on the accumulated gross outflow ──
        _charge(agent, address(0), outflow[0]);
        for (uint256 j; j < n; j++) {
            _charge(agent, protectedTokens[j], outflow[j + 1]);
        }

        emit AgentExecuted(agent, calls.length);
    }

    // ─── Realized-value accounting ──────────────────────────────────

    /// Charge an agent's accumulated gross outflow of one protected asset against its cap.
    function _charge(address agent, address asset, uint256 outflow) internal {
        if (outflow == 0) return; // no realized outflow — nothing to charge

        Cap storage c = _caps[agent][asset];
        // A protected asset that moves with no cap for this agent is unauthorized.
        if (!c.set) revert UncappedProtectedAssetMoved(asset);

        if (c.perTx != 0 && outflow > c.perTx) revert PerTxCapExceeded(asset, outflow, c.perTx);

        if (c.period != 0 && c.perPeriod != 0) {
            if (block.timestamp >= uint256(c.periodStart) + c.period) {
                c.periodStart = uint48(block.timestamp);
                c.spentPeriod = 0;
            }
            if (c.spentPeriod + outflow > c.perPeriod) {
                revert PerPeriodCapExceeded(asset, c.spentPeriod + outflow, c.perPeriod);
            }
            c.spentPeriod += outflow;
        }

        if (c.total != 0 && c.spentTotal + outflow > c.total) {
            revert TotalCapExceeded(asset, c.spentTotal + outflow, c.total);
        }
        c.spentTotal += outflow;

        emit Outflow(agent, asset, outflow);
    }

    /// Authorization-granting / pull selectors an agent may never call.
    function _isForbiddenSelector(bytes4 sel) internal pure returns (bool) {
        return sel == APPROVE_SEL || sel == INCREASE_ALLOWANCE_SEL || sel == SET_APPROVAL_FOR_ALL_SEL
            || sel == PERMIT_SEL || sel == DAI_PERMIT_SEL || sel == PERMIT2_APPROVE_SEL || sel == TRANSFER_FROM_SEL;
    }

    /// Known token value-mover selectors — permitted only on a PROTECTED token.
    function _isValueMover(bytes4 sel) internal pure returns (bool) {
        return sel == TRANSFER_SEL || sel == ERC777_SEND_SEL || sel == TRANSFER_AND_CALL_SEL
            || sel == TRANSFER_AND_CALL2_SEL
            // Extended mover universe so OPEN mode cannot let an unmeasured asset walk
            // (each reverts on a non-protected target).
            || sel == SAFE_TRANSFER_FROM_721_SEL || sel == SAFE_TRANSFER_FROM_721_DATA_SEL
            || sel == SAFE_TRANSFER_FROM_1155_SEL || sel == SAFE_BATCH_TRANSFER_1155_SEL
            || sel == ERC4626_WITHDRAW_SEL || sel == ERC4626_REDEEM_SEL || sel == WETH_WITHDRAW_SEL;
    }

    /// approve(spender, amount) tolerating non-bool-returning tokens; reverts on
    /// an explicit `false`. Used only by the JIT rail (token is owner-vetted/protected).
    function _approveChecked(address token, address spender, uint256 amount) internal {
        (bool ok, bytes memory ret) = token.call(abi.encodeWithSelector(APPROVE_SEL, spender, amount));
        if (!ok || (ret.length >= 32 && !abi.decode(ret, (bool)))) revert ApproveResetFailed(token, spender);
    }

    /// allowance(this, spender); returns 0 on any read failure (JIT requires a
    /// protected, standards-compliant token, so a sound read is expected).
    function _readAllowance(address token, address spender) internal view returns (uint256) {
        (bool ok, bytes memory ret) = token.staticcall(abi.encodeWithSelector(ALLOWANCE_SELECTOR, address(this), spender));
        if (!ok || ret.length < 32) return 0;
        return abi.decode(ret, (uint256));
    }

    /// Non-reverting balanceOf(this). Returns (false, 0) on any failure so a
    /// single sick protected token can't brick unrelated agent calls. (M1)
    function _tryBalanceOf(address token) internal view returns (bool ok, uint256 bal) {
        bytes memory data;
        (ok, data) = token.staticcall(abi.encodeWithSelector(ERC20_BALANCEOF, address(this)));
        if (!ok || data.length < 32) return (false, 0);
        return (true, abi.decode(data, (uint256)));
    }

    // ─── ERC-1271 ───────────────────────────────────────────────────

    /**
     * @notice Signature validation.
     *  - OWNER: unrestricted, over a plain 65-byte ECDSA signature.
     *  - AGENT (bounded login signing): a 256-byte structured blob carrying the
     *    EIP-712 envelope, so the contract proves ON-CHAIN what was signed:
     *      [0:32] domainSeparator | [32:64] structHash | [64:96] primaryTypeHash | [160:225] 65-byte sig
     *    Valid ONLY when the recomputed EIP-712 digest equals `hash`, the domain is
     *    owner-approved, the type is NOT value-authorizing, and the signer is an
     *    active agent with agentCanSign. So a compromised agent can prove a login on
     *    an approved app but can NEVER produce a value-moving signature: Permit /
     *    Permit2 / EIP-3009 live on a token/Permit2 domain the owner never approves,
     *    AND their typehashes are explicitly blocklisted even on an approved domain.
     *    Opaque personal_sign / eth_sign (a bare 65-byte sig) stays OWNER-ONLY,
     *    because its preimage cannot be inspected on-chain.
     */
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        if (signature.length == 65) {
            address s = _recover(hash, signature);
            return (s != address(0) && s == owner) ? ERC1271_MAGIC : bytes4(0xffffffff);
        }
        if (signature.length == 256) {
            bytes32 domSep;
            bytes32 structHash;
            bytes32 typeHash;
            assembly {
                domSep := calldataload(signature.offset)
                structHash := calldataload(add(signature.offset, 32))
                typeHash := calldataload(add(signature.offset, 64))
            }
            // Bind the supplied envelope to the queried hash: prove it IS this exact
            // EIP-712 (domain, struct). Then enforce the agent's signing bounds.
            if (keccak256(abi.encodePacked("\x19\x01", domSep, structHash)) != hash) return bytes4(0xffffffff);
            if (!approvedSignDomain[domSep]) return bytes4(0xffffffff);
            if (_isValueAuthTypehash(typeHash)) return bytes4(0xffffffff);
            address s = _recover(hash, signature[160:225]);
            if (s != address(0) && agentCanSign[s] && agents[s].active) return ERC1271_MAGIC;
        }
        return bytes4(0xffffffff);
    }

    /// EIP-712 types that authorize a value movement — forbidden to agents.
    function _isValueAuthTypehash(bytes32 t) internal pure returns (bool) {
        return t == PERMIT_TYPEHASH || t == DAI_PERMIT_TYPEHASH || t == TRANSFER_WITH_AUTH_TYPEHASH
            || t == RECEIVE_WITH_AUTH_TYPEHASH || t == PERMIT2_TRANSFER_FROM_TYPEHASH || t == PERMIT2_SINGLE_TYPEHASH;
    }

    /// 65-byte ECDSA recovery with EIP-2 low-s enforcement. Returns address(0)
    /// on any malformed/high-s/invalid signature.
    function _recover(bytes32 hash, bytes calldata signature) internal pure returns (address) {
        if (signature.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return address(0);
        }
        return ecrecover(hash, v, r, s);
    }

    // ─── Views ──────────────────────────────────────────────────────

    function getCap(address agent, address asset) external view returns (Cap memory) {
        return _caps[agent][asset];
    }

    function protectedTokenCount() external view returns (uint256) {
        return protectedTokens.length;
    }

    receive() external payable {}
}
