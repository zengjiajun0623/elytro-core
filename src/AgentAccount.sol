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
            if (_isForbiddenSelector(sel)) revert ApprovalForbidden();
            if (!allowedCall[agent][c.target][sel]) revert CallNotAllowlisted(c.target, sel);
            // An agent may only move tokens it is value-accounted for: `transfer`
            // is permitted only on a PROTECTED token (measured + capped below).
            // Closes value exfiltration through tokens outside the protected set.
            if (sel == TRANSFER_SEL && !isProtected[c.target]) revert UnprotectedTokenTransfer(c.target);

            // ── Snapshot protected balances immediately BEFORE this call ──
            uint256 nativeBefore = address(this).balance;
            uint256[] memory tokBefore = new uint256[](n);
            for (uint256 j; j < n; j++) {
                tokBefore[j] = _erc20BalanceOf(protectedTokens[j]);
            }

            // ── Execute ──
            (bool ok, bytes memory ret) = c.target.call{value: c.value}(c.data);
            if (!ok) revert CallFailed(i, ret);
            results[i] = ret;

            // ── Accumulate this call's gross decrease per protected asset ──
            uint256 nativeAfter = address(this).balance;
            if (nativeBefore > nativeAfter) outflow[0] += nativeBefore - nativeAfter;
            for (uint256 j; j < n; j++) {
                uint256 tokAfter = _erc20BalanceOf(protectedTokens[j]);
                if (tokBefore[j] > tokAfter) outflow[j + 1] += tokBefore[j] - tokAfter;
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

    function _erc20BalanceOf(address token) internal view returns (uint256) {
        (bool ok, bytes memory data) = token.staticcall(abi.encodeWithSelector(ERC20_BALANCEOF, address(this)));
        if (!ok || data.length < 32) revert BalanceQueryFailed(token);
        return abi.decode(data, (uint256));
    }

    // ─── ERC-1271 (owner-only) ──────────────────────────────────────

    /**
     * @notice Owner-only signature validation. Agents are deliberately EXCLUDED:
     *         an agent that could sign off-chain (Permit, Permit2, EIP-3009)
     *         would bypass every on-chain cap with zero on-chain footprint.
     */
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        address signer = _recover(hash, signature);
        return (signer != address(0) && signer == owner) ? ERC1271_MAGIC : bytes4(0xffffffff);
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
