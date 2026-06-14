// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IRecoverable {
    function owner() external view returns (address);
    function recoverOwner(address newOwner) external;
}

/**
 * @title GuardianRecovery
 * @notice Agent-drivable, guardian-authorized owner recovery for an AgentAccount.
 *
 * The recovery invariant: an agent can DRIVE recovery (assemble guardian
 * signatures off-chain and submit the permissionless on-chain txs) but can
 * never AUTHORIZE it — only a threshold of distinct guardians can, and only
 * after a time-delay during which the owner or any guardian may veto.
 *
 *   schedule  → permissionless; requires >= threshold distinct guardian sigs
 *               over an EIP-712 digest binding the FULL params (account,
 *               newOwner, nonce, delay). Starts the delay clock.
 *   cancel    → owner OR any guardian; bumps the nonce, invalidating the
 *               scheduled recovery AND any collected signatures.
 *   execute   → permissionless after the delay; rotates the account owner.
 *
 * Guardians never give the agent their keys, so the agent is a courier, not an
 * authorizer. The delay + veto defeat a hijacked recovery to attacker keys.
 */
contract GuardianRecovery {
    IRecoverable public immutable account;

    /// Upper bound on the recovery delay — guards against a units bug or an
    /// absurd value truncating when cast to uint64 in scheduleRecovery.
    uint256 public constant MAX_DELAY = 365 days;

    mapping(address => bool) public isGuardian;
    /// The active guardian set, kept explicitly so reconfiguration can CLEAR the
    /// previous set (a removed guardian must lose all authority).
    address[] private _guardianList;
    uint256 public guardianCount;
    uint256 public threshold;
    uint256 public delay;

    /// Bumped on every cancel/execute to invalidate prior signatures (replay-safe).
    uint256 public nonce;

    struct Pending {
        address newOwner;
        uint64 executeAfter;
        bool exists;
    }

    Pending public pending;

    bytes32 public immutable DOMAIN_SEPARATOR;
    bytes32 public constant RECOVERY_TYPEHASH =
        keccak256("Recovery(address account,address newOwner,uint256 nonce,uint256 delay)");

    event GuardiansSet(uint256 count, uint256 threshold);
    event DelaySet(uint256 delay);
    event RecoveryScheduled(address indexed newOwner, uint256 executeAfter, uint256 nonce);
    event RecoveryCancelled(uint256 newNonce);
    event RecoveryExecuted(address indexed newOwner);

    error NotRoot();
    error NotOwnerOrGuardian();
    error NoGuardians();
    error BadNewOwner();
    error SignersNotOrdered();
    error ThresholdNotMet(uint256 got, uint256 need);
    error NothingScheduled();
    error DelayNotElapsed(uint256 nowTs, uint256 executeAfter);
    error AlreadyScheduled();
    error DelayTooLong();

    constructor(IRecoverable _account, address[] memory guardians, uint256 _threshold, uint256 _delay) {
        account = _account;
        _setGuardians(guardians, _threshold);
        if (_delay > MAX_DELAY) revert DelayTooLong();
        delay = _delay;
        emit DelaySet(_delay);
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("ElytroGuardianRecovery"),
                keccak256("1"),
                block.chainid,
                address(this)
            )
        );
    }

    modifier onlyRoot() {
        if (msg.sender != account.owner()) revert NotRoot();
        _;
    }

    // ─── Root configuration ─────────────────────────────────────────

    function setGuardians(address[] calldata guardians, uint256 _threshold) external onlyRoot {
        _setGuardians(guardians, _threshold);
        _invalidate();
    }

    function setDelay(uint256 _delay) external onlyRoot {
        if (_delay > MAX_DELAY) revert DelayTooLong();
        delay = _delay;
        emit DelaySet(_delay);
        _invalidate();
    }

    // ─── Recovery lifecycle ─────────────────────────────────────────

    /// The EIP-712 digest guardians sign. Binds full params + current nonce.
    function recoveryDigest(address newOwner) public view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(RECOVERY_TYPEHASH, address(account), newOwner, nonce, delay));
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
    }

    /**
     * @notice Schedule a recovery. Permissionless — anyone (the agent) may
     *         submit, but only valid guardian signatures count.
     * @param signatures 65-byte ECDSA sigs, ordered by STRICTLY INCREASING
     *        signer address (guarantees distinct signers).
     */
    function scheduleRecovery(address newOwner, bytes[] calldata signatures) external {
        if (newOwner == address(0)) revert BadNewOwner();
        if (threshold == 0) revert NoGuardians();
        // Must explicitly cancel an in-flight recovery before scheduling another;
        // prevents a permissionless re-submit from resetting the delay clock.
        if (pending.exists) revert AlreadyScheduled();

        bytes32 d = recoveryDigest(newOwner);
        address last = address(0);
        uint256 count;
        for (uint256 i; i < signatures.length; i++) {
            address signer = _recover(d, signatures[i]);
            if (signer <= last) revert SignersNotOrdered();
            last = signer;
            if (isGuardian[signer]) count++;
        }
        if (count < threshold) revert ThresholdNotMet(count, threshold);

        pending = Pending({newOwner: newOwner, executeAfter: uint64(block.timestamp + delay), exists: true});
        emit RecoveryScheduled(newOwner, block.timestamp + delay, nonce);
    }

    /// Veto: the owner OR any guardian can cancel, invalidating collected sigs.
    function cancelRecovery() external {
        if (msg.sender != account.owner() && !isGuardian[msg.sender]) revert NotOwnerOrGuardian();
        _invalidate();
        emit RecoveryCancelled(nonce);
    }

    /// Execute after the delay. Permissionless (the agent submits).
    function executeRecovery() external {
        if (!pending.exists) revert NothingScheduled();
        if (block.timestamp < pending.executeAfter) revert DelayNotElapsed(block.timestamp, pending.executeAfter);
        address newOwner = pending.newOwner;
        _invalidate(); // clear + bump nonce before the external call (no replay)
        account.recoverOwner(newOwner);
        emit RecoveryExecuted(newOwner);
    }

    // ─── Internals ──────────────────────────────────────────────────

    function _setGuardians(address[] memory guardians, uint256 _threshold) internal {
        uint256 n = guardians.length;
        require(_threshold > 0 && _threshold <= n, "bad threshold");

        // Clear the PREVIOUS set first — a removed guardian must lose all
        // authority (it can otherwise still reach threshold or veto forever).
        uint256 oldLen = _guardianList.length;
        for (uint256 i; i < oldLen; i++) {
            isGuardian[_guardianList[i]] = false;
        }
        delete _guardianList;

        // Install the new set. Strictly ascending order guarantees distinctness.
        address last = address(0);
        for (uint256 i; i < n; i++) {
            address g = guardians[i];
            require(g > last, "guardians unordered/dup");
            last = g;
            isGuardian[g] = true;
            _guardianList.push(g);
        }
        guardianCount = n;
        threshold = _threshold;
        emit GuardiansSet(n, _threshold);
    }

    /// The active guardian set.
    function getGuardians() external view returns (address[] memory) {
        return _guardianList;
    }

    function _invalidate() internal {
        delete pending;
        unchecked {
            nonce++;
        }
    }

    function _recover(bytes32 d, bytes calldata sig) internal pure returns (address) {
        if (sig.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return address(0);
        }
        return ecrecover(d, v, r, s);
    }
}
