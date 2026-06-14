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
 * never AUTHORIZE it — only guardians can, and only after a time-delay during
 * which the owner or any guardian may veto.
 *
 * Guardians are WEIGHTED and CLASSED. A schedule requires both:
 *   - total weight of distinct valid guardian signers >= `threshold`, AND
 *   - the signers span >= `minClasses` distinct classes.
 * So compromising one whole category (e.g. all of a user's agents, or all
 * email guardians) cannot by itself reach threshold.
 */
contract GuardianRecovery {
    struct GuardianSpec {
        address addr;
        uint96 weight;
        uint8 classId; // 0-255; e.g. 0=human EOA, 1=hardware, 2=agent, 3=email
    }

    IRecoverable public immutable account;

    /// Upper bound on the recovery delay — guards against a units bug or an
    /// absurd value truncating when cast to uint64 in scheduleRecovery.
    uint256 public constant MAX_DELAY = 365 days;

    mapping(address => bool) public isGuardian;
    mapping(address => uint96) public guardianWeight;
    mapping(address => uint8) public guardianClass;
    address[] private _guardianList;

    /// Minimum total signer weight required to schedule a recovery.
    uint256 public threshold;
    /// Minimum number of distinct guardian classes that must sign.
    uint8 public minClasses;
    uint256 public delay;

    /// Bumped on every cancel/execute/reconfig to invalidate prior signatures.
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

    event GuardiansSet(uint256 count, uint256 threshold, uint8 minClasses);
    event DelaySet(uint256 delay);
    event RecoveryScheduled(address indexed newOwner, uint256 executeAfter, uint256 nonce);
    event RecoveryCancelled(uint256 newNonce);
    event RecoveryExecuted(address indexed newOwner);

    error NotRoot();
    error NotOwnerOrGuardian();
    error NoGuardians();
    error BadNewOwner();
    error SignersNotOrdered();
    error ThresholdNotMet(uint256 gotWeight, uint256 needWeight);
    error ClassDiversityNotMet(uint256 gotClasses, uint256 needClasses);
    error NothingScheduled();
    error DelayNotElapsed(uint256 nowTs, uint256 executeAfter);
    error AlreadyScheduled();
    error DelayTooLong();
    error BadConfig();

    constructor(
        IRecoverable _account,
        GuardianSpec[] memory specs,
        uint256 _threshold,
        uint8 _minClasses,
        uint256 _delay
    ) {
        account = _account;
        _setGuardians(specs, _threshold, _minClasses);
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

    function setGuardians(GuardianSpec[] calldata specs, uint256 _threshold, uint8 _minClasses) external onlyRoot {
        _setGuardians(specs, _threshold, _minClasses);
        _invalidate();
    }

    function setDelay(uint256 _delay) external onlyRoot {
        if (_delay > MAX_DELAY) revert DelayTooLong();
        delay = _delay;
        emit DelaySet(_delay);
        _invalidate();
    }

    // ─── Recovery lifecycle ─────────────────────────────────────────

    /// The EIP-712 digest guardians sign. Binds full params + current nonce
    /// (reconfiguring guardians/threshold/delay bumps the nonce, killing old sigs).
    function recoveryDigest(address newOwner) public view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(RECOVERY_TYPEHASH, address(account), newOwner, nonce, delay));
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
    }

    /**
     * @notice Schedule a recovery. Permissionless — anyone (the agent) may
     *         submit, but only valid guardian signatures count toward the
     *         weight threshold and class-diversity requirement.
     * @param signatures 65-byte ECDSA sigs, ordered by STRICTLY INCREASING
     *        signer address (guarantees distinct signers).
     */
    function scheduleRecovery(address newOwner, bytes[] calldata signatures) external {
        if (newOwner == address(0)) revert BadNewOwner();
        if (threshold == 0) revert NoGuardians();
        if (pending.exists) revert AlreadyScheduled();

        bytes32 d = recoveryDigest(newOwner);
        address last = address(0);
        uint256 weightSum;
        uint256 classBits;
        for (uint256 i; i < signatures.length; i++) {
            address signer = _recover(d, signatures[i]);
            if (signer <= last) revert SignersNotOrdered();
            last = signer;
            if (isGuardian[signer]) {
                weightSum += guardianWeight[signer];
                classBits |= (uint256(1) << guardianClass[signer]);
            }
        }
        if (weightSum < threshold) revert ThresholdNotMet(weightSum, threshold);
        uint256 classes = _popcount(classBits);
        if (classes < minClasses) revert ClassDiversityNotMet(classes, minClasses);

        pending = Pending({newOwner: newOwner, executeAfter: uint64(block.timestamp + delay), exists: true});
        emit RecoveryScheduled(newOwner, block.timestamp + delay, nonce);
    }

    /// Veto: the owner OR any current guardian can cancel, invalidating sigs.
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

    // ─── Views ──────────────────────────────────────────────────────

    function getGuardians() external view returns (address[] memory) {
        return _guardianList;
    }

    function guardianCount() external view returns (uint256) {
        return _guardianList.length;
    }

    // ─── Internals ──────────────────────────────────────────────────

    function _setGuardians(GuardianSpec[] memory specs, uint256 _threshold, uint8 _minClasses) internal {
        uint256 n = specs.length;
        if (_threshold == 0 || _minClasses == 0 || n == 0) revert BadConfig();

        // Clear the PREVIOUS set first — a removed guardian must lose all
        // authority (it can otherwise still reach threshold or veto forever).
        uint256 oldLen = _guardianList.length;
        for (uint256 i; i < oldLen; i++) {
            address g = _guardianList[i];
            isGuardian[g] = false;
            guardianWeight[g] = 0;
            guardianClass[g] = 0;
        }
        delete _guardianList;

        // Install the new set. Strictly ascending order guarantees distinctness.
        address last = address(0);
        uint256 totalWeight;
        uint256 classBits;
        for (uint256 i; i < n; i++) {
            GuardianSpec memory g = specs[i];
            require(g.addr > last, "guardians unordered/dup");
            require(g.weight > 0, "zero weight");
            last = g.addr;
            isGuardian[g.addr] = true;
            guardianWeight[g.addr] = g.weight;
            guardianClass[g.addr] = g.classId;
            _guardianList.push(g.addr);
            totalWeight += g.weight;
            classBits |= (uint256(1) << g.classId);
        }
        // The set must be able to satisfy its own rules.
        if (totalWeight < _threshold) revert BadConfig();
        if (_popcount(classBits) < _minClasses) revert BadConfig();

        threshold = _threshold;
        minClasses = _minClasses;
        emit GuardiansSet(n, _threshold, _minClasses);
    }

    function _invalidate() internal {
        delete pending;
        unchecked {
            nonce++;
        }
    }

    function _popcount(uint256 x) internal pure returns (uint256 c) {
        while (x != 0) {
            x &= (x - 1);
            c++;
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
