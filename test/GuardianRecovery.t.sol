// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {AgentAccount} from "../src/AgentAccount.sol";
import {GuardianRecovery, IRecoverable} from "../src/GuardianRecovery.sol";

contract GuardianRecoveryTest is Test {
    AgentAccount account;
    GuardianRecovery recovery;

    uint256 ownerPk = 0xA11CE;
    uint256 agentPk = 0xBEEF;
    address owner;
    address agent;
    address rescuer = makeAddr("rescuer");
    address bob = makeAddr("bob");

    uint256[] gpks; // guardian private keys, sorted by signer address ascending
    address[] gaddrs;

    uint256 constant DELAY = 2 days;
    uint256 constant THRESHOLD = 2;

    function setUp() public {
        owner = vm.addr(ownerPk);
        agent = vm.addr(agentPk);

        // Three guardians, sorted by address (the module requires ascending order).
        uint256[] memory pks = new uint256[](3);
        pks[0] = 0xA1;
        pks[1] = 0xB2;
        pks[2] = 0xC3;
        _sortByAddr(pks);
        gpks = pks;
        gaddrs = new address[](3);
        for (uint256 i; i < 3; i++) gaddrs[i] = vm.addr(gpks[i]);

        account = new AgentAccount(owner, address(0xE17240E1)); // EntryPoint unused here
        vm.deal(address(account), 10 ether);

        recovery = new GuardianRecovery(IRecoverable(address(account)), gaddrs, THRESHOLD, DELAY);
        vm.prank(owner);
        account.setRecoveryModule(address(recovery));
    }

    // ── helpers ──────────────────────────────────────────────────

    function _sortByAddr(uint256[] memory pks) internal pure {
        for (uint256 i = 1; i < pks.length; i++) {
            uint256 key = pks[i];
            address ka = vm.addr(key);
            uint256 j = i;
            while (j > 0 && vm.addr(pks[j - 1]) > ka) {
                pks[j] = pks[j - 1];
                j--;
            }
            pks[j] = key;
        }
    }

    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    /// k distinct guardian sigs over the current digest, ascending by address.
    function _guardianSigs(address newOwner, uint256 k) internal view returns (bytes[] memory sigs) {
        bytes32 d = recovery.recoveryDigest(newOwner);
        sigs = new bytes[](k);
        for (uint256 i; i < k; i++) sigs[i] = _sign(gpks[i], d);
    }

    function _one(address t, uint256 v, bytes memory d) internal pure returns (AgentAccount.Call[] memory a) {
        a = new AgentAccount.Call[](1);
        a[0] = AgentAccount.Call(t, v, d);
    }

    // ── the core: agent drives, guardians authorize ──────────────

    function test_AgentDrivesRecoveryEndToEnd() public {
        bytes[] memory sigs = _guardianSigs(rescuer, THRESHOLD);

        // A non-guardian agent submits the guardian-signed schedule (courier).
        vm.prank(agent);
        recovery.scheduleRecovery(rescuer, sigs);

        vm.warp(block.timestamp + DELAY);

        // Anyone (the agent) submits execute.
        vm.prank(agent);
        recovery.executeRecovery();

        assertEq(account.owner(), rescuer);
    }

    function test_AgentCannotAuthorize() public {
        // The agent signs with its OWN key — it is not a guardian.
        bytes32 d = recovery.recoveryDigest(rescuer);
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = _sign(agentPk, d);
        vm.prank(agent);
        vm.expectRevert(abi.encodeWithSelector(GuardianRecovery.ThresholdNotMet.selector, uint256(0), THRESHOLD));
        recovery.scheduleRecovery(rescuer, sigs);
    }

    function test_BelowThresholdReverts() public {
        bytes[] memory sigs = _guardianSigs(rescuer, 1); // only 1 guardian
        vm.expectRevert(abi.encodeWithSelector(GuardianRecovery.ThresholdNotMet.selector, uint256(1), THRESHOLD));
        recovery.scheduleRecovery(rescuer, sigs);
    }

    function test_DuplicateGuardianRejected() public {
        bytes32 d = recovery.recoveryDigest(rescuer);
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _sign(gpks[0], d);
        sigs[1] = _sign(gpks[0], d); // same signer twice → not strictly increasing
        vm.expectRevert(GuardianRecovery.SignersNotOrdered.selector);
        recovery.scheduleRecovery(rescuer, sigs);
    }

    // ── time-delay + veto (anti-theft) ───────────────────────────

    function test_DelayEnforced() public {
        bytes[] memory sigs = _guardianSigs(rescuer, THRESHOLD);
        recovery.scheduleRecovery(rescuer, sigs);
        vm.expectRevert(); // DelayNotElapsed
        recovery.executeRecovery();
    }

    function test_OwnerVeto() public {
        bytes[] memory sigs = _guardianSigs(rescuer, THRESHOLD);
        recovery.scheduleRecovery(rescuer, sigs);
        vm.prank(owner);
        recovery.cancelRecovery();
        vm.warp(block.timestamp + DELAY);
        vm.expectRevert(GuardianRecovery.NothingScheduled.selector);
        recovery.executeRecovery();
        assertEq(account.owner(), owner);
    }

    function test_GuardianVeto() public {
        bytes[] memory sigs = _guardianSigs(rescuer, THRESHOLD);
        recovery.scheduleRecovery(rescuer, sigs);
        vm.prank(gaddrs[0]);
        recovery.cancelRecovery();
        vm.warp(block.timestamp + DELAY);
        vm.expectRevert(GuardianRecovery.NothingScheduled.selector);
        recovery.executeRecovery();
    }

    // ── replay safety: cancel invalidates collected signatures ───

    function test_CancelInvalidatesCollectedSigs() public {
        bytes[] memory sigs = _guardianSigs(rescuer, THRESHOLD); // signed over nonce 0
        recovery.scheduleRecovery(rescuer, sigs);
        vm.prank(owner);
        recovery.cancelRecovery(); // nonce → 1

        // The same old signatures no longer validate (digest changed with nonce).
        vm.expectRevert(abi.encodeWithSelector(GuardianRecovery.ThresholdNotMet.selector, uint256(0), THRESHOLD));
        recovery.scheduleRecovery(rescuer, sigs);
    }

    // ── post-recovery control + module isolation ─────────────────

    function test_NewOwnerControlsOldOwnerDoesNot() public {
        bytes[] memory sigs = _guardianSigs(rescuer, THRESHOLD);
        recovery.scheduleRecovery(rescuer, sigs);
        vm.warp(block.timestamp + DELAY);
        recovery.executeRecovery();

        // New owner can drive the root path.
        vm.prank(rescuer);
        account.executeAsOwner(_one(bob, 1 ether, ""));
        assertEq(bob.balance, 1 ether);

        // Old owner is locked out.
        vm.prank(owner);
        vm.expectRevert(AgentAccount.NotOwner.selector);
        account.executeAsOwner(_one(bob, 1 ether, ""));
    }

    function test_OnlyRecoveryModuleCanRotate() public {
        vm.prank(agent);
        vm.expectRevert(AgentAccount.NotRecoveryModule.selector);
        account.recoverOwner(rescuer);
    }

    // ── REGRESSION (red-team fixes) ──────────────────────────────

    // C3: reconfiguring guardians must CLEAR the old set — a removed guardian
    // loses all authority and can no longer count toward threshold.
    function test_C3_SetGuardiansClearsOldSet() public {
        address dropped = gaddrs[0];

        // New set = {g1, g2} (drop g0), still threshold 2, ascending order.
        address[] memory ng = new address[](2);
        ng[0] = gaddrs[1];
        ng[1] = gaddrs[2];
        vm.prank(owner);
        recovery.setGuardians(ng, 2);

        assertFalse(recovery.isGuardian(dropped), "dropped guardian must be cleared");
        assertTrue(recovery.isGuardian(gaddrs[1]));
        assertTrue(recovery.isGuardian(gaddrs[2]));

        // Sigs from {dropped g0, g1} now reach only 1 valid guardian → below threshold.
        bytes32 d = recovery.recoveryDigest(rescuer);
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _sign(gpks[0], d); // dropped
        sigs[1] = _sign(gpks[1], d); // current
        vm.expectRevert(abi.encodeWithSelector(GuardianRecovery.ThresholdNotMet.selector, uint256(1), uint256(2)));
        recovery.scheduleRecovery(rescuer, sigs);

        // The current set {g1, g2} still works.
        bytes[] memory good = new bytes[](2);
        good[0] = _sign(gpks[1], d);
        good[1] = _sign(gpks[2], d);
        recovery.scheduleRecovery(rescuer, good);
    }

    // C6: cannot re-submit a schedule while one is pending (no delay-clock reset).
    function test_C6_CannotRescheduleWhilePending() public {
        bytes[] memory sigs = _guardianSigs(rescuer, THRESHOLD);
        recovery.scheduleRecovery(rescuer, sigs);
        vm.expectRevert(GuardianRecovery.AlreadyScheduled.selector);
        recovery.scheduleRecovery(rescuer, sigs);
    }

    // U2: an absurd delay (would truncate to the past) is rejected.
    function test_U2_DelayTooLongRejected() public {
        vm.prank(owner);
        vm.expectRevert(GuardianRecovery.DelayTooLong.selector);
        recovery.setDelay(type(uint64).max);
    }
}
