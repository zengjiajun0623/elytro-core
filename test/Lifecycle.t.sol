// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {AgentAccount} from "../src/AgentAccount.sol";
import {AgentAccountFactory} from "../src/AgentAccountFactory.sol";
import {GuardianRecovery, IRecoverable} from "../src/GuardianRecovery.sol";
import {PackedUserOperation} from "../src/interfaces/IERC4337.sol";
import {MockEntryPoint} from "./mocks/MockEntryPoint.sol";
import {MockERC20} from "./mocks/Mocks.sol";

/// End-to-end: the whole agent-first lifecycle across every component —
/// counterfactual deploy, agent operation via the EntryPoint bounded by caps,
/// owner revocation, and agent-driven guardian recovery.
contract LifecycleTest is Test {
    MockEntryPoint ep;
    AgentAccountFactory factory;
    AgentAccount account;
    GuardianRecovery recovery;
    MockERC20 usdc;

    uint256 ownerPk = 0xA11CE;
    uint256 agentPk = 0xB0B;
    uint256 newOwnerPk = 0xC0FFEE;
    address owner;
    address agent;
    address newOwner;
    address bob = makeAddr("bob");

    uint256[] gpks;
    address[] gaddrs;

    bytes4 constant TRANSFER = MockERC20.transfer.selector;

    function setUp() public {
        owner = vm.addr(ownerPk);
        agent = vm.addr(agentPk);
        newOwner = vm.addr(newOwnerPk);

        uint256[] memory pks = new uint256[](3);
        pks[0] = 0xA1;
        pks[1] = 0xB2;
        pks[2] = 0xC3;
        _sortByAddr(pks);
        gpks = pks;
        gaddrs = new address[](3);
        for (uint256 i; i < 3; i++) gaddrs[i] = vm.addr(gpks[i]);

        ep = new MockEntryPoint();
        factory = new AgentAccountFactory(address(ep));
        usdc = new MockERC20("USD Coin", "USDC");
    }

    function test_FullAgentFirstLifecycle() public {
        // 1. Counterfactual deploy. Recovery module is bound to the predicted
        //    address before the account even exists.
        bytes32 salt = bytes32(uint256(42));
        address predicted = factory.getAddress(owner, salt);
        recovery = new GuardianRecovery(IRecoverable(predicted), gaddrs, 2, 2 days);

        address acctAddr = factory.createAccount(owner, salt);
        assertEq(acctAddr, predicted, "counterfactual address mismatch");
        account = AgentAccount(payable(acctAddr));

        // Fund the freshly deployed account.
        usdc.mint(acctAddr, 1000e18);
        vm.deal(acctAddr, 10 ether);

        // 2. Owner (cold root) provisions: protect USDC, register the agent with
        //    a capability (per-tx 100, lifetime 300), wire recovery.
        vm.startPrank(owner);
        account.setProtectedToken(address(usdc), true);
        account.setAgent(agent, 0, uint48(block.timestamp + 30 days), true);
        account.setAllowedCall(agent, address(usdc), TRANSFER, true);
        account.setCap(agent, address(usdc), 100e18, 0, 0, 300e18);
        account.setRecoveryModule(address(recovery));
        vm.stopPrank();

        // 3. Agent operates via the EntryPoint (gasless UserOp), within cap.
        _runOp(agentPk, _transfer(bob, 50e18));
        assertEq(usdc.balanceOf(bob), 50e18);
        assertEq(account.getCap(agent, address(usdc)).spentTotal, 50e18);

        // 4. Agent over-cap UserOp is refused on-chain.
        _expectRunRevert(
            agentPk,
            _transfer(bob, 150e18),
            abi.encodeWithSelector(AgentAccount.PerTxCapExceeded.selector, address(usdc), uint256(150e18), uint256(100e18))
        );

        // 5. Owner revokes the agent → its UserOps fail at validation.
        vm.prank(owner);
        account.revokeAgent(agent);
        _expectRunRevert(agentPk, _transfer(bob, 10e18), abi.encodeWithSelector(MockEntryPoint.SignatureValidationFailed.selector));

        // 6. Recovery: the AGENT couriers guardian signatures (it cannot forge
        //    them) and submits the permissionless schedule + execute.
        bytes32 d = recovery.recoveryDigest(newOwner);
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _sign(gpks[0], d);
        sigs[1] = _sign(gpks[1], d);
        vm.prank(agent);
        recovery.scheduleRecovery(newOwner, sigs);
        vm.warp(block.timestamp + 2 days + 1);
        vm.prank(agent);
        recovery.executeRecovery();
        assertEq(account.owner(), newOwner, "owner not rotated");

        // 7. The new owner controls the account via the EntryPoint (unrestricted).
        _runOp(newOwnerPk, _transfer(bob, 500e18));
        assertEq(usdc.balanceOf(bob), 550e18);
    }

    // ── helpers ──────────────────────────────────────────────────

    function _transfer(address to, uint256 amt) internal view returns (bytes memory) {
        AgentAccount.Call[] memory calls = new AgentAccount.Call[](1);
        calls[0] = AgentAccount.Call(address(usdc), 0, abi.encodeWithSelector(TRANSFER, to, amt));
        return abi.encodeWithSelector(AgentAccount.executeUserOp.selector, calls);
    }

    function _runOp(uint256 pk, bytes memory callData) internal {
        bytes32 h = keccak256(abi.encodePacked(callData, pk, block.timestamp));
        PackedUserOperation memory op;
        op.callData = callData;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, h);
        op.signature = abi.encodePacked(r, s, v);
        ep.handleOp(address(account), op, h);
    }

    function _expectRunRevert(uint256 pk, bytes memory callData, bytes memory expectedRevert) internal {
        bytes32 h = keccak256(abi.encodePacked(callData, pk, block.timestamp));
        PackedUserOperation memory op;
        op.callData = callData;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, h);
        op.signature = abi.encodePacked(r, s, v);
        vm.expectRevert(expectedRevert);
        ep.handleOp(address(account), op, h);
    }

    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

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
}
