// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {AgentAccount} from "../src/AgentAccount.sol";
import {PackedUserOperation} from "../src/interfaces/IERC4337.sol";
import {MockEntryPoint} from "./mocks/MockEntryPoint.sol";
import {MockERC20} from "./mocks/Mocks.sol";

/// Proves the account behaves as a real ERC-4337 account: the EntryPoint drives
/// validate→execute, and an agent operating via UserOps is still capped by the
/// realized-value engine — owner via UserOp is unrestricted.
contract ERC4337Test is Test {
    MockEntryPoint ep;
    AgentAccount account;
    MockERC20 usdc;

    uint256 ownerPk = 0xA11CE;
    uint256 agentPk = 0xB0B;
    uint256 strangerPk = 0xDEAD;
    address owner;
    address agent;
    address bob = makeAddr("bob");

    bytes4 constant TRANSFER = MockERC20.transfer.selector;

    function setUp() public {
        owner = vm.addr(ownerPk);
        agent = vm.addr(agentPk);
        ep = new MockEntryPoint();
        account = new AgentAccount(owner, address(ep));
        usdc = new MockERC20("USD Coin", "USDC");
        usdc.mint(address(account), 1000e18);
        vm.deal(address(account), 10 ether);

        vm.startPrank(owner);
        account.setProtectedToken(address(usdc), true);
        account.setAgent(agent, 0, uint48(block.timestamp + 30 days), true);
        account.setAllowedCall(agent, address(usdc), TRANSFER, true);
        account.setCap(agent, address(usdc), 100e18, 0, 0, 0);
        vm.stopPrank();
    }

    // ── helpers ──────────────────────────────────────────────────

    function _transferCallData(address to, uint256 amt) internal view returns (bytes memory) {
        AgentAccount.Call[] memory calls = new AgentAccount.Call[](1);
        calls[0] = AgentAccount.Call(address(usdc), 0, abi.encodeWithSelector(TRANSFER, to, amt));
        return abi.encodeWithSelector(AgentAccount.executeUserOp.selector, calls);
    }

    function _op(bytes memory callData, uint256 signerPk, bytes32 userOpHash)
        internal
        pure
        returns (PackedUserOperation memory op)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, userOpHash);
        op.callData = callData;
        op.signature = abi.encodePacked(r, s, v);
    }

    function _run(bytes memory callData, uint256 signerPk) internal {
        bytes32 h = keccak256(abi.encodePacked(callData, signerPk));
        PackedUserOperation memory op = _op(callData, signerPk, h);
        ep.handleOp(address(account), op, h);
    }

    // ── tests ────────────────────────────────────────────────────

    function test_OwnerUserOpIsUnrestricted() public {
        // 500 > any agent cap — owner has root authority through the EntryPoint too.
        _run(_transferCallData(bob, 500e18), ownerPk);
        assertEq(usdc.balanceOf(bob), 500e18);
    }

    function test_AgentUserOpWithinCapSucceeds() public {
        _run(_transferCallData(bob, 50e18), agentPk);
        assertEq(usdc.balanceOf(bob), 50e18);
        assertEq(account.getCap(agent, address(usdc)).spentTotal, 50e18);
    }

    function test_AgentUserOpOverCapReverts() public {
        bytes memory cd = _transferCallData(bob, 150e18);
        bytes32 h = keccak256(abi.encodePacked(cd, agentPk));
        PackedUserOperation memory op = _op(cd, agentPk, h);
        vm.expectRevert(
            abi.encodeWithSelector(AgentAccount.PerTxCapExceeded.selector, address(usdc), uint256(150e18), uint256(100e18))
        );
        ep.handleOp(address(account), op, h);
        assertEq(usdc.balanceOf(bob), 0);
    }

    function test_BadSignatureRejectedAtValidation() public {
        bytes memory cd = _transferCallData(bob, 10e18);
        bytes32 h = keccak256(abi.encodePacked(cd, strangerPk));
        PackedUserOperation memory op = _op(cd, strangerPk, h); // stranger is neither owner nor agent
        vm.expectRevert(MockEntryPoint.SignatureValidationFailed.selector);
        ep.handleOp(address(account), op, h);
    }

    function test_ExpiredAgentRejectedByTimeWindow() public {
        // Agent still flagged active, but past expiry → validationData carries a
        // past validUntil and the EntryPoint rejects on the time window.
        vm.warp(block.timestamp + 31 days);
        bytes memory cd = _transferCallData(bob, 10e18);
        bytes32 h = keccak256(abi.encodePacked(cd, agentPk));
        PackedUserOperation memory op = _op(cd, agentPk, h);
        vm.expectRevert(MockEntryPoint.Expired.selector);
        ep.handleOp(address(account), op, h);
    }

    function test_OnlyEntryPointCanValidateOrExecute() public {
        PackedUserOperation memory op;
        vm.prank(agent);
        vm.expectRevert(AgentAccount.NotEntryPoint.selector);
        account.validateUserOp(op, bytes32(0), 0);

        AgentAccount.Call[] memory calls = new AgentAccount.Call[](0);
        vm.prank(agent);
        vm.expectRevert(AgentAccount.NotEntryPoint.selector);
        account.executeUserOp(calls);
    }

    function test_ExecuteWithoutValidateReverts() public {
        // EntryPoint calling execute with no operator handed off → NoOperator.
        AgentAccount.Call[] memory calls = new AgentAccount.Call[](0);
        vm.prank(address(ep));
        vm.expectRevert(AgentAccount.NoOperator.selector);
        account.executeUserOp(calls);
    }
}
