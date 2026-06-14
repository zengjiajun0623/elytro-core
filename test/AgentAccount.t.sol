// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {AgentAccount} from "../src/AgentAccount.sol";
import {MockERC20, LyingERC20, Sink, MockSwapRouter} from "./mocks/Mocks.sol";

contract AgentAccountTest is Test {
    AgentAccount account;
    MockERC20 usdc;

    uint256 ownerPk = 0xA11CE;
    uint256 agentPk = 0xB0B;
    address owner;
    address agent;
    address bob = makeAddr("bob");

    bytes4 constant TRANSFER = MockERC20.transfer.selector; // 0xa9059cbb
    bytes4 constant APPROVE = MockERC20.approve.selector; // 0x095ea7b3
    bytes4 constant NATIVE = 0x00000000;

    function setUp() public {
        owner = vm.addr(ownerPk);
        agent = vm.addr(agentPk);
        account = new AgentAccount(owner);
        usdc = new MockERC20("USD Coin", "USDC");
        usdc.mint(address(account), 1000e18);
        vm.deal(address(account), 100 ether);
        vm.prank(owner);
        account.setProtectedToken(address(usdc), true);
    }

    // ── helpers ──────────────────────────────────────────────────

    function _one(address t, uint256 v, bytes memory d) internal pure returns (AgentAccount.Call[] memory a) {
        a = new AgentAccount.Call[](1);
        a[0] = AgentAccount.Call(t, v, d);
    }

    function _transferCall(address token, address to, uint256 amt) internal pure returns (AgentAccount.Call[] memory) {
        return _one(token, 0, abi.encodeWithSelector(TRANSFER, to, amt));
    }

    function _registerUSDCAgent(uint256 perTx, uint256 perPeriod, uint256 period, uint256 total) internal {
        vm.startPrank(owner);
        account.setAgent(agent, 0, uint48(block.timestamp + 30 days), true);
        account.setAllowedCall(agent, address(usdc), TRANSFER, true);
        account.setCap(agent, address(usdc), perTx, perPeriod, period, total);
        vm.stopPrank();
    }

    // ── root authority ───────────────────────────────────────────

    function test_OwnerCanMoveFundsWithNoCap() public {
        vm.prank(owner);
        account.executeAsOwner(_transferCall(address(usdc), bob, 500e18));
        assertEq(usdc.balanceOf(bob), 500e18);
    }

    function test_NonOwnerCannotUseOwnerPath() public {
        vm.prank(agent);
        vm.expectRevert(AgentAccount.NotOwner.selector);
        account.executeAsOwner(_transferCall(address(usdc), bob, 1));
    }

    // ── agent lifecycle ──────────────────────────────────────────

    function test_UnregisteredAgentReverts() public {
        vm.prank(agent);
        vm.expectRevert(AgentAccount.AgentInactive.selector);
        account.executeAsAgent(_transferCall(address(usdc), bob, 1));
    }

    function test_AgentInCapTransferSucceeds() public {
        _registerUSDCAgent(100e18, 0, 0, 0);
        vm.prank(agent);
        account.executeAsAgent(_transferCall(address(usdc), bob, 50e18));
        assertEq(usdc.balanceOf(bob), 50e18);
        assertEq(account.getCap(agent, address(usdc)).spentTotal, 50e18);
    }

    function test_RevokedAgentReverts() public {
        _registerUSDCAgent(100e18, 0, 0, 0);
        vm.prank(owner);
        account.revokeAgent(agent);
        vm.prank(agent);
        vm.expectRevert(AgentAccount.AgentInactive.selector);
        account.executeAsAgent(_transferCall(address(usdc), bob, 1));
    }

    function test_ExpiredAgentReverts() public {
        _registerUSDCAgent(100e18, 0, 0, 0);
        vm.warp(block.timestamp + 31 days);
        vm.prank(agent);
        vm.expectRevert(AgentAccount.AgentExpired.selector);
        account.executeAsAgent(_transferCall(address(usdc), bob, 1));
    }

    function test_NotYetValidAgentReverts() public {
        vm.startPrank(owner);
        account.setAgent(agent, uint48(block.timestamp + 1 days), uint48(block.timestamp + 30 days), true);
        account.setAllowedCall(agent, address(usdc), TRANSFER, true);
        account.setCap(agent, address(usdc), 100e18, 0, 0, 0);
        vm.stopPrank();
        vm.prank(agent);
        vm.expectRevert(AgentAccount.AgentNotYetValid.selector);
        account.executeAsAgent(_transferCall(address(usdc), bob, 1));
    }

    // ── caps ─────────────────────────────────────────────────────

    function test_PerTxCapExceeded() public {
        _registerUSDCAgent(100e18, 0, 0, 0);
        vm.prank(agent);
        vm.expectRevert(
            abi.encodeWithSelector(AgentAccount.PerTxCapExceeded.selector, address(usdc), uint256(150e18), uint256(100e18))
        );
        account.executeAsAgent(_transferCall(address(usdc), bob, 150e18));
    }

    function test_PerPeriodCapWithReset() public {
        _registerUSDCAgent(100e18, 200e18, 1 days, 0);
        vm.startPrank(agent);
        account.executeAsAgent(_transferCall(address(usdc), bob, 80e18)); // 80
        account.executeAsAgent(_transferCall(address(usdc), bob, 80e18)); // 160
        vm.expectRevert(
            abi.encodeWithSelector(AgentAccount.PerPeriodCapExceeded.selector, address(usdc), uint256(240e18), uint256(200e18))
        );
        account.executeAsAgent(_transferCall(address(usdc), bob, 80e18)); // 240 > 200
        vm.stopPrank();

        // After the window rolls over, the period budget resets.
        vm.warp(block.timestamp + 1 days + 1);
        vm.prank(agent);
        account.executeAsAgent(_transferCall(address(usdc), bob, 80e18));
        assertEq(usdc.balanceOf(bob), 240e18);
    }

    function test_TotalCapIsHardCeiling() public {
        _registerUSDCAgent(100e18, 0, 0, 150e18);
        vm.startPrank(agent);
        account.executeAsAgent(_transferCall(address(usdc), bob, 100e18)); // total 100
        vm.expectRevert(
            abi.encodeWithSelector(AgentAccount.TotalCapExceeded.selector, address(usdc), uint256(200e18), uint256(150e18))
        );
        account.executeAsAgent(_transferCall(address(usdc), bob, 100e18)); // total would be 200 > 150
        vm.stopPrank();
    }

    // ── THE HEADLINE: realized value beats calldata ──────────────

    function test_RealizedValueBeatsLyingCalldata() public {
        LyingERC20 lie = new LyingERC20();
        lie.mint(address(account), 1000e18);
        lie.setMoveAmount(1000e18); // transfer() will move 1000 no matter the arg

        vm.startPrank(owner);
        account.setProtectedToken(address(lie), true);
        account.setAgent(agent, 0, uint48(block.timestamp + 30 days), true);
        account.setAllowedCall(agent, address(lie), TRANSFER, true);
        account.setCap(agent, address(lie), 100e18, 0, 0, 0); // per-tx cap 100
        vm.stopPrank();

        // The agent's calldata claims to move 1 token; the token actually moves 1000.
        // A calldata-decoding spend limit would wave this through. Realized balance
        // delta catches the true 1000 and refuses.
        vm.prank(agent);
        vm.expectRevert(
            abi.encodeWithSelector(AgentAccount.PerTxCapExceeded.selector, address(lie), uint256(1000e18), uint256(100e18))
        );
        account.executeAsAgent(_one(address(lie), 0, abi.encodeWithSelector(TRANSFER, bob, uint256(1))));

        // Funds never left.
        assertEq(lie.balanceOf(address(account)), 1000e18);
    }

    // ── allowlist / forbidden surfaces ───────────────────────────

    function test_SelfCallForbidden() public {
        _registerUSDCAgent(100e18, 0, 0, 0);
        vm.prank(agent);
        vm.expectRevert(AgentAccount.SelfCallForbidden.selector);
        account.executeAsAgent(_one(address(account), 0, abi.encodeWithSelector(account.setOwner.selector, agent)));
    }

    function test_ApprovalForbidden() public {
        _registerUSDCAgent(100e18, 0, 0, 0);
        vm.prank(agent);
        vm.expectRevert(AgentAccount.ApprovalForbidden.selector);
        account.executeAsAgent(_one(address(usdc), 0, abi.encodeWithSelector(APPROVE, bob, 1e18)));
    }

    function test_NotAllowlistedReverts() public {
        // active agent + cap, but the call target/selector is not allowlisted
        vm.startPrank(owner);
        account.setAgent(agent, 0, uint48(block.timestamp + 30 days), true);
        account.setCap(agent, address(usdc), 100e18, 0, 0, 0);
        vm.stopPrank();
        vm.prank(agent);
        vm.expectRevert(abi.encodeWithSelector(AgentAccount.CallNotAllowlisted.selector, address(usdc), TRANSFER));
        account.executeAsAgent(_transferCall(address(usdc), bob, 1));
    }

    function test_UncappedProtectedAssetMovedReverts() public {
        MockERC20 dai = new MockERC20("Dai", "DAI");
        dai.mint(address(account), 100e18);
        vm.startPrank(owner);
        account.setProtectedToken(address(dai), true);
        account.setAgent(agent, 0, uint48(block.timestamp + 30 days), true);
        account.setAllowedCall(agent, address(dai), TRANSFER, true);
        // NOTE: no cap set for (agent, dai)
        vm.stopPrank();
        vm.prank(agent);
        vm.expectRevert(abi.encodeWithSelector(AgentAccount.UncappedProtectedAssetMoved.selector, address(dai)));
        account.executeAsAgent(_transferCall(address(dai), bob, 5e18));
    }

    // ── native value caps ────────────────────────────────────────

    function test_NativeValueCap() public {
        Sink sink = new Sink();
        vm.startPrank(owner);
        account.setAgent(agent, 0, uint48(block.timestamp + 30 days), true);
        account.setAllowedCall(agent, address(sink), NATIVE, true);
        account.setCap(agent, address(0), 1 ether, 0, 0, 0);
        vm.stopPrank();

        vm.prank(agent);
        account.executeAsAgent(_one(address(sink), 0.5 ether, ""));
        assertEq(address(sink).balance, 0.5 ether);

        vm.prank(agent);
        vm.expectRevert(
            abi.encodeWithSelector(AgentAccount.PerTxCapExceeded.selector, address(0), uint256(2 ether), uint256(1 ether))
        );
        account.executeAsAgent(_one(address(sink), 2 ether, ""));
    }

    // ── swap nets correctly (outflow charged, inflow ignored) ────

    function test_SwapNetsOutflowOnly() public {
        MockERC20 weth = new MockERC20("Wrapped ETH", "WETH");
        MockSwapRouter router = new MockSwapRouter(address(weth));
        weth.mint(address(router), 1000e18);

        vm.startPrank(owner);
        account.setProtectedToken(address(weth), true);
        account.setAgent(agent, 0, uint48(block.timestamp + 30 days), true);
        account.setAllowedCall(agent, address(usdc), TRANSFER, true);
        account.setAllowedCall(agent, address(router), MockSwapRouter.deliver.selector, true);
        account.setCap(agent, address(usdc), 200e18, 0, 0, 0); // only the spent side needs a cap
        vm.stopPrank();

        AgentAccount.Call[] memory calls = new AgentAccount.Call[](2);
        calls[0] = AgentAccount.Call(address(usdc), 0, abi.encodeWithSelector(TRANSFER, address(router), 100e18));
        calls[1] = AgentAccount.Call(address(router), 0, abi.encodeWithSelector(MockSwapRouter.deliver.selector, 90e18));

        vm.prank(agent);
        account.executeAsAgent(calls);

        // USDC outflow (100) charged; WETH inflow (90) ignored, no cap needed.
        assertEq(usdc.balanceOf(address(router)), 100e18);
        assertEq(weth.balanceOf(address(account)), 90e18);
        assertEq(account.getCap(agent, address(usdc)).spentTotal, 100e18);
    }

    // ── ERC-1271 owner-only ──────────────────────────────────────

    function test_1271OwnerSigValid() public view {
        bytes32 hash = keccak256("authorize something");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, hash);
        bytes memory sig = abi.encodePacked(r, s, v);
        assertEq(account.isValidSignature(hash, sig), bytes4(0x1626ba7e));
    }

    function test_1271AgentSigRejected() public {
        // Even a fully-registered agent cannot produce a valid account signature.
        _registerUSDCAgent(100e18, 0, 0, 0);
        bytes32 hash = keccak256("authorize something");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(agentPk, hash);
        bytes memory sig = abi.encodePacked(r, s, v);
        assertEq(account.isValidSignature(hash, sig), bytes4(0xffffffff));
    }
}
