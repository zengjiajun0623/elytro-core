// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {AgentAccount} from "../src/AgentAccount.sol";
import {MockERC20, Sink} from "./mocks/Mocks.sol";

interface IERC20F {
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

/// A router that PULLS tokenIn via transferFrom (needs an allowance) and delivers
/// tokenOut 1:1 — like a real Uniswap router. Proves the JIT approve+reset rail
/// lets a deposit/swap app work out of the box, bounded by realized value.
contract PullSwapRouter {
    IERC20F public tokenIn;
    IERC20F public tokenOut;

    constructor(address i, address o) {
        tokenIn = IERC20F(i);
        tokenOut = IERC20F(o);
    }

    function swap(uint256 amtIn) external {
        tokenIn.transferFrom(msg.sender, address(this), amtIn);
        tokenOut.transfer(msg.sender, amtIn);
    }
}

/// Stub NFT exposing only safeTransferFrom(address,address,uint256) (selector
/// 0x42842e0e). The AgentAccount gauntlet must reject an OPEN-mode agent moving it
/// (unmeasured asset) BEFORE this body ever runs — the red-team's critical hole.
contract MockNFT {
    function safeTransferFrom(address, address, uint256) external pure {}
}

/// OPEN mode: the agent interacts with any app out of the box (no per-(target,
/// selector) allowlist), still bounded by realized-value caps; plus the JIT
/// approve+reset rail for deposit/swap apps.
contract OpenModeTest is Test {
    AgentAccount account;
    MockERC20 usdc;
    MockERC20 weth;
    PullSwapRouter router;
    Sink sink;
    MockNFT nft;

    uint256 ownerPk = 0xA11CE;
    uint256 agentPk = 0xB0B;
    address owner;
    address agent;
    address attacker = makeAddr("attacker");

    bytes4 constant TRANSFER = MockERC20.transfer.selector;
    bytes4 constant APPROVE = MockERC20.approve.selector;

    function setUp() public {
        owner = vm.addr(ownerPk);
        agent = vm.addr(agentPk);
        account = new AgentAccount(owner, address(0xE17240E1));
        usdc = new MockERC20("USD Coin", "USDC");
        weth = new MockERC20("Wrapped Ether", "WETH");
        usdc.mint(address(account), 1000e18);
        vm.deal(address(account), 100 ether);
        router = new PullSwapRouter(address(usdc), address(weth));
        weth.mint(address(router), 1000e18); // router liquidity
        sink = new Sink();
        nft = new MockNFT();

        // Agent active + a USDC cap, but NO setAllowedCall for ANY target — the
        // whole point of open mode is that no per-app wiring is required.
        vm.startPrank(owner);
        account.setProtectedToken(address(usdc), true);
        account.setAgent(agent, 0, uint48(block.timestamp + 30 days), true);
        account.setCap(agent, address(usdc), 100e18, 0, 0, 300e18);
        vm.stopPrank();
    }

    function _one(address t, uint256 v, bytes memory d) internal pure returns (AgentAccount.Call[] memory a) {
        a = new AgentAccount.Call[](1);
        a[0] = AgentAccount.Call(t, v, d);
    }

    function _open() internal {
        vm.prank(owner);
        account.setOpenMode(agent, true);
    }

    // ── open mode: arbitrary calls, no per-app allowlist ─────────

    function test_WithoutOpenMode_ArbitraryCallReverts() public {
        vm.prank(agent);
        vm.expectRevert(abi.encodeWithSelector(AgentAccount.CallNotAllowlisted.selector, address(usdc), TRANSFER));
        account.executeAsAgent(_one(address(usdc), 0, abi.encodeWithSelector(TRANSFER, attacker, 10e18)));
    }

    function test_OpenMode_TransferWithinCapNoAllowlist() public {
        _open();
        vm.prank(agent);
        account.executeAsAgent(_one(address(usdc), 0, abi.encodeWithSelector(TRANSFER, attacker, 50e18)));
        assertEq(usdc.balanceOf(attacker), 50e18);
        assertEq(account.getCap(agent, address(usdc)).spentTotal, 50e18);
    }

    function test_OpenMode_ArbitraryContractCallSucceeds() public {
        _open();
        // An app the agent was NEVER allowlisted for is reachable (no revert).
        vm.prank(agent);
        account.executeAsAgent(_one(address(sink), 0, abi.encodeWithSelector(Sink.ping.selector)));
    }

    function test_OpenMode_OverCapStillReverts() public {
        _open();
        vm.prank(agent);
        vm.expectRevert(abi.encodeWithSelector(AgentAccount.PerTxCapExceeded.selector, address(usdc), 150e18, 100e18));
        account.executeAsAgent(_one(address(usdc), 0, abi.encodeWithSelector(TRANSFER, attacker, 150e18)));
    }

    /// The red-team's critical hole: an open agent must NOT be able to walk an
    /// unmeasured asset (NFT) out with zero charge. safeTransferFrom is now a
    /// value-mover, so it reverts on a non-protected target before executing.
    function test_OpenMode_UnmeasuredNFTCannotWalk() public {
        _open();
        vm.prank(agent);
        vm.expectRevert(abi.encodeWithSelector(AgentAccount.UnprotectedTokenTransfer.selector, address(nft)));
        account.executeAsAgent(
            _one(address(nft), 0, abi.encodeWithSelector(MockNFT.safeTransferFrom.selector, address(account), attacker, 1))
        );
    }

    function test_OpenMode_ApproveStillForbidden() public {
        _open();
        vm.prank(agent);
        vm.expectRevert(AgentAccount.ApprovalForbidden.selector);
        account.executeAsAgent(_one(address(usdc), 0, abi.encodeWithSelector(APPROVE, attacker, 1e18)));
    }

    function test_OpenMode_SelfCallStillForbidden() public {
        _open();
        vm.prank(agent);
        vm.expectRevert(AgentAccount.SelfCallForbidden.selector);
        account.executeAsAgent(
            _one(address(account), 0, abi.encodeWithSelector(AgentAccount.setOpenMode.selector, agent, true))
        );
    }

    function test_SetOpenMode_AgentCannotSelfEnable() public {
        vm.prank(agent);
        vm.expectRevert(AgentAccount.NotOwnerOrSelf.selector);
        account.setOpenMode(agent, true);
    }

    // ── JIT approve+reset: deposit/swap apps out of the box ──────

    function test_JIT_SwapBoundedByCapNoStandingAllowance() public {
        _open();
        AgentAccount.Call[] memory calls =
            _one(address(router), 0, abi.encodeWithSelector(PullSwapRouter.swap.selector, 50e18));
        vm.prank(agent);
        account.executeAsAgentJIT(address(router), address(usdc), 50e18, calls);
        assertEq(weth.balanceOf(address(account)), 50e18, "received WETH");
        assertEq(account.getCap(agent, address(usdc)).spentTotal, 50e18, "charged 50 USDC");
        assertEq(usdc.allowance(address(account), address(router)), 0, "no standing allowance");
    }

    /// JIT composes with the existing allowlist model (no open mode needed): the
    /// owner allowlists the router call, the JIT rail supplies the bounded approve.
    function test_JIT_WorksWithAllowlistNoOpenMode() public {
        vm.prank(owner);
        account.setAllowedCall(agent, address(router), PullSwapRouter.swap.selector, true);
        AgentAccount.Call[] memory calls =
            _one(address(router), 0, abi.encodeWithSelector(PullSwapRouter.swap.selector, 40e18));
        vm.prank(agent);
        account.executeAsAgentJIT(address(router), address(usdc), 40e18, calls);
        assertEq(weth.balanceOf(address(account)), 40e18);
        assertEq(usdc.allowance(address(account), address(router)), 0);
    }

    function test_JIT_OverCapRevertsAtomic() public {
        _open();
        AgentAccount.Call[] memory calls =
            _one(address(router), 0, abi.encodeWithSelector(PullSwapRouter.swap.selector, 150e18));
        vm.prank(agent);
        vm.expectRevert(abi.encodeWithSelector(AgentAccount.PerTxCapExceeded.selector, address(usdc), 150e18, 100e18));
        account.executeAsAgentJIT(address(router), address(usdc), 150e18, calls);
        // atomic: nothing moved, no standing allowance survives
        assertEq(usdc.allowance(address(account), address(router)), 0);
        assertEq(weth.balanceOf(address(account)), 0);
    }

    function test_JIT_RejectsUnprotectedToken() public {
        _open();
        AgentAccount.Call[] memory calls =
            _one(address(router), 0, abi.encodeWithSelector(PullSwapRouter.swap.selector, 1e18));
        vm.prank(agent);
        vm.expectRevert(abi.encodeWithSelector(AgentAccount.UnprotectedTokenTransfer.selector, address(weth)));
        account.executeAsAgentJIT(address(router), address(weth), 1e18, calls);
    }

    function test_JIT_RejectsExistingStandingAllowance() public {
        // Owner leaves a standing allowance; JIT must refuse to stack on it.
        vm.prank(owner);
        account.executeAsOwner(_one(address(usdc), 0, abi.encodeWithSelector(APPROVE, address(router), 1)));
        AgentAccount.Call[] memory calls =
            _one(address(router), 0, abi.encodeWithSelector(PullSwapRouter.swap.selector, 1e18));
        vm.prank(agent);
        vm.expectRevert(abi.encodeWithSelector(AgentAccount.ApproveResetFailed.selector, address(usdc), address(router)));
        account.executeAsAgentJIT(address(router), address(usdc), 1e18, calls);
    }

    // ── audit 2026-06-15 fixes ───────────────────────────────────

    /// HIGH-2 partial: ERC-777 operatorSend is now a recognized value-mover, so it
    /// reverts on a non-protected token (closes the direct-held redirect leak).
    function test_OpenMode_ERC777OperatorSendOnUnprotectedReverts() public {
        _open();
        bytes memory data = abi.encodeWithSelector(bytes4(0x62ad1b83), address(account), attacker, uint256(1e18), bytes(""), bytes(""));
        vm.prank(agent);
        vm.expectRevert(abi.encodeWithSelector(AgentAccount.UnprotectedTokenTransfer.selector, address(weth)));
        account.executeAsAgent(_one(address(weth), 0, data));
    }

    /// HIGH-3 mitigation: target-scoped open mode bounds the agent's reach to
    /// owner-approved targets (so it cannot reach an arbitrary sweep router).
    function test_OpenModeScoped_RestrictsToApprovedTargets() public {
        _open();
        vm.startPrank(owner);
        account.setOpenModeScoped(agent, true);
        account.setOpenAllowedTarget(agent, address(sink), true);
        vm.stopPrank();

        // approved target → allowed
        vm.prank(agent);
        account.executeAsAgent(_one(address(sink), 0, abi.encodeWithSelector(Sink.ping.selector)));

        // any other target → refused, even in open mode
        vm.prank(agent);
        vm.expectRevert(
            abi.encodeWithSelector(AgentAccount.CallNotAllowlisted.selector, address(router), PullSwapRouter.swap.selector)
        );
        account.executeAsAgent(_one(address(router), 0, abi.encodeWithSelector(PullSwapRouter.swap.selector, 1e18)));
    }

    function test_OpenModeScopedControls_OwnerOnly() public {
        vm.prank(agent);
        vm.expectRevert(AgentAccount.NotOwnerOrSelf.selector);
        account.setOpenModeScoped(agent, true);
        vm.prank(agent);
        vm.expectRevert(AgentAccount.NotOwnerOrSelf.selector);
        account.setOpenAllowedTarget(agent, address(sink), true);
    }
}
