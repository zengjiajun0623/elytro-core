// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {AgentAccount} from "../src/AgentAccount.sol";
import {MockERC20, MockSwapRouter} from "./mocks/Mocks.sol";

/**
 * @notice Property-based proof of the core invariant: across ANY sequence of
 *         agent actions (in-cap, over-cap, batches, inflow-masking attempts),
 *         the agent can never move more than its total cap, and the amount it
 *         moved exactly equals what the account charged it. The fuzzer drives
 *         the handler with random inputs; the invariant must hold after each.
 */
contract AgentAccountInvariant is Test {
    AgentAccount account;
    MockERC20 usdc;
    Handler handler;

    uint256 constant INITIAL = 1_000_000e18;
    uint256 constant TOTAL_CAP = 300e18;
    uint256 constant PER_TX = 100e18;

    address owner = makeAddr("owner");
    address bob = makeAddr("bob");

    function setUp() public {
        account = new AgentAccount(owner, address(0xE17240E1));
        usdc = new MockERC20("USD Coin", "USDC");
        usdc.mint(address(account), INITIAL);

        // The handler IS the agent (executeAsAgent uses msg.sender).
        handler = new Handler(account, usdc, bob);
        usdc.mint(address(handler.src()), INITIAL); // inflow source for masking attempts

        vm.startPrank(owner);
        account.setProtectedToken(address(usdc), true);
        account.setAgent(address(handler), 0, type(uint48).max, true);
        account.setAllowedCall(address(handler), address(usdc), MockERC20.transfer.selector, true);
        account.setAllowedCall(address(handler), address(handler.src()), MockSwapRouter.deliver.selector, true);
        account.setCap(address(handler), address(usdc), PER_TX, 0, 0, TOTAL_CAP);
        vm.stopPrank();

        // Only the two agent actions are fuzzed.
        bytes4[] memory sel = new bytes4[](2);
        sel[0] = Handler.agentTransfer.selector;
        sel[1] = Handler.agentBatchWithInflow.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: sel}));
        targetContract(address(handler));
    }

    /// The agent's lifetime spend can never exceed its total cap.
    function invariant_spendNeverExceedsTotalCap() public view {
        assertLe(account.getCap(address(handler), address(usdc)).spentTotal, TOTAL_CAP);
    }

    /// What the agent actually moved to bob equals what the account charged it —
    /// no value escapes accounting (incl. through batches and inflow-masking).
    function invariant_chargedEqualsMoved() public view {
        assertEq(usdc.balanceOf(bob), account.getCap(address(handler), address(usdc)).spentTotal);
    }

    /// The account can never lose more than the cap to the agent's recipient.
    function invariant_recipientBoundedByCap() public view {
        assertLe(usdc.balanceOf(bob), TOTAL_CAP);
    }
}

/// Driven by the fuzzer. Every action is attempted as the agent; reverts
/// (over-cap, etc.) are swallowed — the invariant must hold regardless.
contract Handler is Test {
    AgentAccount account;
    MockERC20 usdc;
    MockSwapRouter public src;
    address bob;

    constructor(AgentAccount _account, MockERC20 _usdc, address _bob) {
        account = _account;
        usdc = _usdc;
        bob = _bob;
        src = new MockSwapRouter(address(_usdc));
    }

    function agentTransfer(uint256 amt) external {
        amt = bound(amt, 0, 250e18); // spans below + above per-tx and total caps
        AgentAccount.Call[] memory calls = new AgentAccount.Call[](1);
        calls[0] = AgentAccount.Call(address(usdc), 0, abi.encodeWithSelector(MockERC20.transfer.selector, bob, amt));
        try account.executeAsAgent(calls) {} catch {}
    }

    /// Attempt to mask an outflow with a same-asset inflow in one batch.
    function agentBatchWithInflow(uint256 out, uint256 back) external {
        out = bound(out, 0, 250e18);
        back = bound(back, 0, 250e18);
        AgentAccount.Call[] memory calls = new AgentAccount.Call[](2);
        calls[0] = AgentAccount.Call(address(usdc), 0, abi.encodeWithSelector(MockERC20.transfer.selector, bob, out));
        calls[1] = AgentAccount.Call(address(src), 0, abi.encodeWithSelector(MockSwapRouter.deliver.selector, back));
        try account.executeAsAgent(calls) {} catch {}
    }
}
