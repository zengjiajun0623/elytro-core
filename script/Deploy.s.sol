// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {AgentAccountFactory} from "../src/AgentAccountFactory.sol";

/**
 * @notice Deploys the AgentAccountFactory wired to a canonical ERC-4337 EntryPoint.
 *
 * The EntryPoint address differs per version/chain, so it is REQUIRED via env
 * rather than hardcoded (avoids deploying against the wrong EntryPoint):
 *
 *   ENTRYPOINT=0x... forge script script/Deploy.s.sol --rpc-url <rpc> --broadcast
 *
 * Accounts are then deployed counterfactually by the EntryPoint on first use via
 * `initCode = factory ++ createAccount(owner, salt)`.
 */
contract Deploy is Script {
    function run() external returns (AgentAccountFactory factory) {
        address entryPoint = vm.envAddress("ENTRYPOINT");
        vm.startBroadcast();
        factory = new AgentAccountFactory(entryPoint);
        vm.stopBroadcast();
        console.log("AgentAccountFactory deployed:", address(factory));
        console.log("Wired EntryPoint:", entryPoint);
    }
}
