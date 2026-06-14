// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {AgentAccount} from "../src/AgentAccount.sol";
import {AgentAccountFactory} from "../src/AgentAccountFactory.sol";
import {GuardianRecovery, IRecoverable} from "../src/GuardianRecovery.sol";

/**
 * Live agent-driven recovery on the Cleave testnet: deploy an account + a
 * weighted/class-diverse GuardianRecovery (delay 0 for the test so we don't
 * warp shared chain time), then the "agent" (the broadcaster, a non-guardian)
 * couriers 2 cross-class guardian signatures, schedules, and executes the
 * recovery — rotating the owner on-chain. Proves: agent drives, guardians
 * authorize, agent cannot forge.
 *
 * Env: PK (owner + courier = anvil #9), FACTORY.
 */
contract CleaveRecovery is Script {
    string constant MN = "test test test test test test test test test test test junk";

    function run() external {
        uint256 ownerPk = vm.envUint("PK");
        address owner = vm.addr(ownerPk);
        AgentAccountFactory factory = AgentAccountFactory(vm.envAddress("FACTORY"));
        address newOwner = vm.addr(vm.deriveKey(MN, 5)); // rotate target = anvil #5

        // Guardians = anvil #2,#3,#4, sorted ascending by address.
        uint256[] memory gk = new uint256[](3);
        gk[0] = vm.deriveKey(MN, 2);
        gk[1] = vm.deriveKey(MN, 3);
        gk[2] = vm.deriveKey(MN, 4);
        _sortByAddr(gk);

        GuardianRecovery.GuardianSpec[] memory specs = new GuardianRecovery.GuardianSpec[](3);
        for (uint256 i; i < 3; i++) {
            specs[i] = GuardianRecovery.GuardianSpec(vm.addr(gk[i]), 1, uint8(i));
        }

        bytes32 salt = keccak256("cleave-recovery-v1");
        address predicted = factory.getAddress(owner, salt);

        vm.startBroadcast(ownerPk);
        GuardianRecovery rec = new GuardianRecovery(IRecoverable(predicted), specs, 2, 2, 0); // thr 2, minClasses 2, delay 0
        AgentAccount account = AgentAccount(payable(factory.createAccount(owner, salt)));
        require(address(account) == predicted, "addr mismatch");
        account.setRecoveryModule(address(rec));
        vm.stopBroadcast();

        // The agent (non-guardian) collects 2 cross-class guardian sigs.
        bytes32 d = rec.recoveryDigest(newOwner);
        bytes[] memory sigs = new bytes[](2);
        sigs[0] = _sign(gk[0], d); // class 0
        sigs[1] = _sign(gk[1], d); // class 1

        vm.startBroadcast(ownerPk); // broadcaster acts as the agent/courier
        rec.scheduleRecovery(newOwner, sigs);
        rec.executeRecovery();
        vm.stopBroadcast();

        console.log("account     :", address(account));
        console.log("owner before:", owner);
        console.log("newOwner    :", newOwner);
        console.log("owner after :", account.owner());
        require(account.owner() == newOwner, "recovery did not rotate owner");
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
