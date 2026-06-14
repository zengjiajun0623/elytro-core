// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IAccount, PackedUserOperation} from "../../src/interfaces/IERC4337.sol";

/**
 * @notice A faithful-enough ERC-4337 EntryPoint stand-in for testing an
 *         account's validate→execute flow. It mirrors the single-op path:
 *         call validateUserOp, honor the returned validationData (sig failure
 *         + time window), then call the account with the op's callData.
 *
 * It deliberately omits mempool, prefund accounting, and the multi-op two-phase
 * loop — those are EntryPoint concerns, not the account's. What it exercises is
 * exactly the account's IAccount surface and its capability enforcement.
 */
contract MockEntryPoint {
    error SignatureValidationFailed();
    error NotYetValid();
    error Expired();

    function handleOp(address account, PackedUserOperation calldata op, bytes32 userOpHash) external {
        uint256 vd = IAccount(account).validateUserOp(op, userOpHash, 0);

        // authorizer in the low 160 bits; non-zero authorizer == failure here
        if (uint160(vd) == 1) revert SignatureValidationFailed();
        uint48 validUntil = uint48(vd >> 160);
        uint48 validAfter = uint48(vd >> 208);
        if (validAfter != 0 && block.timestamp < validAfter) revert NotYetValid();
        if (validUntil != 0 && block.timestamp > validUntil) revert Expired();

        (bool ok, bytes memory ret) = account.call(op.callData);
        if (!ok) {
            assembly {
                revert(add(ret, 0x20), mload(ret))
            }
        }
    }

    receive() external payable {}
}
