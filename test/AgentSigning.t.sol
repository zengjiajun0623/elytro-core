// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {AgentAccount} from "../src/AgentAccount.sol";

/// Bounded ERC-1271 login signing: the agent may sign a login / typed-data on an
/// owner-approved domain, but a COMPROMISED agent can NEVER produce a value-
/// authorizing signature (Permit / Permit2 / EIP-3009). The owner keeps full,
/// unrestricted signing. The domain allowlist is the load-bearing bound; the
/// value-auth typehash blocklist is defense-in-depth.
contract AgentSigningTest is Test {
    AgentAccount account;

    uint256 ownerPk = 0xA11CE;
    uint256 agentPk = 0xB0B;
    uint256 strangerPk = 0xBAD;
    address owner;
    address agent;

    bytes4 constant MAGIC = 0x1626ba7e;
    bytes4 constant FAIL = 0xffffffff;

    // An owner-approved login app domain, and a token (Permit) domain that is NOT.
    bytes32 constant LOGIN_DOMSEP = keccak256("login.example.com EIP712Domain");
    bytes32 constant TOKEN_DOMSEP = keccak256("USDC EIP712Domain");
    bytes32 constant LOGIN_TYPEHASH = keccak256("Login(address account,string statement,uint256 nonce)");
    bytes32 constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    function setUp() public {
        owner = vm.addr(ownerPk);
        agent = vm.addr(agentPk);
        account = new AgentAccount(owner, address(0xE17240E1));
        vm.startPrank(owner);
        account.setAgent(agent, 0, uint48(block.timestamp + 30 days), true);
        account.setAgentCanSign(agent, true);
        account.setApprovedSignDomain(LOGIN_DOMSEP, true);
        vm.stopPrank();
    }

    function _digest(bytes32 domSep, bytes32 structHash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domSep, structHash));
    }

    /// The structured agent blob: abi.encode(domSep, structHash, typeHash, 65-byte sig).
    function _blob(bytes32 domSep, bytes32 structHash, bytes32 typeHash, uint256 pk, bytes32 hash)
        internal
        pure
        returns (bytes memory)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, hash);
        return abi.encode(domSep, structHash, typeHash, abi.encodePacked(r, s, v));
    }

    function _plainSig(uint256 pk, bytes32 hash) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, hash);
        return abi.encodePacked(r, s, v);
    }

    // ── owner keeps full, unrestricted signing ───────────────────

    function test_OwnerSignsAnything() public view {
        bytes32 hash = keccak256("anything at all");
        assertEq(account.isValidSignature(hash, _plainSig(ownerPk, hash)), MAGIC);
    }

    function test_OwnerCanSignAValueAuthMessageToo() public view {
        // The owner is root; the value-auth blocklist applies ONLY to agents.
        bytes32 sh = keccak256(abi.encode(PERMIT_TYPEHASH, owner, address(1), 1e18, 0, type(uint256).max));
        bytes32 hash = _digest(TOKEN_DOMSEP, sh);
        assertEq(account.isValidSignature(hash, _plainSig(ownerPk, hash)), MAGIC);
    }

    // ── agent CAN log in on an approved domain ───────────────────

    function test_AgentLoginOnApprovedDomain_Valid() public view {
        bytes32 sh = keccak256(abi.encode(LOGIN_TYPEHASH, address(account), "Sign in", uint256(42)));
        bytes32 hash = _digest(LOGIN_DOMSEP, sh);
        assertEq(account.isValidSignature(hash, _blob(LOGIN_DOMSEP, sh, LOGIN_TYPEHASH, agentPk, hash)), MAGIC);
    }

    // ── the value bound: a compromised agent cannot sign value ───

    /// The realistic drain: a token's permit() calls isValidSignature with a real
    /// Permit digest. The agent supplies a matching envelope (even lying about the
    /// typehash) — but the TOKEN's domain was never approved, so it is refused.
    function test_AgentCannotSignPermit_DomainNotApproved() public view {
        bytes32 sh = keccak256(abi.encode(PERMIT_TYPEHASH, address(account), address(0xBAD), 1e18, 0, type(uint256).max));
        bytes32 hash = _digest(TOKEN_DOMSEP, sh);
        // even with a FAKE benign typehash, the unapproved domain blocks it
        assertEq(account.isValidSignature(hash, _blob(TOKEN_DOMSEP, sh, LOGIN_TYPEHASH, agentPk, hash)), FAIL);
        // and with the honest Permit typehash, doubly so
        assertEq(account.isValidSignature(hash, _blob(TOKEN_DOMSEP, sh, PERMIT_TYPEHASH, agentPk, hash)), FAIL);
    }

    /// Defense-in-depth: even if the owner MISTAKENLY approved a value domain, an
    /// honest value-auth typehash is still blocklisted.
    function test_AgentCannotSignValueAuthType_EvenOnApprovedDomain() public {
        vm.prank(owner);
        account.setApprovedSignDomain(TOKEN_DOMSEP, true); // misconfiguration
        bytes32 sh = keccak256(abi.encode(PERMIT_TYPEHASH, address(account), address(0xBAD), 1e18, 0, type(uint256).max));
        bytes32 hash = _digest(TOKEN_DOMSEP, sh);
        assertEq(account.isValidSignature(hash, _blob(TOKEN_DOMSEP, sh, PERMIT_TYPEHASH, agentPk, hash)), FAIL);
    }

    // ── other refusals ───────────────────────────────────────────

    function test_AgentRejectedWhenCanSignOff() public {
        vm.prank(owner);
        account.setAgentCanSign(agent, false);
        bytes32 sh = keccak256("login");
        bytes32 hash = _digest(LOGIN_DOMSEP, sh);
        assertEq(account.isValidSignature(hash, _blob(LOGIN_DOMSEP, sh, LOGIN_TYPEHASH, agentPk, hash)), FAIL);
    }

    function test_RejectedWrongSigner() public view {
        bytes32 sh = keccak256("login");
        bytes32 hash = _digest(LOGIN_DOMSEP, sh);
        // a stranger (not an agent) signs an otherwise-valid envelope
        assertEq(account.isValidSignature(hash, _blob(LOGIN_DOMSEP, sh, LOGIN_TYPEHASH, strangerPk, hash)), FAIL);
    }

    /// The envelope cannot be faked: the supplied (domain, struct) MUST hash to the
    /// queried `hash`, or it is refused (so the agent can't pass off a value digest
    /// as a benign one).
    function test_EnvelopeMustBindTheQueriedHash() public view {
        bytes32 sh = keccak256("login");
        bytes32 realHash = _digest(LOGIN_DOMSEP, sh);
        bytes32 wrongHash = keccak256("a different hash entirely");
        bytes memory blob = _blob(LOGIN_DOMSEP, sh, LOGIN_TYPEHASH, agentPk, wrongHash);
        // queried hash != keccak(0x1901, domSep, structHash) → refused
        assertEq(account.isValidSignature(realHash, blob), FAIL);
    }

    /// Opaque personal_sign / a bare 65-byte agent signature stays OWNER-ONLY: the
    /// agent path requires the 256-byte structured envelope.
    function test_AgentBarePersonalSignIsOwnerOnly() public view {
        bytes32 hash = keccak256("\x19Ethereum Signed Message:\n5hello");
        assertEq(account.isValidSignature(hash, _plainSig(agentPk, hash)), FAIL); // agent bare sig
        assertEq(account.isValidSignature(hash, _plainSig(ownerPk, hash)), MAGIC); // owner bare sig
    }

    function test_SetSigningControlsAreOwnerOnly() public {
        vm.prank(agent);
        vm.expectRevert(AgentAccount.NotOwnerOrSelf.selector);
        account.setAgentCanSign(agent, true);
        vm.prank(agent);
        vm.expectRevert(AgentAccount.NotOwnerOrSelf.selector);
        account.setApprovedSignDomain(LOGIN_DOMSEP, true);
    }
}
