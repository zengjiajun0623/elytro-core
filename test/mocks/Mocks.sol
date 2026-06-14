// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20Min {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

/// Minimal honest ERC-20.
contract MockERC20 {
    string public name;
    string public symbol;
    uint8 public constant decimals = 18;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(string memory n, string memory s) {
        name = n;
        symbol = s;
    }

    function mint(address to, uint256 amt) external {
        balanceOf[to] += amt;
    }

    function transfer(address to, uint256 amt) external returns (bool) {
        _transfer(msg.sender, to, amt);
        return true;
    }

    function approve(address sp, uint256 amt) external returns (bool) {
        allowance[msg.sender][sp] = amt;
        return true;
    }

    function transferFrom(address f, address t, uint256 amt) external returns (bool) {
        uint256 al = allowance[f][msg.sender];
        require(al >= amt, "allowance");
        if (al != type(uint256).max) allowance[f][msg.sender] = al - amt;
        _transfer(f, t, amt);
        return true;
    }

    function _transfer(address f, address t, uint256 amt) internal {
        require(balanceOf[f] >= amt, "balance");
        balanceOf[f] -= amt;
        balanceOf[t] += amt;
    }
}

/// A token whose transfer() moves a DIFFERENT amount than its calldata states.
/// Models an obfuscated/malicious/buggy token — the case that defeats any
/// calldata-decoding spend limit but is caught by realized balance delta.
contract LyingERC20 {
    string public name = "Lying";
    string public symbol = "LIE";
    uint8 public constant decimals = 18;
    mapping(address => uint256) public balanceOf;
    uint256 public moveAmount; // what transfer() ACTUALLY moves, ignoring its arg

    function mint(address to, uint256 amt) external {
        balanceOf[to] += amt;
    }

    function setMoveAmount(uint256 m) external {
        moveAmount = m;
    }

    /// Ignores `statedAmount` entirely and moves `moveAmount`.
    function transfer(address to, uint256 statedAmount) external returns (bool) {
        statedAmount; // silence
        uint256 amt = moveAmount;
        require(balanceOf[msg.sender] >= amt, "balance");
        balanceOf[msg.sender] -= amt;
        balanceOf[to] += amt;
        return true;
    }
}

/// A plain call target that accepts native value and a no-op ping.
contract Sink {
    event Pinged();

    function ping() external {
        emit Pinged();
    }

    receive() external payable {}
}

/// A swap-like router: caller has already transferred tokenIn to this router,
/// then calls deliver() to receive `amtOut` of tokenOut. Used to prove that a
/// swap nets correctly (outflow charged, inflow ignored).
contract MockSwapRouter {
    address public tokenOut;

    constructor(address _tokenOut) {
        tokenOut = _tokenOut;
    }

    function deliver(uint256 amtOut) external {
        IERC20Min(tokenOut).transfer(msg.sender, amtOut);
    }
}
