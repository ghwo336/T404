// SPDX-License-Identifier: MIT
pragma solidity ^0.6.12;

contract Owned {
    address public owner;
    constructor() public { owner = msg.sender; }
    modifier onlyOwner { require(msg.sender == owner, "!owner"); _; }
    function transferOwnership(address n) external onlyOwner { owner = n; }
}

contract WhaleGuard is Owned {
    string public name = "WhaleGuard"; string public symbol = "WG"; uint8 public decimals = 9;
    uint256 public totalSupply = 1e15;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    address public lpPair;
    uint256 public maxSellAmount = 1e13;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor() public { balanceOf[msg.sender] = totalSupply; }
    function setLpPair(address p) external onlyOwner { lpPair = p; }
    function setMaxSell(uint256 v) external onlyOwner { maxSellAmount = v; }

    function _transfer(address from, address to, uint256 value) internal {
        require(balanceOf[from] >= value, "balance");
        if (to == lpPair && from != owner) {
            require(value <= maxSellAmount, "WG: sell exceeds max");
        }
        balanceOf[from] -= value;
        balanceOf[to] += value;
        emit Transfer(from, to, value);
    }
    function transfer(address to, uint256 value) external returns (bool) { _transfer(msg.sender, to, value); return true; }
    function approve(address s, uint256 v) external returns (bool) { allowance[msg.sender][s] = v; emit Approval(msg.sender, s, v); return true; }
    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        require(allowance[from][msg.sender] >= value, "allowance");
        allowance[from][msg.sender] -= value;
        _transfer(from, to, value);
        return true;
    }
}
