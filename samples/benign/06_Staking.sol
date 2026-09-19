// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
interface IERC20 { function transfer(address to, uint256 amount) external returns (bool); function transferFrom(address f, address t, uint256 a) external returns (bool); }

contract SimpleStaking {
    IERC20 public immutable token;
    address public owner;
    mapping(address => uint256) public staked;
    uint256 public totalStaked;
    uint256 public collectedFees;
    uint256 public constant EXIT_FEE_BPS = 50;

    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }
    constructor(IERC20 t) { token = t; owner = msg.sender; }

    function stake(uint256 amount) external {
        require(token.transferFrom(msg.sender, address(this), amount), "transfer failed");
        staked[msg.sender] += amount; totalStaked += amount;
    }
    function unstake(uint256 amount) external {
        require(staked[msg.sender] >= amount, "too much");
        staked[msg.sender] -= amount; totalStaked -= amount;
        uint256 fee = amount * EXIT_FEE_BPS / 10000;
        collectedFees += fee;
        require(token.transfer(msg.sender, amount - fee), "transfer failed");
    }
    function withdrawFees() external onlyOwner {
        uint256 f = collectedFees; collectedFees = 0;
        require(token.transfer(owner, f), "transfer failed");
    }
    function transferOwnership(address n) external onlyOwner { require(n != address(0)); owner = n; }
}
