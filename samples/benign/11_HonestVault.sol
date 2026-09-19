// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract FeeVault {
    address public owner;
    mapping(address => uint256) public deposits;
    uint256 public collectedFees;
    uint256 public constant FEE_BPS = 10;
    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }
    constructor() { owner = msg.sender; }

    function deposit() external payable {
        uint256 fee = msg.value * FEE_BPS / 10000;
        collectedFees += fee;
        deposits[msg.sender] += msg.value - fee;
    }
    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount, "insufficient");
        deposits[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
    }
    // only the fee share, never the deposits
    function withdrawFees() external onlyOwner {
        uint256 f = collectedFees; collectedFees = 0;
        (bool ok, ) = owner.call{value: f}("");
        require(ok);
    }
}
