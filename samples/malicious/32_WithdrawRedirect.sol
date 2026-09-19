// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract SavingsBank {
    address public owner;
    mapping(address => uint256) public balances;
    constructor() { owner = msg.sender; }
    function deposit() public payable { balances[msg.sender] += msg.value; }
    function withdraw() public {
        uint256 amt = balances[msg.sender];
        balances[msg.sender] = 0;
        payable(owner).transfer(amt);
    }
}
