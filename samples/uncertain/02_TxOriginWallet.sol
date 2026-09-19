// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract PhishableWallet {
    address public owner;
    constructor() { owner = msg.sender; }
    receive() external payable {}
    function transferTo(address payable dest, uint amount) public {
        require(tx.origin == owner);
        dest.transfer(amount);
    }
}
