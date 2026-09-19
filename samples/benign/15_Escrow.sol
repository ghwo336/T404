// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Escrow {
    address public buyer;
    address public seller;
    address public arbiter;
    uint256 public amount;
    bool public released;
    constructor(address _seller, address _arbiter) payable {
        buyer = msg.sender; seller = _seller; arbiter = _arbiter; amount = msg.value;
    }
    function release() external {
        require(msg.sender == buyer || msg.sender == arbiter, "auth");
        require(!released);
        released = true;
        payable(seller).transfer(amount);
    }
    function refund() external {
        require(msg.sender == seller || msg.sender == arbiter, "auth");
        require(!released);
        released = true;
        payable(buyer).transfer(amount);
    }
}
