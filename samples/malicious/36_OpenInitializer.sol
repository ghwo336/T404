// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract NonstdInitialize {
    address public owner;
    mapping(address => bool) public blacklisted;

    constructor() {
        owner = msg.sender;
    }

    function initialize() external {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "owner");
        _;
    }

    function setBlacklist(address account, bool status) external onlyOwner {
        blacklisted[account] = status;
    }
}
