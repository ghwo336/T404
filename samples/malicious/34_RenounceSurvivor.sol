// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract FakeRenounce {
    address public owner;
    address private _dev;
    mapping(address => bool) public blacklisted;

    constructor() {
        owner = msg.sender;
        _dev = msg.sender;
    }

    function renounceOwnership() external {
        require(msg.sender == owner, "owner");
        owner = address(0);
    }

    modifier onlyDev() {
        require(msg.sender == _dev, "dev");
        _;
    }

    function setBlacklist(address account, bool status) external onlyDev {
        blacklisted[account] = status;
    }
}
