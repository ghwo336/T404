// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
interface IERC20 { function transfer(address to, uint256 amount) external returns (bool); function balanceOf(address a) external view returns (uint256); }

contract LinearVesting {
    IERC20 public immutable token;
    address public immutable beneficiary;
    uint64 public immutable start;
    uint64 public immutable duration;
    uint256 public released;

    constructor(IERC20 t, address b, uint64 s, uint64 d) { token = t; beneficiary = b; start = s; duration = d; }

    function vestedAmount(uint64 ts) public view returns (uint256) {
        uint256 total = token.balanceOf(address(this)) + released;
        if (ts < start) return 0;
        if (ts >= start + duration) return total;
        return (total * (ts - start)) / duration;
    }
    function release() external {
        uint256 amount = vestedAmount(uint64(block.timestamp)) - released;
        released += amount;
        require(token.transfer(beneficiary, amount), "transfer failed");
    }
}
