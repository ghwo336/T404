// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
import "./lib/ERC20.sol";
import "./lib/Ownable.sol";

contract GoodToken is ERC20, Ownable {
    constructor() ERC20("Good", "GOOD") { _mint(msg.sender, 1_000_000e18); }
    function burn(uint256 amount) external { _balances[msg.sender] -= amount; _totalSupply -= amount; emit Transfer(msg.sender, address(0), amount); }
}
