// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
import "./lib/ERC20.sol";
import "./lib/Ownable.sol";

// The token file itself is spotless. The backdoor lives in ./lib/ERC20.sol: transferFrom skips the allowance check for the deployer.
contract CleanLookingToken is ERC20, Ownable {
    constructor() ERC20("Clean", "CLEAN") { _mint(msg.sender, 1_000_000e18); }
}
