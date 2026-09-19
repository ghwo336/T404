// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract CommunityToken is ERC20, Ownable {
    constructor() ERC20("Community", "CMT") Ownable(msg.sender) {
        _mint(msg.sender, 21_000_000 * 10 ** decimals());
    }
}
