// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
contract SimpleVault is Ownable, ReentrancyGuard {
    using SafeERC20 for IERC20;
    IERC20 public immutable asset;
    mapping(address => uint256) public balances;
    uint256 public totalDeposited;
    constructor(IERC20 _asset) { asset = _asset; }
    function deposit(uint256 amount) external nonReentrant {
        asset.safeTransferFrom(msg.sender, address(this), amount);
        balances[msg.sender] += amount;
        totalDeposited += amount;
    }
    function withdraw(uint256 amount) external nonReentrant {
        balances[msg.sender] -= amount;
        totalDeposited -= amount;
        asset.safeTransfer(msg.sender, amount);
    }
    function rescueToken(IERC20 token, address to) external onlyOwner {
        require(address(token) != address(asset), "cannot rescue asset");
        token.safeTransfer(to, token.balanceOf(address(this)));
    }
}
