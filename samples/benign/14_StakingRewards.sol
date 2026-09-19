// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
contract StakingRewards is Ownable, ReentrancyGuard {
    IERC20 public stakingToken;
    IERC20 public rewardsToken;
    uint256 public rewardRate;
    uint256 public lastUpdateTime;
    uint256 public rewardPerTokenStored;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => uint256) public userRewardPerTokenPaid;
    mapping(address => uint256) public rewards;
    constructor(address s, address r) { stakingToken = IERC20(s); rewardsToken = IERC20(r); }
    modifier updateReward(address account) {
        rewardPerTokenStored = rewardPerToken();
        lastUpdateTime = block.timestamp;
        if (account != address(0)) {
            rewards[account] = earned(account);
            userRewardPerTokenPaid[account] = rewardPerTokenStored;
        }
        _;
    }
    function rewardPerToken() public view returns (uint256) {
        if (totalSupply == 0) return rewardPerTokenStored;
        return rewardPerTokenStored + (block.timestamp - lastUpdateTime) * rewardRate * 1e18 / totalSupply;
    }
    function earned(address a) public view returns (uint256) {
        return balanceOf[a] * (rewardPerToken() - userRewardPerTokenPaid[a]) / 1e18 + rewards[a];
    }
    function stake(uint256 amount) external nonReentrant updateReward(msg.sender) {
        totalSupply += amount;
        balanceOf[msg.sender] += amount;
        stakingToken.transferFrom(msg.sender, address(this), amount);
    }
    function withdraw(uint256 amount) public nonReentrant updateReward(msg.sender) {
        totalSupply -= amount;
        balanceOf[msg.sender] -= amount;
        stakingToken.transfer(msg.sender, amount);
    }
    function getReward() public nonReentrant updateReward(msg.sender) {
        uint256 reward = rewards[msg.sender];
        if (reward > 0) {
            rewards[msg.sender] = 0;
            rewardsToken.transfer(msg.sender, reward);
        }
    }
    function setRewardRate(uint256 r) external onlyOwner updateReward(address(0)) {
        require(r <= 1e20, "rate");
        rewardRate = r;
    }
}
