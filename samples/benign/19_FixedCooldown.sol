// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
// Constant 30-second cooldown between transfers, applied to everyone including the deployer; no setter.
contract PolitePauseToken {
    uint256 public totalSupply = 1e24;
    uint256 public constant COOLDOWN = 30;
    mapping(address => uint256) private _balances;
    mapping(address => uint256) private _lastTransfer;
    mapping(address => mapping(address => uint256)) public allowance;
    event Transfer(address indexed from, address indexed to, uint256 value);
    constructor() { _balances[msg.sender] = totalSupply; }
    function balanceOf(address a) public view returns (uint256) { return _balances[a]; }
    function transfer(address to, uint256 amount) external returns (bool) { _transfer(msg.sender, to, amount); return true; }
    function approve(address s, uint256 a) external returns (bool) { allowance[msg.sender][s] = a; return true; }
    function transferFrom(address f, address t, uint256 a) external returns (bool) { allowance[f][msg.sender] -= a; _transfer(f, t, a); return true; }
    function _transfer(address from, address to, uint256 amount) internal {
        require(block.timestamp >= _lastTransfer[from] + COOLDOWN, "cooldown");
        _lastTransfer[from] = block.timestamp;
        _balances[from] -= amount;
        _balances[to] += amount;
        emit Transfer(from, to, amount);
    }
}
