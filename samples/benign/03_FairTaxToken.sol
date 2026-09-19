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

contract FairTaxToken is ERC20, Ownable {
    address public uniswapV2Pair;
    address public treasury;
    uint256 public buyFee = 2;
    uint256 public sellFee = 4;
    uint256 public constant MAX_FEE = 5;
    uint256 public maxTxAmount;
    bool public tradingEnabled;
    mapping(address => bool) public isExcludedFromFee;

    constructor(address pair_, address treasury_) ERC20("FairTax", "FTX") {
        uniswapV2Pair = pair_; treasury = treasury_;
        _mint(msg.sender, 1e27);
        maxTxAmount = _totalSupply / 100;
        isExcludedFromFee[msg.sender] = true; isExcludedFromFee[address(this)] = true;
    }
    function enableTrading() external onlyOwner { tradingEnabled = true; }
    function setFees(uint256 _buy, uint256 _sell) external onlyOwner {
        require(_buy <= MAX_FEE && _sell <= MAX_FEE, "fee too high");
        buyFee = _buy; sellFee = _sell;
    }
    function setMaxTx(uint256 v) external onlyOwner {
        require(v >= _totalSupply / 200, "max tx too low");
        maxTxAmount = v;
    }
    function excludeFromFee(address a, bool v) external onlyOwner { isExcludedFromFee[a] = v; }
    function _transfer(address from, address to, uint256 amount) internal override {
        if (!isExcludedFromFee[from] && !isExcludedFromFee[to]) {
            require(tradingEnabled, "trading not open");
            require(amount <= maxTxAmount, "max tx");
        }
        uint256 fee = 0;
        if (!isExcludedFromFee[from] && !isExcludedFromFee[to]) {
            if (from == uniswapV2Pair) fee = buyFee;
            else if (to == uniswapV2Pair) fee = sellFee;
        }
        uint256 feeAmount = amount * fee / 100;
        if (feeAmount > 0) super._transfer(from, treasury, feeAmount);
        super._transfer(from, to, amount - feeAmount);
    }
    function withdrawStuckETH() external onlyOwner { payable(owner()).transfer(address(this).balance); }
}
