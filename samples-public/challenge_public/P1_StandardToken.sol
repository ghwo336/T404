// SPDX-License-Identifier: MIT
// LABEL: BENIGN
//
// 소유자나 특권 역할이 없는 최소 ERC20입니다. 총공급량은 생성자에서 고정되며
// 이후 증가하지 않습니다. 이를 위험으로 판정하면 오탐입니다.
pragma solidity ^0.8.20;

contract StandardToken {
    string public name = "Standard";
    string public symbol = "STD";
    uint8  public constant decimals = 18;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(uint256 initialSupply) {
        totalSupply = initialSupply;
        balanceOf[msg.sender] = initialSupply;
        emit Transfer(address(0), msg.sender, initialSupply);
    }

    function transfer(address to, uint256 value) external returns (bool) {
        // 실수로 토큰이 소각되지 않도록 영 주소로의 전송을 거부합니다.
        require(to != address(0), "zero address");
        require(balanceOf[msg.sender] >= value, "insufficient");
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
        emit Transfer(msg.sender, to, value);
        return true;
    }

    function approve(address spender, uint256 value) external returns (bool) {
        require(spender != address(0), "zero address");
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        require(to != address(0), "zero address");
        require(balanceOf[from] >= value, "insufficient");
        require(allowance[from][msg.sender] >= value, "not allowed");
        allowance[from][msg.sender] -= value;
        balanceOf[from] -= value;
        balanceOf[to] += value;
        emit Transfer(from, to, value);
        return true;
    }
}
