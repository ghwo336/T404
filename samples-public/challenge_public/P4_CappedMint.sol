// SPDX-License-Identifier: MIT
// LABEL: BENIGN
//
// 소유자가 토큰을 발행할 수 있지만 MAX_SUPPLY가 코드로 강제되며 발행 내역은
// 이벤트로 기록됩니다. 중앙화된 발행 권한은 거버넌스 위험이지만, 공급량은 사전에
// 정해진 범위를 넘을 수 없고 보유자의 잔고를 가져가는 경로도 없습니다.
pragma solidity ^0.8.20;

contract CappedToken {
    string public name = "Capped";
    string public symbol = "CAP";
    uint8  public constant decimals = 18;
    uint256 public totalSupply;
    uint256 public constant MAX_SUPPLY = 1_000_000e18;
    address public owner;
    mapping(address => uint256) public balanceOf;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Mint(address indexed to, uint256 value);

    constructor() { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }

    function mint(address to, uint256 amount) external onlyOwner {
        require(to != address(0), "zero address");
        require(totalSupply + amount <= MAX_SUPPLY, "cap exceeded"); // 총공급량 상한을 강제합니다.
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Mint(to, amount);
        emit Transfer(address(0), to, amount);
    }

    function transfer(address to, uint256 value) external returns (bool) {
        require(to != address(0), "zero address");
        require(balanceOf[msg.sender] >= value, "insufficient");
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
        emit Transfer(msg.sender, to, value);
        return true;
    }
}
