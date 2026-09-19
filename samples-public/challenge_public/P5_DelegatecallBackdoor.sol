// SPDX-License-Identifier: MIT
// LABEL: MALICIOUS
//
// 임의 delegatecall을 실행하는 백도어가 있습니다. 입금과 일반 출금은 정상적으로
// 동작하지만, 소유자는 execute()를 통해 선택한 코드를 이 컨트랙트의 스토리지
// 문맥에서 실행할 수 있습니다. 이를 이용해 예치 기록과 소유권을 변경하고 사용자
// 예치금을 인출할 수 있습니다.
// 근거: execute()는 소유자가 지정한 대상과 데이터로 delegatecall을 실행합니다.
pragma solidity ^0.8.20;

contract Vault {
    address public owner;
    mapping(address => uint256) public deposits;

    event Deposited(address indexed account, uint256 amount);
    event Withdrawn(address indexed account, uint256 amount);

    constructor() { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }

    function deposit() external payable {
        deposits[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    // 외부 송금 전에 예치 기록을 갱신합니다.
    function withdraw(uint256 amount) external {
        require(deposits[msg.sender] >= amount, "insufficient");
        deposits[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        emit Withdrawn(msg.sender, amount);
    }

    // 소유자가 임의 코드를 현재 컨트랙트의 스토리지 문맥에서 실행합니다.
    function execute(address target, bytes calldata data) external onlyOwner {
        (bool ok, ) = target.delegatecall(data);
        require(ok, "exec failed");
    }
}
