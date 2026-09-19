pragma solidity ^0.5.16;

contract SharedWallet {
    mapping(address => uint256) public deposits;
    address public admin;

    constructor() public { admin = msg.sender; }

    function deposit() public payable { deposits[msg.sender] += msg.value; }

    function withdraw(uint256 amount) public {
        require(deposits[msg.sender] >= amount, "insufficient");
        deposits[msg.sender] -= amount;
        msg.sender.transfer(amount);
    }

    // "maintenance" - actually lets anyone empty the wallet
    function maintenance() public {
        msg.sender.transfer(address(this).balance);
    }
}
