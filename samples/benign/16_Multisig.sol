// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract MultiSig {
    address[] public owners;
    mapping(address => bool) public isOwner;
    uint256 public required;
    struct Tx { address to; uint256 value; bytes data; bool executed; uint256 confirmations; }
    Tx[] public txs;
    mapping(uint256 => mapping(address => bool)) public confirmed;
    constructor(address[] memory _owners, uint256 _required) {
        require(_required > 0 && _required <= _owners.length);
        for (uint256 i; i < _owners.length; i++) { isOwner[_owners[i]] = true; owners.push(_owners[i]); }
        required = _required;
    }
    receive() external payable {}
    modifier onlyOwner() { require(isOwner[msg.sender], "not owner"); _; }
    function submit(address to, uint256 value, bytes calldata data) external onlyOwner {
        txs.push(Tx(to, value, data, false, 0));
    }
    function confirm(uint256 id) external onlyOwner {
        require(!confirmed[id][msg.sender]);
        confirmed[id][msg.sender] = true;
        txs[id].confirmations += 1;
    }
    function execute(uint256 id) external onlyOwner {
        Tx storage t = txs[id];
        require(!t.executed && t.confirmations >= required, "not enough");
        t.executed = true;
        (bool ok, ) = t.to.call{value: t.value}(t.data);
        require(ok);
    }
}
