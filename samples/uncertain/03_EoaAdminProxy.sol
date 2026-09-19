// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

contract EoaAdminProxy {
    address public admin;
    address public implementation;

    constructor(address impl) {
        admin = msg.sender;
        implementation = impl;
    }

    function setImplementation(address nextImpl) external {
        require(msg.sender == admin, "admin");
        implementation = nextImpl;
    }

    receive() external payable {}

    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch ok
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
