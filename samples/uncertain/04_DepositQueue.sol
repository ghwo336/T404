// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

/// Payouts to earlier investors are funded only by later msg.value / deposits (no yield).
contract DepositPonzi {
    address[] private investors;
    uint256 private nextPay;

    function invest() external payable {
        require(msg.value > 0);
        investors.push(msg.sender);
    }

    function payout() external payable {
        require(nextPay < investors.length);
        address payee = investors[nextPay];
        nextPay += 1;
        uint256 n = address(this).balance;
        payable(payee).transfer(n);
    }
}
