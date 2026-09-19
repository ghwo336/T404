# noexit real-world benchmark

Sources: Pied-Piper backdoor list (TOSEM 2022, 189 Ethereum ERC-20 contracts) + 29 blue-chip tokens. 1 skipped (source not verified / not cached).

| label \ verdict | Malicious | Uncertain | Benign | total |
|---|---|---|---|---|
| Malicious (backdoor) | **151** | 21 | 16 | 188 |
| Benign (blue-chip) | 2 | 4 | **23** | 29 |

- recall (Malicious flagged as Malicious): **80.3%**; counting Uncertain as a flag: 91.5%
- precision: **98.7%**, F1: **0.886**

## Recall by backdoor category

| category | n | Malicious | Uncertain | Benign |
|---|---|---|---|---|
| ArbitraryTransfer | 1 | 1 | 0 | 0 |
| GenerateToken | 34 | 31 | 0 | 3 |
| DestoryToken | 29 | 19 | 8 | 2 |
| FreezeAccount | 95 | 87 | 1 | 7 |
| DisableTransfer | 29 | 13 | 12 | 4 |

## Blue-chip tokens

| token | verdict | score | top findings | note |
|---|---|---|---|---|
| WETH | Benign | 0 |  |  |
| UNI | Benign | 7 | BALANCE_MANIPULATION |  |
| LINK | Benign | 0 |  |  |
| DAI | Benign | 7 | HIDDEN_MINT |  |
| AAVE | Benign | 2 | UPGRADEABLE_PROXY | multi-file (19) proxy->0x5d4aa78b08bc7c530e21bf7447988b1be7991322 |
| COMP | Benign | 0 |  |  |
| SHIB | Benign | 0 |  |  |
| PEPE | Malicious | 47 | BLACKLIST_GATE,OWNER_LIMIT_TO_ZERO |  |
| CRV | Uncertain | 0 |  |  |
| LDO | Malicious | 100 | EXTERNAL_TRANSFER_HOOK,APPROVAL_BYPASS |  |
| ENS | Benign | 2 | OWNER_MINT | multi-file (16) |
| 1INCH | Benign | 7 | HIDDEN_MINT |  |
| SUSHI | Benign | 7 | HIDDEN_MINT |  |
| YFI | Benign | 7 | HIDDEN_MINT |  |
| BAT | Benign | 0 |  |  |
| ZRX | Benign | 0 |  |  |
| GRT | Benign | 7 | HIDDEN_MINT |  |
| BAL | Benign | 7 | HIDDEN_MINT |  |
| APE | Benign | 0 |  | multi-file (5) |
| GNO | Benign | 0 |  |  |
| LRC | Benign | 0 |  |  |
| MANA | Uncertain | 14 | TRADING_GATE,HIDDEN_MINT |  |
| SAND | Benign | 0 |  | multi-file (8) |
| AXS | Benign | 0 |  |  |
| CHZ | Benign | 7 | TRADING_GATE |  |
| OMG | Uncertain | 22 | TRADING_GATE,HIDDEN_MINT |  |
| CRO | Benign | 7 | HIDDEN_MINT |  |
| QNT | Benign | 7 | BALANCE_MANIPULATION |  |
| ENJ | Uncertain | 26 | BALANCE_MANIPULATION,BALANCE_MANIPULATION |  |

## Missed / uncertain backdoors

| address | category | verdict | top findings |
|---|---|---|---|
| 0x2604fa406be957e542beb89e6754fcde6815e83f | GenerateToken | Benign | OWNER_MINT,TRADING_GATE |
| 0xb052f8a33d8bb068414eade06af6955199f9f010 | GenerateToken | Benign | HIDDEN_MINT |
| 0xf4134146af2d511dd5ea8cdb1c4ac88c57d60404 | GenerateToken | Benign |  |
| 0x9f8f72aa9304c8b593d555f12ef6589cc3a579a2 | DestoryToken | Uncertain | TRADING_GATE,HIDDEN_MINT |
| 0x89d24a6b4ccb1b6faa2625fe562bdd9a23260359 | DestoryToken | Uncertain | TRADING_GATE,HIDDEN_MINT |
| 0x99bc08db67f52010f2d6017b7ad968808113db10 | DestoryToken | Uncertain | SELFDESTRUCT,HIDDEN_MINT |
| 0x574f84108a98c575794f75483d801d1d5dc861a5 | DestoryToken | Uncertain | SELFDESTRUCT,HIDDEN_MINT |
| 0x814f67fa286f7572b041d041b1d99b432c9155ee | DestoryToken | Benign |  |
| 0x1829aa045e21e0d59580024a951db48096e01782 | DestoryToken | Benign | PRIVILEGED_WITHDRAW |
| 0x2396fbc0e2e3ae4b7206ebdb5706e2a5920349cb | DestoryToken | Uncertain | SELFDESTRUCT,BALANCE_MANIPULATION |
| 0xc7c03b8a3fc5719066e185ea616e87b88eba44a3 | DestoryToken | Uncertain | SELFDESTRUCT,HIDDEN_MINT |
| 0xe7d3e4413e29ae35b0893140f4500965c74365e5 | DestoryToken | Uncertain | SELFDESTRUCT,PRIVILEGED_WITHDRAW |
| 0xea38eaa3c86c8f9b751533ba2e562deb9acded40 | DestoryToken | Uncertain | BALANCE_MANIPULATION |
| 0x0b6e701cd51a9e1b5829a4c4fe2130d60c0c4f6c | FreezeAccount | Benign | PRIVILEGED_WITHDRAW,TRADING_GATE |
| 0x6e8b6f2d02eacbe33b4c45154cbfa53df1b542ea | FreezeAccount | Benign |  |
| 0x89f70fa9f439dbd0a1bc22a09befc56ada04d9b4 | FreezeAccount | Benign |  |
| 0x240bae5a27233fd3ac5440b5a598467725f7d1cd | FreezeAccount | Benign |  |
| 0x17280da053596e097604839c61a2ef5efb7d493f | FreezeAccount | Benign | HIDDEN_MINT |
| 0xf3b450002c7bc300ea03c9463d8e8ba7f821b7c6 | FreezeAccount | Benign |  |
| 0xfa456cf55250a839088b27ee32a424d7dacb54ff | FreezeAccount | Uncertain | BALANCE_MANIPULATION,BALANCE_MANIPULATION |
| 0x6f7a4bac3315b5082f793161a22e26666d22717f | FreezeAccount | Benign |  |
| 0x6d3475a51ef25e210e7f2851ce4af528738a975a | DisableTransfer | Benign | TRADING_GATE |
| 0x7e0d051ec68668d603c4e33255d1aed342a691b7 | DisableTransfer | Uncertain | TRADING_GATE |
| 0x8bcb64bfda77905398b67af0af084c744e777a20 | DisableTransfer | Benign |  |
| 0x9f8f72aa9304c8b593d555f12ef6589cc3a579a2 | DisableTransfer | Uncertain | TRADING_GATE,HIDDEN_MINT |
| 0x14c926f2290044b647e1bf2072e67b495eff1905 | DisableTransfer | Uncertain | TRADING_GATE,HIDDEN_MINT |
| 0x17d30c85376bc2c39edc1da179162d308559a3c4 | DisableTransfer | Uncertain | TRADING_GATE |
| 0x031e0c6a7c91df1bc171d33cccc6988fd2ddeb6f | DisableTransfer | Uncertain | TRADING_GATE |
| 0x89d24a6b4ccb1b6faa2625fe562bdd9a23260359 | DisableTransfer | Uncertain | TRADING_GATE,HIDDEN_MINT |
| 0x381beac50b9a5ea06a320a72592f7460c49a2b48 | DisableTransfer | Uncertain | TRADING_GATE |
| 0x9954ff0295443c01f562dccb1f893be464e01986 | DisableTransfer | Uncertain | TRADING_GATE |
| 0x27054b13b1b798b345b591a4d22e6562d47ea75a | DisableTransfer | Benign | TRADING_GATE |
| 0xa66daa57432024023db65477ba87d4e7f5f95213 | DisableTransfer | Uncertain | TRADING_GATE |
| 0xbc2faad1ec407571249b0e874a9abd840111389b | DisableTransfer | Uncertain | TRADING_GATE |
| 0xc5b106f17246b2f5c0c658dbd6e8d168695806ab | DisableTransfer | Uncertain | TRADING_GATE |
| 0xda2e0aa8f697db190c32034894cf9731f6619960 | DisableTransfer | Uncertain | TRADING_GATE |
| 0xdf859c9878ef5e742d7bbe3c22a496c088c89fa9 | DisableTransfer | Benign | TRADING_GATE |
