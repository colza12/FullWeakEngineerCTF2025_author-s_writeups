#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import hashlib
import secrets
from dataclasses import dataclass
from typing import Callable, Optional, Any, Dict
from web3 import Web3, HTTPProvider
from eth_account import Account
from eth_account.signers.local import LocalAccount

ENV = os.getenv("ENV", "production")
PUBLIC_IP = os.getenv("PUBLIC_IP", "127.0.0.1")
HTTP_PORT = int(os.getenv("HTTP_PORT", "8545"))
RPC_URL = os.getenv("RPC_URL", f"http://{PUBLIC_IP}:{HTTP_PORT}")
FUNC_SIG_IS_SOLVED = os.getenv("FUNC_SIG_IS_SOLVED", "isSolved()")
DISABLE_POW = os.getenv("DISABLE_POW", "1") == "1"
POW_BITS = int(os.getenv("POW_BITS", "24" if ENV == "production" else "16"))
FLAG = os.getenv("FLAG", "FLAG{dummy_flag}")
DEFAULT_DEPLOYER_PRIV = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
DEPLOYER_PRIV = os.getenv("DEPLOYER_PRIV", DEFAULT_DEPLOYER_PRIV)

@dataclass
class InstanceState:
    w3: Web3
    deployer: LocalAccount
    player: LocalAccount
    challenge_addr: Optional[str] = None

_current: Optional[InstanceState] = None
_keyring: Dict[str, LocalAccount] = {}

def _print(s: str = ""):
    sys.stdout.write(s + "\n")
    sys.stdout.flush()

def _mk_w3() -> Web3:
    return Web3(HTTPProvider(RPC_URL))

def _wait_for_rpc(timeout_s: int = 30, interval_s: float = 0.5) -> Web3:
    deadline = time.time() + timeout_s
    last_err = None
    while time.time() < deadline:
        try:
            w3 = _mk_w3()
            if w3.is_connected():
                _ = w3.eth.block_number
                return w3
        except Exception as e:
            last_err = e
        time.sleep(interval_s)
    raise RuntimeError(f"cannot connect RPC at {RPC_URL}: {last_err}")

def _to_checksum(addr: str) -> str:
    return Web3.to_checksum_address(addr)

def _resolve_selector(sig_or_hex: str) -> str:
    s = sig_or_hex.strip()
    if s.startswith("0x") and len(s) == 10:
        return s.lower()
    raw4 = Web3.keccak(text=s)[:4]
    return "0x" + bytes(raw4).hex()

def _eth_call_raw(w3: Web3, to: str, data_hex: str) -> bytes:
    return bytes(w3.eth.call({"to": _to_checksum(to), "data": data_hex}))

def _decode_address(ret: bytes) -> str:
    if len(ret) < 32:
        raise ValueError("eth_call return too short for address")
    return _to_checksum("0x" + ret[-20:].hex())

def _wait_receipt(w3: Web3, txh, timeout=120):
    return w3.eth.wait_for_transaction_receipt(txh, timeout=timeout)

def pow_request(bits: int = 24) -> None:
    if DISABLE_POW or bits <= 0:
        return
    prefix = secrets.token_hex(8)
    _print("== PoW ==")
    _print(f'  sha256("{prefix}" + YOUR_INPUT) must start with {bits} zeros in binary')
    sys.stdout.write("  YOUR_INPUT = "); sys.stdout.flush()
    user_in = sys.stdin.readline().strip()
    h = hashlib.sha256((prefix + user_in).encode()).hexdigest()
    ok = bin(int(h, 16))[2:].zfill(256).startswith("0"*bits)
    _print(f'  sha256("{prefix}{user_in}") = {h}')
    if not ok:
        _print("  incorrect")
        raise SystemExit(0)
    _print("  ok")

def send_transaction(w3: Web3, tx: Dict[str, Any], ignore_status: bool = False) -> Dict[str, Any]:
    from_addr = _to_checksum(tx["from"])
    acct = _keyring.get(from_addr.lower())
    if acct is None:
        raise RuntimeError(f"no private key for from={from_addr}")
    txd = dict(tx)
    if "to" in txd and txd["to"] is None:
        txd.pop("to")
    chain_id = w3.eth.chain_id
    nonce = w3.eth.get_transaction_count(from_addr)
    try:
        gas = w3.eth.estimate_gas({**txd, "from": from_addr})
    except Exception:
        gas = 1_500_000
    latest = w3.eth.get_block("latest")
    base_fee = latest.get("baseFeePerGas")
    if base_fee is not None:
        try:
            max_priority = w3.eth.max_priority_fee
        except Exception:
            max_priority = w3.to_wei(2, "gwei")
        fee = {"maxPriorityFeePerGas": int(max_priority), "maxFeePerGas": int(base_fee * 2 + max_priority)}
    else:
        fee = {"gasPrice": int(w3.eth.gas_price)}
    final = {"from": from_addr, "chainId": chain_id, "nonce": nonce, "gas": gas, **fee, **{k: v for k, v in txd.items() if k != "from"}}
    signed = acct.sign_transaction(final)
    raw_tx = getattr(signed, "rawTransaction", None) or getattr(signed, "raw_transaction", None)
    if raw_tx is None:
        raise RuntimeError("SignedTransaction has neither 'rawTransaction' nor 'raw_transaction'")
    txh = w3.eth.send_raw_transaction(raw_tx)
    receipt = _wait_receipt(w3, txh)
    if (not ignore_status) and receipt.get("status", 0) != 1:
        raise RuntimeError(f"tx failed: {receipt}")
    ret = dict(receipt)
    if ret.get("contractAddress"):
        ret["contractAddress"] = _to_checksum(ret["contractAddress"])
    return ret

def new_launch_instance_action(deploy_fn: Callable[[Web3, str, str], str]):
    def _action():
        global _current, _keyring
        pow_request(POW_BITS)
        w3 = _wait_for_rpc(timeout_s=30, interval_s=0.5)
        deployer = Account.from_key(DEPLOYER_PRIV)
        player = Account.create()
        _keyring = {deployer.address.lower(): deployer, player.address.lower(): player}
        _current = InstanceState(w3=w3, deployer=deployer, player=player, challenge_addr=None)
        challenge_addr = deploy_fn(w3, deployer.address, player.address)
        _current.challenge_addr = challenge_addr
        _print(f"RPC endpoint : {RPC_URL}")
        _print(f"Player PRIV  : {player.key.hex()}")
        _print("")
    return _action

def new_kill_instance_action():
    def _action():
        global _current
        if _current is None:
            _print("no active instance.")
        else:
            _current = None
            _print("instance killed.")
    return _action

def new_get_flag_action():
    def _action():
        if _current is None or not _current.challenge_addr:
            _print("no active instance. choose '1 - launch' first.")
            return
        w3 = _current.w3
        setup = _current.challenge_addr
        sel_getbank = _resolve_selector("getBank()")
        bank_bytes = _eth_call_raw(w3, setup, sel_getbank)
        bank = _decode_address(bank_bytes)
        bal_wei = w3.eth.get_balance(bank)
        bal_eth = Web3.from_wei(bal_wei, "ether")
        sel_solved = _resolve_selector(FUNC_SIG_IS_SOLVED)
        ret = _eth_call_raw(w3, setup, sel_solved)
        solved = False
        if len(ret) >= 32:
            solved = int.from_bytes(ret[-32:], "big") != 0
        elif len(ret) > 0:
            solved = any(b != 0 for b in ret)
        _print(f"bank balance : {bal_eth} ETH")
        if solved or bal_wei == 0:
            _print(FLAG)
        else:
            _print("retry")
    return _action

def run_launcher(actions: list) -> None:
    menu = [
        "1 - launch new instance",
        "2 - kill instance",
        "3 - get flag",
    ]
    _print("Welcome to blockchain CTF.")
    while True:
        _print("")
        for m in menu:
            _print(m)
        sys.stdout.write("action? "); sys.stdout.flush()
        choice = sys.stdin.readline().strip()
        if choice == "1":
            actions[0]()
        elif choice == "2":
            actions[1]()
        elif choice == "3":
            actions[2]()
        else:
            _print("bye.")
            break
