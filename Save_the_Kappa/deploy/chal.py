#!/usr/bin/env python3

import json
from pathlib import Path
from web3 import Web3
import eth_sandbox.launcher

SEED_ETHER = 10
PLAYER_ETHER = 1

ARTIFACTS_ROOT = Path("/ctf/contracts/out")

def _find_artifact(contract: str) -> Path:
    p = ARTIFACTS_ROOT / f"{contract}.sol" / f"{contract}.json"
    if p.exists():
        return p
    cands = list(ARTIFACTS_ROOT.rglob(f"{contract}.json"))
    if not cands:
        raise FileNotFoundError(f"artifact not found for {contract}")
    cands.sort(key=lambda x: len(str(x)))
    return cands[0]

def _sel(signature: str) -> str:
    raw4 = Web3.keccak(text=signature)[:4]
    return "0x" + bytes(raw4).hex()

def _eth_call(w3: Web3, to: str, data_hex: str) -> bytes:
    return bytes(w3.eth.call({"to": Web3.to_checksum_address(to), "data": data_hex}))

def _decode_addr(ret: bytes) -> str:
    if len(ret) < 32:
        raise ValueError("eth_call return too short for address")
    return Web3.to_checksum_address("0x" + ret[-20:].hex())

def deploy(w3: Web3, deployer: str, player: str) -> str:
    setup_json = json.loads(_find_artifact("Setup").read_text())
    setup_bytecode = setup_json["bytecode"]["object"]

    receipt = eth_sandbox.launcher.send_transaction(
        w3,
        {"from": deployer, "data": setup_bytecode, "value": w3.to_wei(SEED_ETHER, "ether")},
        ignore_status=True,
    )
    setup_addr = Web3.to_checksum_address(receipt["contractAddress"])

    bank_raw = _eth_call(w3, setup_addr, _sel("getBank()"))
    bank_addr = _decode_addr(bank_raw)

    print(f"[save_the_kappa] Setup         : {setup_addr}")
    print(f"[save_the_kappa] VulnerableBank: {bank_addr}")

    eth_sandbox.launcher.send_transaction(
        w3, {"from": deployer, "to": player, "value": w3.to_wei(PLAYER_ETHER, "ether")}
    )
    return setup_addr

if __name__ == "__main__":
    eth_sandbox.launcher.run_launcher(
        [
            eth_sandbox.launcher.new_launch_instance_action(deploy),
            eth_sandbox.launcher.new_kill_instance_action(),
            eth_sandbox.launcher.new_get_flag_action(),
        ]
    )
