"""Deterministic Merkle tree utilities for NEMESIS case integrity."""
import hashlib

def _leaf(hash_hex: str) -> str:
    return hashlib.sha256(b"NEMESIS-LEAF:" + bytes.fromhex(hash_hex)).hexdigest()

def _node(left: str, right: str) -> str:
    return hashlib.sha256(b"NEMESIS-NODE:" + bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()

def calculate_merkle_root(file_hashes: list[str]) -> str:
    if not file_hashes:
        raise ValueError("Cannot create a Merkle root from an empty list.")
    level = [_leaf(h) for h in file_hashes]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [_node(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]
