import hashlib


def calculate_merkle_root(hashes):
    """Return a deterministic SHA-256 Merkle root for a list of hex hashes."""
    if not hashes:
        return None
    level = [bytes.fromhex(h) for h in hashes]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            nxt.append(hashlib.sha256(left + right).digest())
        level = nxt
    return level[0].hex()
