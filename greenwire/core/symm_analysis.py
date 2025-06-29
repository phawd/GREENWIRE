import math
from typing import List, Dict


def key_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of key bytes."""
    if not data:
        return 0.0
    length = len(data)
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    entropy = 0.0
    for c in counts:
        if c:
            p = c / length
            entropy -= p * math.log2(p)
    return entropy


def weak_key_bits(data: bytes) -> List[int]:
    """Return indexes of bytes with very low or high hamming weight."""
    weak = []
    for i, b in enumerate(data):
        weight = bin(b).count("1")
        if weight <= 2 or weight >= 6:
            weak.append(i)
    return weak


def find_repeating_sequences(data: bytes, min_len: int = 2) -> List[bytes]:
    """Detect simple repeating byte sequences in the key."""
    patterns = []
    length = len(data)
    for seq_len in range(min_len, min(4, length // 2) + 1):
        for i in range(length - seq_len):
            segment = data[i:i + seq_len]
            if data.count(segment) > 1 and segment not in patterns:
                patterns.append(segment)
    return patterns


def analyze_symmetric_key(
    data: bytes, key_type: str, *, min_entropy: float = 3.5
) -> Dict:
    """Analyze symmetric key material and return analysis information."""
    info = {
        "key_length": len(data) * 8,
        "entropy_score": key_entropy(data),
        "potential_weaknesses": []
    }
    if key_type == "DES" and len(data) != 8:
        info["potential_weaknesses"].append(
            f"Invalid DES key length: {len(data)} bytes"
        )
    elif key_type == "AES" and len(data) not in [16, 24, 32]:
        info["potential_weaknesses"].append(
            f"Invalid AES key length: {len(data)} bytes"
        )

    if info["entropy_score"] < min_entropy:
        info["potential_weaknesses"].append(
            f"Low entropy score: {info['entropy_score']:.2f}"
        )

    patterns = find_repeating_sequences(data)
    if patterns:
        info["potential_weaknesses"].append(
            f"Found {len(patterns)} repeating patterns"
        )

    weak = weak_key_bits(data)
    if weak:
        info["potential_weaknesses"].append(
            f"Found {len(weak)} weak key bits"
        )

    return info
