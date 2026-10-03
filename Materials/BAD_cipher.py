"""Public specification of the deliberately insecure cipher in Exercise 3.

Python 3.10+. Blocks and both keys are exactly 16 bytes. No padding or mode
of operation is used: each challenge is one independent block.
"""

BLOCK_BYTES = 16
MASK = (1 << 128) - 1


def rotate_left_13(block: bytes) -> bytes:
    if len(block) != BLOCK_BYTES:
        raise ValueError("Expected exactly 16 bytes")
    value = int.from_bytes(block, "big")
    return (((value << 13) & MASK) | (value >> 115)).to_bytes(16, "big")


def xor(left: bytes, right: bytes) -> bytes:
    if len(left) != BLOCK_BYTES or len(right) != BLOCK_BYTES:
        raise ValueError("Expected exactly 16 bytes per operand")
    return bytes(a ^ b for a, b in zip(left, right))


def encrypt(plaintext: bytes, key1: bytes, key2: bytes) -> bytes:
    return xor(rotate_left_13(xor(plaintext, key1)), key2)


if __name__ == "__main__":
    # Public test vector. These are NOT the challenge keys.
    p = bytes(16)
    k1 = bytes.fromhex("00000000000000000000000000000001")
    k2 = bytes(16)
    expected = "00000000000000000000000000002000"
    assert encrypt(p, k1, k2).hex() == expected
    print("Public test vector passed:", expected)
