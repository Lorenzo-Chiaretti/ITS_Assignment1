import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent   
sys.path.insert(0, str(ROOT))                   

from Materials.BAD_cipher import BLOCK_BYTES, MASK, encrypt, rotate_left_13, xor 

def rotate_right_13(block: bytes) -> bytes:
    v = int.from_bytes(block, "big")
    return (((v >> 13) | (v << 115)) & MASK).to_bytes(BLOCK_BYTES, "big")


def decrypt(ct: bytes, key1: bytes, key2: bytes) -> bytes:
    return xor(rotate_right_13(xor(ct, key2)), key1)


def main():
    with open(ROOT / "Materials" / "cipher_challenge.json") as f:
        data = json.load(f)

    p0 = bytes.fromhex(data["known_plaintext_hex"])
    c0 = bytes.fromhex(data["known_ciphertext_hex"])

    # Effective key: C = R(K1) xor K2 = E(P0) xor R(P0)
    C = xor(c0, rotate_left_13(p0))
    print("Effective key C =", C.hex())

    def dec_eff(ct: bytes) -> bytes:   # P = R^{-1}(ct xor C)
        return rotate_right_13(xor(ct, C))

    def enc_eff(pt: bytes) -> bytes:   # ct = R(P) xor C
        return xor(rotate_left_13(pt), C)

    assert dec_eff(c0) == p0  # sanity check on the known pair

    for ch in data["challenges"]:
        pt = dec_eff(bytes.fromhex(ch["ciphertext_hex"]))
        print(f'{ch["id"]}: hex = {pt.hex()}  ascii = {pt.decode("ascii")!r}')

    target = bytes.fromhex(data["target_plaintext_hex"])
    print("Target plaintext :", target.hex(), repr(target.decode("ascii")))
    print("Target ciphertext:", enc_eff(target).hex())

    # Sanity: verify against the real cipher using a random key pair that
    k1 = bytes(range(16))
    k2 = xor(C, rotate_left_13(k1))
    assert encrypt(p0, k1, k2) == c0
    assert encrypt(target, k1, k2) == enc_eff(target)
    assert decrypt(c0, k1, k2) == p0
    print("Equivalent-key check passed (K1 is not unique).")


if __name__ == "__main__":
    main()