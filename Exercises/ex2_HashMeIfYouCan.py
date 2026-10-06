import hashlib
import math
import os
import time


def H(m: str, b: int) -> bytes:
    return hashlib.sha256(m.encode("utf-8")).digest()[: b // 8]


# Exercise 2.a
def find_collision(b: int, prefix: str = "msg-"):
    seen = {} 
    i = 0
    while True:
        m = f"{prefix}{i}"
        h = H(m, b)
        if h in seen and seen[h] != m:
            return seen[h], m, i + 1
        seen[h] = m
        i += 1


def main():
    for b in (16, 24, 32):
        # Different prefix per run so repeated runs give different examples
        prefix = os.urandom(4).hex() + "-"
        t0 = time.perf_counter()
        m1, m2, n = find_collision(b, prefix)
        dt = time.perf_counter() - t0

        # Independent verification
        assert m1 != m2
        assert H(m1, b) == H(m2, b)

        expected = math.sqrt(math.pi / 2 * 2**b)
        print(f"--- b            = {b} bits ({b // 8} bytes) ---")
        print(f"m1               = {m1!r}")
        print(f"m2               = {m2!r}")
        print(f"H_b(m1)          = {H(m1, b).hex()}")
        print(f"H_b(m2)          = {H(m2, b).hex()}")
        print(f"full SHA-256(m1) = {hashlib.sha256(m1.encode()).hexdigest()}")
        print(f"full SHA-256(m2) = {hashlib.sha256(m2.encode()).hexdigest()}")
        print(f"hashes computed  = {n}  (expected ~ {expected:.0f}, 2^(b/2) = {2 ** (b / 2):.0f})")
        print(f"time             = {dt:.3f} s\n")


if __name__ == "__main__":
    main()