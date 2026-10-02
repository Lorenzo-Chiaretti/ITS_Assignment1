### Exercise 1: ElGamal

p = 29837
g = 42
PK = 22690
c1 = 23447
c2 = 8372

#Exercise 1.a
def find_private_key(p, g, PK):
    candidates = []
    for x in range(1, p):
        if pow(g, x, p) == PK:
            candidates.append(x)
    return candidates


def decrypt(p, x, c1, c2):
    mask = pow(c1, x, p)
    inverse_mask = pow(mask,-1, p) 
    m = (c2 * inverse_mask) % p
    return m

def verify_decryption(p, g, PK, x, m):
    c1_check = pow(g, 10, p)
    c2_check = pow(m * pow(PK, 10, p), 1, p)
    return decrypt(p, x, c1_check, c2_check)


#Exercise 1.b
def forge_ciphertext(p, c1, c2, m_known, m_target):
    inv_m = pow(m_known, -1, p)
    t = (m_target * inv_m) % p
    c2_new = (c2 * t) % p
    return c1, c2_new

   

def main():
    candidates = find_private_key(p, g, PK)
    print("Candidates for x: " + str(candidates))
    print("Decrypted cyphertext:" + str(decrypt(p, candidates[0], c1, c2)))
    print("Verification of m: "+ str(verify_decryption(p, g, PK, candidates[0], decrypt(p, candidates[0], c1, c2))))
    print("Forged ciphertext: " + str(forge_ciphertext(p, c1, c2, 26000, 12345)))
    print("Decrypted cyphertext:" + str(decrypt(p, candidates[0], forge_ciphertext(p, c1, c2, 26000, 12345)[0], forge_ciphertext(p, c1, c2, 26000, 12345)[1])))



if __name__ == "__main__":
    main()
    
    