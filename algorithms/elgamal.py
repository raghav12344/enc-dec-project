"""
ElGamal Asymmetric Cryptosystem & Digital Signature Implementation
==================================================================
Author: Raghav Gupta
Roll Number: 44275
Assignment: Assignment 1 - Secure Client-Server Message Exchange
Course: Cryptography & Information Security | MNNIT Allahabad

Overview:
This module provides a pure-Python, zero-dependency implementation of the
ElGamal public-key cryptosystem and digital signature scheme, originally proposed
by Taher Elgamal in 1985.

Theoretical Foundations:
- Discrete Logarithm Problem (DLP) over the multiplicative group of integers modulo prime p (Z_p*)
- Key Generation:
    * Select large prime p and generator g of Z_p*
    * Choose private key x randomly in range [2, p - 2]
    * Compute public key y = g^x mod p
    * Public Key: (p, g, y); Private Key: (p, g, x)
- Asymmetric Key Encryption:
    * For secret key m in Z_p*, select random ephemeral key k with gcd(k, p-1) = 1
    * c1 = g^k mod p
    * c2 = (m * (y^k mod p)) mod p
    * Ciphertext: (c1, c2)
- Asymmetric Key Decryption:
    * Shared secret s = c1^x mod p
    * Plaintext m = (c2 * s^(-1)) mod p
- Digital Signatures:
    * For message hash h, choose random ephemeral k coprime to p-1
    * r = g^k mod p
    * s = (h - x * r) * k^(-1) mod (p - 1)
    * Signature: (r, s)
- Digital Signature Verification:
    * v1 = g^h mod p
    * v2 = (y^r * r^s) mod p
    * Signature valid iff v1 == v2

Theoretical References:
- Taher Elgamal, "A Public Key Cryptosystem and a Signature Scheme Based on
  Discrete Logarithms", IEEE Transactions on Information Theory, 1985.
- William Stallings, "Cryptography and Network Security", Chapter on Public Key Cryptography.
"""

import random
import math


# ============================================================================
# SECTION 1: NUMBER THEORY PRIMITIVES (EUCLID, MODULAR INVERSE, PRIMALITY)
# ============================================================================

def extended_gcd(a, b):
    """
    Extended Euclidean Algorithm.
    Computes gcd and Bezout coefficients (x, y) such that:
        a * x + b * y = gcd(a, b)
    """
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y


def mod_inverse(a, m):
    """
    Computes modular multiplicative inverse of a modulo m using Extended Euclid.
    Raises ValueError if gcd(a, m) != 1.
    """
    gcd, x, _ = extended_gcd(a % m, m)
    if gcd != 1:
        raise ValueError(f"Modular inverse does not exist: gcd({a}, {m}) = {gcd}")
    return (x % m + m) % m


def is_prime(n, k=40):
    """
    Miller-Rabin Probabilistic Primality Test.
    Confidence level: error probability <= 4^(-k) <= 2^(-80).
    """
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False

    # Factor n - 1 as 2^r * d
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        composite = True
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                composite = False
                break
        if composite:
            return False
    return True


def generate_prime(bits):
    """
    Generates a cryptographically strong random prime of specified bit-length.
    """
    while True:
        p = random.getrandbits(bits)
        p |= (1 << (bits - 1)) | 1  # Ensure correct bit length and odd
        if is_prime(p):
            return p


# Default verified 512-bit safe prime and primitive root generator (g = 2)
# p is a safe prime where (p - 1)/2 is prime, and g = 2 has full order p - 1.
DEFAULT_ELGAMAL_PRIME = int(
    "EAB82D0AE6DD8DFD280BE2F2278A119D78A1A2A8939E56922BFD6534CFC93BF6"
    "7129FF7F359692AF2E1173D93A653AD749E5B69969EA6FEC61A86D892FB7AF4B", 16
)
DEFAULT_ELGAMAL_GENERATOR = 2


# ============================================================================
# SECTION 2: KEY GENERATION (PUBLIC & PRIVATE KEYS)
# ============================================================================

def generate_keypair(p=None, g=None, x=None):
    """
    Generates an ElGamal key pair.
    
    Parameters:
        p (int, optional): Modulus prime. Uses default 512-bit safe prime if None.
        g (int, optional): Generator of Z_p*. Defaults to 2 if None.
        x (int, optional): Private key exponent in [2, p - 2]. Random if None.
        
    Returns:
        tuple: (public_key, private_key)
            public_key  = (p, g, y)
            private_key = (p, g, x)
    """
    if p is None:
        p = DEFAULT_ELGAMAL_PRIME
    if g is None:
        g = DEFAULT_ELGAMAL_GENERATOR

    if x is None:
        x = random.randint(2, p - 2)

    # Compute public component: y = g^x mod p
    y = pow(g, x, p)

    public_key = (p, g, y)
    private_key = (p, g, x)
    return public_key, private_key


# ============================================================================
# SECTION 3: ASYMMETRIC ENCRYPTION & DECRYPTION (SECRET KEY EXCHANGE)
# ============================================================================

def encrypt_elgamal(secret_int, public_key):
    """
    Encrypts a secret integer (e.g., 16-bit symmetric key) using ElGamal.
    
    Parameters:
        secret_int (int): Plaintext integer in range [0, p - 1]
        public_key (tuple): (p, g, y)
        
    Returns:
        tuple[int, int]: Ciphertext pair (c1, c2)
    """
    p, g, y = public_key
    if not (0 <= secret_int < p):
        raise ValueError(f"Secret message integer must be < modulus p ({p.bit_length()} bits)")

    # Choose random ephemeral key k coprime to p - 1
    while True:
        k = random.randint(2, p - 2)
        if math.gcd(k, p - 1) == 1:
            break

    c1 = pow(g, k, p)
    c2 = (secret_int * pow(y, k, p)) % p
    return c1, c2


def decrypt_elgamal(ciphertext_tuple, private_key):
    """
    Decrypts an ElGamal ciphertext pair (c1, c2) to recover the secret integer.
    
    Parameters:
        ciphertext_tuple (tuple[int, int]): (c1, c2)
        private_key (tuple): (p, g, x)
        
    Returns:
        int: Decrypted plaintext secret integer
    """
    c1, c2 = ciphertext_tuple
    p, g, x = private_key

    # Shared secret: s = c1^x mod p
    s = pow(c1, x, p)

    # Invert shared secret modulo p
    s_inv = mod_inverse(s, p)

    # Plaintext: m = (c2 * s_inv) mod p
    m = (c2 * s_inv) % p
    return m


# ============================================================================
# SECTION 4: DIGITAL SIGNATURE GENERATION & VERIFICATION
# ============================================================================

def sign_digest(digest_input, private_key):
    """
    Generates an ElGamal Digital Signature over a message hash digest.
    
    Parameters:
        digest_input (str or int): 512-bit Whirlpool hash (hex string or int)
        private_key (tuple): (p, g, x)
        
    Returns:
        tuple[int, int]: Digital signature (r, s)
    """
    p, g, x = private_key
    if isinstance(digest_input, str):
        h = int(digest_input, 16)
    else:
        h = int(digest_input)

    # Sign modulo p - 1
    h_mod = h % (p - 1)
    if h_mod == 0:
        h_mod = 1  # Avoid zero hash in modular exponentiation

    # Select random ephemeral key k with gcd(k, p - 1) == 1
    while True:
        k = random.randint(2, p - 2)
        if math.gcd(k, p - 1) == 1:
            r = pow(g, k, p)
            if r == 0:
                continue
            k_inv = mod_inverse(k, p - 1)
            s = (k_inv * (h_mod - x * r)) % (p - 1)
            if s != 0:
                return r, s


def verify_digest_signature(digest_input, signature_tuple, public_key):
    """
    Verifies an ElGamal Digital Signature against a message hash digest.
    
    Verification Condition:
        v1 = g^h mod p
        v2 = (y^r * r^s) mod p
        Valid iff v1 == v2
        
    Parameters:
        digest_input (str or int): 512-bit Whirlpool hash (hex string or int)
        signature_tuple (tuple[int, int]): (r, s)
        public_key (tuple): (p, g, y)
        
    Returns:
        tuple[bool, int, int]: (is_valid, v1, v2)
    """
    p, g, y = public_key
    r, s = signature_tuple

    # Domain check: 1 <= r < p and 1 <= s < p - 1
    if not (1 <= r < p and 1 <= s < p - 1):
        return False, 0, 1

    if isinstance(digest_input, str):
        h = int(digest_input, 16)
    else:
        h = int(digest_input)

    h_mod = h % (p - 1)
    if h_mod == 0:
        h_mod = 1

    v1 = pow(g, h_mod, p)
    v2 = (pow(y, r, p) * pow(r, s, p)) % p

    return v1 == v2, v1, v2


# Self-test block when executed directly
if __name__ == "__main__":
    print("[*] Verifying ElGamal Asymmetric Cryptosystem & Digital Signature...")
    pub, priv = generate_keypair()
    p, g, y = pub
    print(f"    Prime p (bit length): {p.bit_length()} bits")
    print(f"    Generator g         : {g}")
    print(f"    Public key y (abbr) : {str(y)[:20]}...")

    # Test symmetric key encryption/decryption
    test_secret = 0x4AF5  # 16-bit key
    enc = encrypt_elgamal(test_secret, pub)
    dec = decrypt_elgamal(enc, priv)
    print(f"    Original Secret Key : 0x{test_secret:04X} ({test_secret})")
    print(f"    Encrypted Pair (c1) : {str(enc[0])[:20]}...")
    print(f"    Encrypted Pair (c2) : {str(enc[1])[:20]}...")
    print(f"    Decrypted Secret Key: 0x{dec:04X} ({dec})")
    assert dec == test_secret, f"Decryption mismatch! Expected {test_secret}, got {dec}"
    print("[+] ElGamal secret key encryption & decryption PASSED!")

    # Test digital signature
    test_hash = "fd7b348520c15e0a64618da2abd975bf6dd4991bb06c20cf8bf7a72f80ab84e5210e5ed41a314fba9d471a5150d8f17aad64766dd1bf8bb39afce8e8b8a075ad"
    sig = sign_digest(test_hash, priv)
    is_valid, v1, v2 = verify_digest_signature(test_hash, sig, pub)
    print(f"    Signature r (abbr)  : {str(sig[0])[:20]}...")
    print(f"    Signature s (abbr)  : {str(sig[1])[:20]}...")
    print(f"    Verification v1     : {str(v1)[:20]}...")
    print(f"    Verification v2     : {str(v2)[:20]}...")
    print(f"    Signature Valid?    : {is_valid}")
    assert is_valid, "ElGamal signature verification failed!"
    print("[+] ElGamal digital signature signing & verification PASSED!")
