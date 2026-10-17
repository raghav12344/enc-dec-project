"""
RSA Asymmetric Cryptosystem Implementation
==========================================
Author: Raghav Gupta
Roll Number: 20243226
Assignment: Assignment 1 - Secure Client-Server Message Exchange
Course: Cryptography & Information Security | MNNIT Allahabad

Overview:
This module provides a pure-Python, zero-dependency implementation of the
Rivest-Shamir-Adleman (RSA) public-key cryptosystem.

Theoretical Foundations:
- Euler's Totient Theorem: a^phi(n) = 1 (mod n) for gcd(a, n) = 1
- Bezout's Identity: a*x + b*y = gcd(a, b) via Extended Euclidean Algorithm
- Miller-Rabin Probabilistic Primality Test: Solovay-Strassen refinement
- Asymmetric Key Exchange: Hybrid encryption of symmetric secret keys
- Digital Signatures: Integrity and non-repudiation over cryptographic hash digests
"""

import random
import math


# ============================================================================
# SECTION 1: NUMBER THEORY PRIMITIVES (EUCLID, TOTIENT, MODULAR INVERSE)
# ============================================================================

def extended_gcd(a, b):
    """
    Extended Euclidean Algorithm.
    Computes greatest common divisor and Bezout coefficients (x, y) such that:
        a * x + b * y = gcd(a, b)

    Parameters:
        a (int): First non-negative integer
        b (int): Second non-negative integer
    Returns:
        (gcd, x, y) tuple
    """
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y


def mod_inverse(e, phi):
    """
    Computes modular multiplicative inverse d such that:
        (d * e) = 1 (mod phi)

    Uses Extended Euclidean Algorithm. Raises ValueError if gcd(e, phi) != 1.
    """
    gcd, x, _ = extended_gcd(e, phi)
    if gcd != 1:
        raise ValueError(f"Modular inverse does not exist: gcd({e}, {phi}) = {gcd} != 1")
    return (x % phi + phi) % phi


# ============================================================================
# SECTION 2: PROBABILISTIC PRIMALITY TESTING (MILLER-RABIN)
# ============================================================================

def is_prime(n, k=40):
    """
    Miller-Rabin Probabilistic Primality Test.
    Decomposes n - 1 = 2^r * d (with d odd) and tests k independent random witnesses.

    Parameters:
        n (int): Candidate integer to test for primality
        k (int): Number of testing rounds (k=40 yields error probability < 2^-80)
    Returns:
        bool: True if n is prime with overwhelming probability, False otherwise
    """
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    # Decompose n - 1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Witness testing loop
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits=280):
    """
    Generates a cryptographically strong random prime of specified bit length.
    Sets the highest and lowest bits to ensure exact magnitude and odd parity.
    """
    while True:
        candidate = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_prime(candidate):
            return candidate


# ============================================================================
# SECTION 3: KEY GENERATION (PRIMES p, q -> (e, n) & (d, n))
# ============================================================================

def generate_keypair_from_primes(p, q, e=65537):
    """
    Generates RSA public and private keypairs given prime inputs p and q.

    Mathematical Process:
    1. Compute Modulus: n = p * q
    2. Compute Euler's Totient: phi(n) = (p - 1) * (q - 1)
    3. Verify or select public exponent e such that gcd(e, phi) == 1
    4. Compute private exponent d: d = e^-1 mod phi(n)

    Returns:
        public_key:  (e, n)
        private_key: (d, n)
        params:      {'p': p, 'q': q, 'n': n, 'phi': phi, 'e': e, 'd': d}
    """
    if p == q:
        raise ValueError("Primes p and q must be distinct.")

    n = p * q
    phi = (p - 1) * (q - 1)

    # Ensure gcd(e, phi) == 1
    if math.gcd(e, phi) != 1:
        for candidate_e in [65537, 17, 3, 5, 7, 11, 13, 19, 23, 29]:
            if candidate_e < phi and math.gcd(candidate_e, phi) == 1:
                e = candidate_e
                break
        else:
            e = 3
            while math.gcd(e, phi) != 1:
                e += 2

    d = mod_inverse(e, phi)

    public_key = (e, n)
    private_key = (d, n)
    params = {
        "p": p,
        "q": q,
        "n": n,
        "phi": phi,
        "e": e,
        "d": d
    }
    return public_key, private_key, params


def generate_rsa_keys(bits=280, e=65537):
    """
    Generates full RSA keys with primes of the specified bit length.
    Using bits >= 260 guarantees modulus n > 2^512, which directly accommodates
    512-bit Whirlpool hash digests without requiring modular truncation.
    """
    p = generate_prime(bits)
    q = generate_prime(bits)
    while p == q:
        q = generate_prime(bits)
    return generate_keypair_from_primes(p, q, e)


# ============================================================================
# SECTION 4: ASYMMETRIC ENCRYPTION & DECRYPTION (SECRET KEY EXCHANGE)
# ============================================================================

def encrypt_rsa(plaintext_int, public_key):
    """
    RSA Encryption: c = (m ^ e) mod n
    Used by Client to encrypt the 10-bit symmetric Secret Key.
    """
    e, n = public_key
    if plaintext_int >= n:
        raise ValueError(f"Plaintext integer ({plaintext_int}) must be strictly less than modulus n ({n})")
    return pow(plaintext_int, e, n)


def decrypt_rsa(ciphertext_int, private_key):
    """
    RSA Decryption: m = (c ^ d) mod n
    Used by Server to recover the 10-bit symmetric Secret Key.
    """
    d, n = private_key
    return pow(ciphertext_int, d, n)


# ============================================================================
# SECTION 5: DIGITAL SIGNATURE GENERATION & VERIFICATION
# ============================================================================

def sign_digest(digest_hex_or_int, private_key):
    """
    RSA Digital Signature Generation:
        Signature S = (Hash mod n) ^ d mod n

    Signing with the Client's private exponent guarantees message authenticity
    and non-repudiation.
    """
    d, n = private_key
    if isinstance(digest_hex_or_int, str):
        h_int = int(digest_hex_or_int, 16)
    else:
        h_int = int(digest_hex_or_int)

    h_reduced = h_int % n
    signature = pow(h_reduced, d, n)
    return signature


def verify_digest_signature(signature, expected_digest_hex_or_int, public_key):
    """
    RSA Digital Signature Verification:
        Verification Code V = (Signature ^ e) mod n

    Checks if V == (expected_digest mod n).
    Returns:
        (is_valid, verification_code, expected_code)
    """
    e, n = public_key
    if isinstance(expected_digest_hex_or_int, str):
        expected_int = int(expected_digest_hex_or_int, 16)
    else:
        expected_int = int(expected_digest_hex_or_int)

    expected_reduced = expected_int % n
    verification_code = pow(signature, e, n)
    is_valid = (verification_code == expected_reduced)
    return is_valid, verification_code, expected_reduced


if __name__ == "__main__":
    print("=== RSA Module Verification (Author: Raghav Gupta, Roll No: 20243226) ===")
    pub, priv, params = generate_rsa_keys(bits=280)
    print(f"Generated modulus n ({params['n'].bit_length()} bits)")
    val = 642
    enc = encrypt_rsa(val, pub)
    dec = decrypt_rsa(enc, priv)
    assert val == dec
    print(f"Original Secret Key:  {val}")
    print(f"Encrypted Secret Key: {enc}")
    print(f"Decrypted Secret Key: {dec}")
    print("\nVerification: SUCCESS! RSA encryption and decryption verified.")
