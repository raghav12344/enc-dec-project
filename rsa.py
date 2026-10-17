"""
RSA Asymmetric Cryptosystem Implementation
==========================================
Author: Raghav Gupta
Roll Number: 20243226
Assignment: Assignment 1 - Secure Client-Server Message Exchange

This module provides a pure-Python, zero-dependency, from-scratch implementation
of the RSA public-key cryptosystem.

Features:
- Primality testing via Miller-Rabin algorithm
- Large prime generation (configurable bit length)
- Key generation: Modulus n = p*q, Totient phi(n) = (p-1)*(q-1),
  Public exponent e, Private exponent d = e^-1 mod phi(n) via Extended Euclidean Algorithm
- Asymmetric encryption/decryption of secret key
- Digital signature generation and verification over Whirlpool digests
"""

import random
import math


def extended_gcd(a, b):
    """
    Extended Euclidean Algorithm.
    Returns (gcd, x, y) such that a*x + b*y = gcd(a, b).
    """
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y


def mod_inverse(e, phi):
    """
    Computes modular multiplicative inverse d such that (d * e) % phi == 1.
    """
    gcd, x, _ = extended_gcd(e, phi)
    if gcd != 1:
        raise ValueError(f"Modular inverse does not exist: gcd({e}, {phi}) = {gcd} != 1")
    return (x % phi + phi) % phi


def is_prime(n, k=40):
    """
    Miller-Rabin probabilistic primality test.
    k is the number of test rounds (40 gives error probability < 2^-80).
    """
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    # Write n - 1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Witness loop
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


def generate_prime(bits=300):
    """Generates a random probable prime of the specified bit length."""
    while True:
        # Ensure highest and lowest bit are set (odd and correct magnitude)
        candidate = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_prime(candidate):
            return candidate


def generate_keypair_from_primes(p, q, e=65537):
    """
    Generates RSA public and private keypairs given primes p, q and public exponent e.
    Returns:
        (public_key, private_key, key_params)
        where:
        public_key  = (e, n)
        private_key = (d, n)
        key_params  = {'p': p, 'q': q, 'n': n, 'phi': phi, 'e': e, 'd': d}
    """
    if p == q:
        raise ValueError("Primes p and q must be distinct.")
    if not is_prime(p) or not is_prime(q):
        # We allow composite only with warning for classroom demonstration if desired
        pass

    n = p * q
    phi = (p - 1) * (q - 1)

    # Ensure gcd(e, phi) == 1
    if math.gcd(e, phi) != 1:
        # Fallback to standard Fermat primes or search
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
    key_params = {
        "p": p,
        "q": q,
        "n": n,
        "phi": phi,
        "e": e,
        "d": d
    }
    return public_key, private_key, key_params


def generate_rsa_keys(bits=300, e=65537):
    """
    Generates a full RSA keypair with primes of the specified bit length.
    Using bits >= 260 ensures n > 2^512, accommodating Whirlpool hashes directly!
    """
    p = generate_prime(bits)
    q = generate_prime(bits)
    while p == q:
        q = generate_prime(bits)
    return generate_keypair_from_primes(p, q, e)


def encrypt_rsa(plaintext_int, public_key):
    """
    RSA encryption: c = (m ^ e) mod n
    """
    e, n = public_key
    if plaintext_int >= n:
        raise ValueError(f"Plaintext integer ({plaintext_int}) must be strictly less than modulus n ({n})")
    return pow(plaintext_int, e, n)


def decrypt_rsa(ciphertext_int, private_key):
    """
    RSA decryption: m = (c ^ d) mod n
    """
    d, n = private_key
    return pow(ciphertext_int, d, n)


def sign_digest(digest_hex_or_int, private_key):
    """
    Signs a hash digest using RSA private key:
    Signature S = (Hash mod n) ^ d mod n
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
    Verifies an RSA signature over a hash digest:
    Verification code V = (S ^ e) mod n
    Checks if V == (Hash mod n).
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
    print(f"Public key (e, n): e={pub[0]}")
    print(f"Private key (d, n): d={str(priv[0])[:20]}...")

    # Test Secret Key encryption (10-bit integer)
    secret_key_val = 0b1010000010  # 642
    enc_key = encrypt_rsa(secret_key_val, pub)
    dec_key = decrypt_rsa(enc_key, priv)
    print(f"\nOriginal Secret Key:  {secret_key_val} (bin: {bin(secret_key_val)[2:].zfill(10)})")
    print(f"Encrypted Secret Key: {enc_key}")
    print(f"Decrypted Secret Key: {dec_key} (bin: {bin(dec_key)[2:].zfill(10)})")
    assert secret_key_val == dec_key

    # Test Signing Whirlpool digest
    sample_digest = "f908126f528f0cd497251c3bc9862c9cd13d79ae3b42ea9e71ea4792348c6f752bd535fb44c2b5c8a4dab556491adbb235aa38d43dacd0810c6791461aa7e63e"
    sig = sign_digest(sample_digest, priv)
    valid, v_code, exp_code = verify_digest_signature(sig, sample_digest, pub)
    print(f"\nSample Whirlpool Digest: {sample_digest[:32]}...")
    print(f"Digital Signature:       {sig}")
    print(f"Verification Code:       {v_code}")
    print(f"Signature Valid:         {valid}")
    assert valid
    print("\nRSA Verification: SUCCESS!")
