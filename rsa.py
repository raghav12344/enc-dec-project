"""
RSA Asymmetric Cryptosystem Implementation
==========================================
Author: Raghav Gupta
Roll Number: 20243226
Assignment: Assignment 1 - Secure Client-Server Message Exchange

This module re-exports the modular RSA cryptosystem implementation from the
'algorithms' package (algorithms/rsa.py) for top-level accessibility.
"""

from algorithms.rsa import (
    extended_gcd,
    mod_inverse,
    is_prime,
    generate_prime,
    generate_keypair_from_primes,
    generate_rsa_keys,
    encrypt_rsa,
    decrypt_rsa,
    sign_digest,
    verify_digest_signature
)

if __name__ == "__main__":
    print("=== RSA Module Verification (Author: Raghav Gupta, Roll No: 20243226) ===")
    pub, priv, params = generate_rsa_keys(bits=280)
    print(f"Generated modulus n ({params['n'].bit_length()} bits)")
    val = 642
    enc = encrypt_rsa(val, pub)
    dec = decrypt_rsa(enc, priv)
    assert val == dec
    print(f"Original:  {val}")
    print(f"Encrypted: {enc}")
    print(f"Decrypted: {dec}")
    print("\nVerification: SUCCESS!")
