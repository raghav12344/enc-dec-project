"""
Cryptography Algorithms Package
===============================
Author: Raghav Gupta
Roll Number: 20243226
Assignment: Assignment 1 - Secure Client-Server Message Exchange

This package contains modular implementations of:
1. Simplified DES (S-DES) - Symmetric block cipher (Part 1)
2. RSA - Asymmetric cryptosystem & digital signatures (Part 2)
3. Whirlpool - 512-bit cryptographic hash function from scratch
"""

from .sdes import (
    generate_subkeys,
    encrypt_block_with_trace,
    decrypt_block_with_trace,
    encrypt_message,
    decrypt_message,
    format_encryption_trace,
    format_decryption_trace
)

from .rsa import (
    generate_rsa_keys,
    generate_keypair_from_primes,
    encrypt_rsa,
    decrypt_rsa,
    sign_digest,
    verify_digest_signature,
    is_prime,
    generate_prime
)

from .whirlpool import (
    Whirlpool,
    whirlpool_hash
)

__all__ = [
    # S-DES
    "generate_subkeys",
    "encrypt_block_with_trace",
    "decrypt_block_with_trace",
    "encrypt_message",
    "decrypt_message",
    "format_encryption_trace",
    "format_decryption_trace",
    # RSA
    "generate_rsa_keys",
    "generate_keypair_from_primes",
    "encrypt_rsa",
    "decrypt_rsa",
    "sign_digest",
    "verify_digest_signature",
    "is_prime",
    "generate_prime",
    # Whirlpool
    "Whirlpool",
    "whirlpool_hash"
]
