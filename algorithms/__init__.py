"""
Cryptography Algorithms Package
===============================
Author: Raghav Gupta
Roll Number: 44275
Assignment: Assignment 1 - Secure Client-Server Message Exchange
Course: Cryptography & Information Security | MNNIT Allahabad

This package contains modular implementations of:
1. Simplified AES (S-AES) - Symmetric block cipher (Part 1, Roll % 3 = 1)
2. ElGamal - Asymmetric cryptosystem & digital signatures (Part 2, Roll % 2 = 1)
3. Whirlpool - 512-bit cryptographic hash function from scratch (ISO/IEC 10118-3)
"""

# Part 1 Symmetric: Simplified AES (S-AES) for Roll % 3 = 1
from .saes import (
    generate_subkeys as generate_saes_subkeys,
    encrypt_block_with_trace as saes_encrypt_block_with_trace,
    decrypt_block_with_trace as saes_decrypt_block_with_trace,
    encrypt_block as saes_encrypt_block,
    decrypt_block as saes_decrypt_block,
    encrypt_message as saes_encrypt_message,
    decrypt_message as saes_decrypt_message,
    format_encryption_trace as format_saes_encryption_trace,
    format_decryption_trace as format_saes_decryption_trace,
)

# Part 2 Asymmetric: ElGamal for Roll % 2 = 1
from .elgamal import (
    DEFAULT_ELGAMAL_PRIME,
    DEFAULT_ELGAMAL_GENERATOR,
    generate_keypair as generate_elgamal_keypair,
    encrypt_elgamal,
    decrypt_elgamal,
    sign_digest as elgamal_sign_digest,
    verify_digest_signature as elgamal_verify_digest_signature,
    is_prime,
    generate_prime,
    extended_gcd,
    mod_inverse,
)

# Part 3 Hash: Whirlpool from scratch
from .whirlpool import (
    Whirlpool,
    whirlpool_hash,
)

__all__ = [
    # S-AES
    "generate_saes_subkeys",
    "saes_encrypt_block_with_trace",
    "saes_decrypt_block_with_trace",
    "saes_encrypt_block",
    "saes_decrypt_block",
    "saes_encrypt_message",
    "saes_decrypt_message",
    "format_saes_encryption_trace",
    "format_saes_decryption_trace",
    # ElGamal
    "DEFAULT_ELGAMAL_PRIME",
    "DEFAULT_ELGAMAL_GENERATOR",
    "generate_elgamal_keypair",
    "encrypt_elgamal",
    "decrypt_elgamal",
    "elgamal_sign_digest",
    "elgamal_verify_digest_signature",
    "is_prime",
    "generate_prime",
    "extended_gcd",
    "mod_inverse",
    # Whirlpool
    "Whirlpool",
    "whirlpool_hash",
]
