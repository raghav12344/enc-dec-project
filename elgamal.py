"""
ElGamal Asymmetric Cryptosystem & Digital Signatures - Re-exporter
==================================================================
Author: Raghav Gupta
Roll Number: 44275
Assignment: Assignment 1 - Secure Client-Server Message Exchange
Course: Cryptography & Information Security | MNNIT Allahabad

This root module re-exports all ElGamal primitives from algorithms/elgamal.py.
"""

from algorithms.elgamal import (
    DEFAULT_ELGAMAL_PRIME,
    DEFAULT_ELGAMAL_GENERATOR,
    extended_gcd,
    mod_inverse,
    is_prime,
    generate_prime,
    generate_keypair,
    encrypt_elgamal,
    decrypt_elgamal,
    sign_digest,
    verify_digest_signature,
)

__all__ = [
    "DEFAULT_ELGAMAL_PRIME",
    "DEFAULT_ELGAMAL_GENERATOR",
    "extended_gcd",
    "mod_inverse",
    "is_prime",
    "generate_prime",
    "generate_keypair",
    "encrypt_elgamal",
    "decrypt_elgamal",
    "sign_digest",
    "verify_digest_signature",
]
