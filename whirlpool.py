"""
Whirlpool Cryptographic Hash Function (Scratch Implementation)
=============================================================
Author: Raghav Gupta
Roll Number: 20243226
Assignment: Assignment 1 - Secure Client-Server Message Exchange

This module re-exports the modular Whirlpool implementation from the
'algorithms' package (algorithms/whirlpool.py) for top-level accessibility.
"""

from algorithms.whirlpool import (
    ROUNDS,
    RC,
    SBOX,
    C_TABLES,
    Whirlpool,
    whirlpool_hash
)

if __name__ == "__main__":
    print("=== Whirlpool Hash Verification (Author: Raghav Gupta, Roll No: 20243226) ===")
    test_msg = "The quick brown fox jumps over the lazy dog"
    h = whirlpool_hash(test_msg)
    expected = "0c8cbe8ecdf4806a1afda403aff11d589f3345053f57595aec04b6ebb978b08fa48e142d388e5c057e0ae99812896f4dee8b62fa65d5a1c49872f8d9127b28c1"
    assert h == expected
    print(f"Message: '{test_msg}'")
    print(f"Hash:    {h}")
    print("\nVerification: SUCCESS! Matches official ISO/IEC 10118-3 test vector.")
