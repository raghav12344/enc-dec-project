"""
Simplified Data Encryption Standard (S-DES) Implementation
==========================================================
Author: Raghav Gupta
Roll Number: 20243226
Assignment: Assignment 1 - Secure Client-Server Message Exchange

This module re-exports the modular S-DES implementation from the
'algorithms' package (algorithms/sdes.py) for top-level accessibility.
"""

from algorithms.sdes import (
    P10,
    P8,
    IP,
    IP_INV,
    EP,
    P4,
    S0,
    S1,
    permute,
    left_shift,
    generate_subkeys,
    encrypt_block_with_trace,
    decrypt_block_with_trace,
    encrypt_message,
    decrypt_message,
    format_encryption_trace,
    format_decryption_trace
)

if __name__ == "__main__":
    print("=== S-DES Module Verification (Author: Raghav Gupta, Roll No: 20243226) ===")
    test_key = "1010000010"
    test_msg = "CRYPTOGRAPHY"
    ct_hex, enc_traces, k_trace = encrypt_message(test_msg, test_key)
    recovered, dec_traces, _ = decrypt_message(ct_hex, test_key)
    assert recovered == test_msg
    print(f"Message:   '{test_msg}'")
    print(f"Key:       {test_key}")
    print(f"Cipher:    {ct_hex}")
    print(f"Recovered: '{recovered}'")
    print("\nVerification: SUCCESS! Decrypted message matches original perfectly.")
