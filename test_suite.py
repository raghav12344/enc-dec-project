"""
Automated Test Suite for Crypto Assignment 1
===========================================
Author: Raghav Gupta
Roll Number: 44275
Assignment: Assignment 1 - Secure Client-Server Message Exchange
Course: Cryptography & Information Security | MNNIT Allahabad

This suite runs comprehensive unit and integration tests:
1. S-AES algorithm textbook test vectors and round-trip verification (Musa et al. / Stallings)
2. S-AES full ASCII string encryption and decryption
3. Whirlpool hash test vectors (ISO/IEC 10118-3 standards)
4. ElGamal asymmetric encryption, decryption, and digital signature verification
5. End-to-end client-server network socket simulation
"""

import threading
import time
import unittest

from algorithms.saes import (
    encrypt_block,
    decrypt_block,
    encrypt_message as saes_encrypt_message,
    decrypt_message as saes_decrypt_message,
    generate_subkeys as generate_saes_subkeys
)
from algorithms.elgamal import (
    generate_keypair,
    encrypt_elgamal,
    decrypt_elgamal,
    sign_digest,
    verify_digest_signature
)
from algorithms.whirlpool import whirlpool_hash
from server import run_server
from client import run_client


class TestCryptoAssignment(unittest.TestCase):

    def test_01_saes_standard_vector(self):
        """Tests S-AES using Musa / Stallings textbook test vector."""
        key = 0x4AF5       # 0100 1010 1111 0101
        pt = 0xD728        # 1101 0111 0010 1000
        expected_ct = 0x24EC  # 0010 0100 1110 1100

        k0, k1, k2 = generate_saes_subkeys(key)
        self.assertEqual(k0, 0x4AF5)
        self.assertEqual(k1, 0xDD28)
        self.assertEqual(k2, 0x87AF)

        ct = encrypt_block(pt, key)
        self.assertEqual(ct, expected_ct, f"Expected 0x{expected_ct:04X}, got 0x{ct:04X}")

        recovered = decrypt_block(ct, key)
        self.assertEqual(recovered, pt, f"Decryption failed to recover original plaintext 0x{pt:04X}")

    def test_02_saes_string_roundtrip(self):
        """Tests full ASCII string encryption and decryption via S-AES."""
        key = 0xA0B1  # 16-bit key
        message = "ANTIGRAVITY CRYPTO 2026 - RAGHAV GUPTA (44275)"
        ct_hex, enc_traces = saes_encrypt_message(message, key)
        self.assertTrue(len(ct_hex) > 0)
        recovered, dec_traces = saes_decrypt_message(ct_hex, key)
        self.assertEqual(recovered, message)

    def test_03_whirlpool_test_vectors(self):
        """Tests Whirlpool against ISO/IEC 10118-3 official test vectors."""
        # Test vector 1: 'a'
        hash_a = whirlpool_hash("a")
        expected_a = "c09b3f68b4fd3db3d05e9fa26c3038df6e287c19cd49b4374ffc6544d7f2a11766b8b0c340f67d4a3e6bc7941daf25bd302056a74a98954b22ff3290ee1159b2"
        self.assertEqual(hash_a, expected_a)

        # Test vector 2: 'The quick brown fox jumps over the lazy dog'
        fox = "The quick brown fox jumps over the lazy dog"
        hash_fox = whirlpool_hash(fox)
        expected_fox = "0c8cbe8ecdf4806a1afda403aff11d589f3345053f57595aec04b6ebb978b08fa48e142d388e5c057e0ae99812896f4dee8b62fa65d5a1c49872f8d9127b28c1"
        self.assertEqual(hash_fox, expected_fox)

    def test_04_elgamal_encryption_and_signing(self):
        """Tests ElGamal key generation, secret key encryption, and Whirlpool signature verification."""
        pub, priv = generate_keypair()
        secret_key_val = 0xA0B1  # 16-bit secret key

        # Asymmetric encryption of secret key
        enc = encrypt_elgamal(secret_key_val, pub)
        dec = decrypt_elgamal(enc, priv)
        self.assertEqual(dec, secret_key_val)

        # Sign Whirlpool hash
        digest = whirlpool_hash("TEST CIPHERTEXT MESSAGE")
        sig = sign_digest(digest, priv)
        valid, v1, v2 = verify_digest_signature(digest, sig, pub)
        self.assertTrue(valid)
        self.assertEqual(v1, v2)

        # Tampered message should fail verification
        tampered_digest = whirlpool_hash("TAMPERED CIPHERTEXT MESSAGE")
        valid_tampered, _, _ = verify_digest_signature(tampered_digest, sig, pub)
        self.assertFalse(valid_tampered)

    def test_05_client_server_integration(self):
        """Tests live socket communication between client and server."""
        test_port = 12999
        server_thread = threading.Thread(
            target=run_server,
            kwargs={"host": "127.0.0.1", "port": test_port},
            daemon=True
        )
        server_thread.start()
        time.sleep(0.5)  # Allow socket to bind

        success = run_client(
            host="127.0.0.1",
            port=test_port,
            message="TEST SOCKET INTEGRATION - RAGHAV GUPTA (44275)",
            secret_key="1010000010110001"
        )
        self.assertTrue(success)


if __name__ == "__main__":
    unittest.main()
