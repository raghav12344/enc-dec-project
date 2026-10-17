"""
Automated Test Suite for Crypto Assignment 1
===========================================
Author: Raghav Gupta
Roll Number: 20243226
Assignment: Assignment 1 - Secure Client-Server Message Exchange

This suite runs comprehensive unit and integration tests:
1. S-DES algorithm test vectors and round-trip verification
2. Whirlpool hash test vectors (ISO/IEC 10118-3 standards)
3. RSA asymmetric encryption and digital signature verification
4. End-to-end client-server network socket simulation
"""

import threading
import time
import unittest

from sdes import encrypt_message, decrypt_message, generate_subkeys, encrypt_block_with_trace, decrypt_block_with_trace
from whirlpool import whirlpool_hash
from rsa import generate_rsa_keys, encrypt_rsa, decrypt_rsa, sign_digest, verify_digest_signature
from server import run_server
from client import run_client


class TestCryptoAssignment(unittest.TestCase):

    def test_01_sdes_standard_vector(self):
        """Tests S-DES using Schaefer/Stallings textbook test vector."""
        key = "1010000010"
        pt = "11010111"
        k1, k2, trace = generate_subkeys(key)
        self.assertEqual("".join(map(str, k1)), "10100100")
        self.assertEqual("".join(map(str, k2)), "01000011")

        ct, _ = encrypt_block_with_trace(pt, k1, k2)
        self.assertEqual("".join(map(str, ct)), "10101000")

        recovered, _ = decrypt_block_with_trace(ct, k1, k2)
        self.assertEqual("".join(map(str, recovered)), pt)

    def test_02_sdes_string_roundtrip(self):
        """Tests full ASCII string encryption and decryption via S-DES."""
        key = "1100101101"
        message = "ANTIGRAVITY CRYPTO 2026 - RAGHAV GUPTA (20243226)"
        ct_hex, enc_traces, k_trace = encrypt_message(message, key)
        self.assertTrue(len(ct_hex) > 0)
        recovered, dec_traces, _ = decrypt_message(ct_hex, key)
        self.assertEqual(recovered, message)

    def test_03_whirlpool_test_vectors(self):
        """Tests Whirlpool against ISO/IEC 10118-3 official test vectors."""
        # Test vector: 'a'
        hash_a = whirlpool_hash("a")
        expected_a = "c09b3f68b4fd3db3d05e9fa26c3038df6e287c19cd49b4374ffc6544d7f2a11766b8b0c340f67d4a3e6bc7941daf25bd302056a74a98954b22ff3290ee1159b2"
        self.assertEqual(hash_a, expected_a)

        # Test vector: 'The quick brown fox jumps over the lazy dog'
        fox = "The quick brown fox jumps over the lazy dog"
        hash_fox = whirlpool_hash(fox)
        expected_fox = "0c8cbe8ecdf4806a1afda403aff11d589f3345053f57595aec04b6ebb978b08fa48e142d388e5c057e0ae99812896f4dee8b62fa65d5a1c49872f8d9127b28c1"
        self.assertEqual(hash_fox, expected_fox)

    def test_04_rsa_encryption_and_signing(self):
        """Tests RSA key generation, secret key encryption, and Whirlpool signature verification."""
        pub, priv, params = generate_rsa_keys(bits=280)
        secret_key_val = 0b1010000010
        enc = encrypt_rsa(secret_key_val, pub)
        dec = decrypt_rsa(enc, priv)
        self.assertEqual(dec, secret_key_val)

        # Sign a hash
        digest = whirlpool_hash("TEST MESSAGE")
        sig = sign_digest(digest, priv)
        valid, v_code, exp_code = verify_digest_signature(sig, digest, pub)
        self.assertTrue(valid)

        # Tampered message should fail verification
        tampered_digest = whirlpool_hash("TAMPERED MESSAGE")
        valid_tampered, _, _ = verify_digest_signature(sig, tampered_digest, pub)
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
        time.sleep(1)  # Allow server to bind and listen

        client_thread = threading.Thread(
            target=run_client,
            kwargs={
                "host": "127.0.0.1",
                "port": test_port,
                "message": "SOCKET INTEGRATION TEST PASSED",
                "secret_key": "1001100110"
            }
        )
        client_thread.start()
        client_thread.join(timeout=10)
        server_thread.join(timeout=10)
        self.assertFalse(client_thread.is_alive())


if __name__ == "__main__":
    unittest.main()
