"""
Server Application for Secure Message Exchange
==============================================
Author: Raghav Gupta
Roll Number: 20243226
Assignment: Assignment 1 - Secure Client-Server Message Exchange

Algorithms Assigned:
- Symmetric Key Algorithm (RollNo % 3 = 0): Simplified DES (S-DES)
- Asymmetric Key Algorithm (RollNo % 2 = 0): RSA
- Hashing Algorithm: Whirlpool (from scratch)

Server Workflow:
1. Generates or accepts Server RSA keypair (Public and Private key parameters).
2. Listens for client connection on specified port.
3. Responds to client's request for Server Public Key.
4. Receives message bundle:
   - Ciphertext (encrypted with S-DES)
   - Encrypted Secret Key (encrypted with Server's RSA Public Key)
   - Client Digital Signature (Whirlpool hash signed with Client's RSA Private Key)
   - Client RSA Public Key
5. Decrypts Secret Key using Server's RSA Private Key.
6. Decrypts Ciphertext using S-DES with decrypted secret key.
7. Computes Whirlpool hash of decrypted message.
8. Verifies Client Digital Signature using Client's RSA Public Key.
9. Displays outputs according to the exact required assignment format.
"""

import socket
import json
import argparse
import sys
from rsa import generate_rsa_keys, generate_keypair_from_primes, decrypt_rsa, verify_digest_signature
from sdes import decrypt_message, format_decryption_trace
from whirlpool import whirlpool_hash


def get_interactive_server_inputs():
    """Prompts the user for Server RSA key parameters interactively."""
    print("\n" + "=" * 60)
    print("  INTERACTIVE SERVER KEY CONFIGURATION")
    print("=" * 60)
    print("\nEnter Server Key Generation Parameters (RSA):")
    print("  (Press ENTER to auto-generate secure 280-bit primes where modulus n > 512 bits)")
    p_in = input("  Enter Prime p (or press ENTER for default): ").strip()
    q_in = input("  Enter Prime q (or press ENTER for default): ").strip()
    e_in = input("  Enter Public Exponent e (or press ENTER for 65537): ").strip()

    custom_p = int(p_in) if p_in.isdigit() else None
    custom_q = int(q_in) if q_in.isdigit() else None
    custom_e = int(e_in) if e_in.isdigit() else 65537

    if custom_p and custom_q:
        print(f"  -> Using custom key parameters: p={custom_p}, q={custom_q}, e={custom_e}")
    else:
        print(f"  -> Using auto-generated key parameters (modulus > 512 bits to accommodate Whirlpool)")

    print("=" * 60)
    return custom_p, custom_q, custom_e


def run_server(host="127.0.0.1", port=12345, auto_keys=True, custom_p=None, custom_q=None, custom_e=65537, interactive=False):
    """
    Runs the secure message exchange server.
    """
    print("=" * 70)
    print("SECURE MESSAGE EXCHANGE SERVER")
    print("Author: Raghav Gupta | Roll Number: 20243226 | MNNIT Allahabad")
    print("Algorithms: S-DES (Symmetric) | RSA (Asymmetric) | Whirlpool (Hash)")
    print("=" * 70)

    # 1. Server Key Generation
    if interactive:
        custom_p, custom_q, custom_e = get_interactive_server_inputs()

    if custom_p and custom_q:
        print(f"\n[+] Using provided primes for Server RSA: p={custom_p}, q={custom_q}, e={custom_e}")
        pub_key, priv_key, params = generate_keypair_from_primes(custom_p, custom_q, custom_e)
    else:
        print("\n[+] Generating Server RSA key parameters (280-bit primes, modulus > 512 bits)...")
        pub_key, priv_key, params = generate_rsa_keys(bits=280, e=custom_e)

    server_e, server_n = pub_key
    server_d, _ = priv_key

    # Display Server Initial Parameters in required format
    print("\nServer Side:")
    print(f"Input: Public Key parameters: (e={server_e}, n={server_n})")
    print(f"       Private key parameters: (d={server_d}, n={server_n})")

    # 2. Setup TCP Socket Server
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_sock.bind((host, port))
        server_sock.listen(1)
        print(f"\n[*] Server listening on {host}:{port}...")
        print("[*] Waiting for Client connection...")

        conn, addr = server_sock.accept()
        print(f"[+] Client connected from {addr[0]}:{addr[1]}")

        with conn:
            # 3. Message Flow Handling
            # Step 1: Wait for client's public key request
            raw_req = conn.recv(4096).decode("utf-8")
            if not raw_req:
                print("[-] No request received from client.")
                return

            req_json = json.loads(raw_req)
            if req_json.get("type") == "REQUEST_SERVER_PUBLIC_KEY":
                print("[*] Received request for Server Public Key from Client.")
                # Send Server Public Key
                resp = json.dumps({
                    "type": "SERVER_PUBLIC_KEY",
                    "e": server_e,
                    "n": server_n
                })
                conn.sendall(resp.encode("utf-8"))
                print("[*] Sent Server Public Key to Client.")
            else:
                print(f"[-] Unexpected message: {raw_req}")
                return

            # Step 2: Receive Payload from Client
            payload_data = ""
            while True:
                chunk = conn.recv(8192).decode("utf-8")
                if not chunk:
                    break
                payload_data += chunk
                # Check for end of JSON payload
                try:
                    payload = json.loads(payload_data)
                    break
                except json.JSONDecodeError:
                    continue

            print("[+] Received secure bundle from Client.")

            ciphertext = payload["ciphertext"]
            enc_secret_key = int(payload["encrypted_secret_key"])
            client_signature = int(payload["client_signature"])
            client_pub_key = (int(payload["client_public_key"]["e"]), int(payload["client_public_key"]["n"]))

            # Step 3: Decrypt Secret Key using Server's RSA Private Key
            decrypted_key_int = decrypt_rsa(enc_secret_key, priv_key)
            # S-DES secret key is a 10-bit binary string
            secret_key_bin = bin(decrypted_key_int)[2:].zfill(10)

            # Step 4: Decrypt Ciphertext using S-DES
            decrypted_message, dec_traces, k_trace = decrypt_message(ciphertext, secret_key_bin)

            # Step 5: Compute Whirlpool Hash of Decrypted Message
            computed_hash_hex = whirlpool_hash(decrypted_message)
            computed_hash_int = int(computed_hash_hex, 16)

            # Step 6: Verify Client Digital Signature using Client's RSA Public Key
            is_valid, verification_code, expected_code = verify_digest_signature(
                client_signature, computed_hash_hex, client_pub_key
            )

            sig_status = "valid" if is_valid else "invalid"
            msg_status = "Accepted" if is_valid else "Rejected"

            # 4. Display Outputs strictly according to the format required by assignment
            print("\n" + "=" * 70)
            print("REQUIRED ASSIGNMENT OUTPUT (SERVER SIDE)")
            print("Author: Raghav Gupta | Roll No: 20243226")
            print("=" * 70)
            print("Server Side:")
            print(f"Input: Public Key parameters: (e={server_e}, n={server_n})")
            print(f"       Private key parameters: (d={server_d}, n={server_n})")
            print(f"Decrypted Secret key: {secret_key_bin} (integer: {decrypted_key_int})")
            print(f"\nIntermediate decryption process:")
            print(format_decryption_trace(dec_traces, k_trace, max_blocks=3))
            print(f"\nDecrypt Message: {decrypted_message}")
            print(f"Hash code: {computed_hash_hex}")
            print(f"Verification code: {hex(verification_code)[2:].zfill(128)}")
            print(f"Signature: <{sig_status}>")
            print(f"Message: <{msg_status}>")
            print("=" * 70)

            # Step 7: Send confirmation to Client
            ack_msg = json.dumps({
                "type": "ACK",
                "status": msg_status,
                "signature": sig_status,
                "received_message": decrypted_message
            })
            conn.sendall(ack_msg.encode("utf-8"))

    finally:
        server_sock.close()
        print("\n[*] Server socket closed.")


def main():
    parser = argparse.ArgumentParser(description="Secure Message Exchange Server (Raghav Gupta - 20243226)")
    parser.add_argument("--host", default="127.0.0.1", help="Server host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=12345, help="Server port (default: 12345)")
    parser.add_argument("--p", type=int, default=None, help="Optional prime p for Server RSA")
    parser.add_argument("--q", type=int, default=None, help="Optional prime q for Server RSA")
    parser.add_argument("--e", type=int, default=65537, help="Public exponent e (default: 65537)")
    parser.add_argument("--interactive", action="store_true", help="Prompt interactively for key parameters")
    args = parser.parse_args()

    run_server(host=args.host, port=args.port, custom_p=args.p, custom_q=args.q, custom_e=args.e, interactive=args.interactive)


if __name__ == "__main__":
    main()
