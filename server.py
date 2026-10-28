"""
Server Application for Secure Message Exchange
==============================================
Author: Raghav Gupta
Roll Number: 44275
Assignment: Assignment 1 - Secure Client-Server Message Exchange
Course: Cryptography & Information Security | MNNIT Allahabad

Algorithms Assigned (Roll Number: 44275):
- Symmetric Key Algorithm (RollNo % 3 = 1): Simplified AES (S-AES / AES Variant)
- Asymmetric Key Algorithm (RollNo % 2 = 1): ElGamal Cryptosystem & Digital Signatures
- Hashing Algorithm: Whirlpool (ISO/IEC 10118-3, created from scratch)

Server Workflow (Matching Assignment 1 Specifications):
1. Generates or prompts for Server ElGamal keypair (Public and Private key parameters).
2. Listens for client connection on specified port.
3. Responds to client's request for Server Public Key (p_s, g_s, y_s).
4. Receives message bundle:
   - Ciphertext (encrypted with S-AES)
   - Encrypted Secret Key (c1, c2 encrypted with Server's ElGamal Public Key)
   - Client Digital Signature (r, s over Whirlpool hash with Client's ElGamal Private Key)
   - Client ElGamal Public Key (p_c, g_c, y_c)
5. Decrypts Secret Key using Server's ElGamal Private Key:
   s = c1^x mod p -> m = (c2 * s^(-1)) mod p.
6. Decrypts Ciphertext using S-AES with decrypted 16-bit secret key.
7. Computes Whirlpool hash of decrypted message.
8. Verifies Client Digital Signature using Client's ElGamal Public Key.
9. Displays outputs according to the exact required assignment format.
"""

import socket
import argparse
import sys

from algorithms.saes import (
    decrypt_message as saes_decrypt_message,
    format_decryption_trace as format_saes_decryption_trace
)
from algorithms.elgamal import (
    DEFAULT_ELGAMAL_PRIME,
    DEFAULT_ELGAMAL_GENERATOR,
    generate_keypair,
    decrypt_elgamal,
    verify_digest_signature
)
from algorithms.whirlpool import whirlpool_hash
from network.protocol import MessageProtocol, send_json, recv_json


def get_interactive_server_inputs():
    """Prompts the user for Server ElGamal key parameters interactively."""
    print("\n" + "=" * 65)
    print("  INTERACTIVE SERVER KEY CONFIGURATION (Raghav Gupta - 44275)")
    print("=" * 65)
    print("\nEnter Server Key Generation Parameters (ElGamal):")
    print("  (Press ENTER to use standard 512-bit safe prime & generator g=2)")
    p_in = input("  Enter Prime p (or press ENTER for default): ").strip()
    g_in = input("  Enter Generator g (or press ENTER for 2): ").strip()
    x_in = input("  Enter Private Exponent x (or press ENTER for random): ").strip()

    custom_p = int(p_in) if p_in.isdigit() else None
    custom_g = int(g_in) if g_in.isdigit() else None
    custom_x = int(x_in) if x_in.isdigit() else None

    if custom_p:
        print(f"  -> Using custom ElGamal parameters: p={custom_p}, g={custom_g or 2}")
    else:
        print(f"  -> Using default verified 512-bit safe prime & generator g=2")

    print("=" * 65)
    return custom_p, custom_g, custom_x


def run_server(host="127.0.0.1", port=12345, custom_p=None, custom_g=None, custom_x=None, interactive=False):
    """
    Runs the secure message exchange server.
    """
    print("=" * 75)
    print("SECURE MESSAGE EXCHANGE SERVER")
    print("Author: Raghav Gupta | Roll Number: 44275 | MNNIT Allahabad")
    print("Algorithms: S-AES (Symmetric) | ElGamal (Asymmetric) | Whirlpool (Hash)")
    print("=" * 75)

    # 1. Server Key Generation (ElGamal: p, g, y) and (p, g, x)
    if interactive:
        custom_p, custom_g, custom_x = get_interactive_server_inputs()

    print("\n[+] Generating Server ElGamal key parameters (512-bit prime)...")
    pub_key, priv_key = generate_keypair(p=custom_p, g=custom_g, x=custom_x)
    server_p, server_g, server_y = pub_key
    _, _, server_x = priv_key

    # Display Server Initial Parameters in required format
    print("\nServer Side:")
    print(f"Input: Public Key parameters: (p={server_p}, g={server_g}, y={server_y})")
    print(f"       Private key parameters: (p={server_p}, g={server_g}, x={server_x})")

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
            req_json = recv_json(conn)
            if not req_json:
                print("[-] No request received from client.")
                return

            if req_json.get("type") == MessageProtocol.REQ_PUBLIC_KEY:
                print("[*] Received request for Server Public Key from Client.")
                # Send Server Public Key using protocol module
                resp = MessageProtocol.response_server_key(pub_key)
                send_json(conn, resp)
                print("[*] Sent Server Public Key to Client.")
            else:
                print(f"[-] Unexpected message: {req_json}")
                return

            # Step 2: Receive Payload from Client
            payload = recv_json(conn)
            if not payload:
                print("[-] No payload received.")
                return

            print("[+] Received secure bundle from Client.")

            ciphertext = payload["ciphertext"]
            raw_enc_key = payload["encrypted_secret_key"]
            if isinstance(raw_enc_key, list):
                enc_secret_key = (int(raw_enc_key[0]), int(raw_enc_key[1]))
            else:
                enc_secret_key = int(raw_enc_key)

            raw_sig = payload["client_signature"]
            if isinstance(raw_sig, list):
                client_signature = (int(raw_sig[0]), int(raw_sig[1]))
            else:
                client_signature = int(raw_sig)

            raw_pub = payload["client_public_key"]
            if isinstance(raw_pub, list):
                client_pub_key = tuple(int(x) for x in raw_pub)
            elif isinstance(raw_pub, dict):
                client_pub_key = MessageProtocol.parse_public_key(raw_pub)
            else:
                client_pub_key = raw_pub

            # ----------------------------------------------------------------
            # SERVER-SIDE COMPUTATIONS
            # (Refer to Page 2: Server side Computation)
            # ----------------------------------------------------------------
            # Step 1: Decrypt secret key using asymmetric key decryption process (ElGamal)
            #         s = c1^x mod p, key = (c2 * s^(-1)) mod p
            decrypted_key_int = decrypt_elgamal(enc_secret_key, priv_key)
            secret_key_bin = bin(decrypted_key_int)[2:].zfill(16)

            # Step 2: Decrypt ciphertext using symmetric key decryption process (S-AES)
            #         Input: Ciphertext & Decrypted Secret Key -> Output: Message
            decrypted_message, dec_traces = saes_decrypt_message(ciphertext, decrypted_key_int)

            # Step 3: Compute hash of message using Whirlpool algorithm from scratch
            computed_hash_hex = whirlpool_hash(decrypted_message)

            # Step 4: Verify digital signature using client public key (ElGamal)
            #         v1 = g^h mod p, v2 = (y^r * r^s) mod p
            is_valid, v1, v2 = verify_digest_signature(
                computed_hash_hex, client_signature, client_pub_key
            )

            sig_status = "valid" if is_valid else "invalid"
            msg_status = "Accepted" if is_valid else "Rejected"

            # ----------------------------------------------------------------
            # DISPLAY OUTPUT (Strictly matches format on Page 3)
            # ----------------------------------------------------------------
            print("\n" + "=" * 75)
            print("REQUIRED ASSIGNMENT OUTPUT (SERVER SIDE)")
            print("Author: Raghav Gupta | Roll No: 44275")
            print("=" * 75)
            print("Server Side:")
            print(f"Input: Public Key parameters: (p={server_p}, g={server_g}, y={server_y})")
            print(f"       Private key parameters: (p={server_p}, g={server_g}, x={server_x})")
            print(f"Decrypted Secret key: {secret_key_bin} (integer: {decrypted_key_int})")
            print(f"\nIntermediate decryption process:")
            print(format_saes_decryption_trace(dec_traces, decrypted_key_int, max_blocks_to_show=3))
            print(f"\nDecrypt Message: {decrypted_message}")
            print(f"Hash code: {computed_hash_hex}")
            print(f"Verification code: {computed_hash_hex if is_valid else hex(v2)[2:]}")
            print(f"Signature: <{sig_status}>")
            print(f"Message: <{msg_status}>")
            print("=" * 75)

            # Step 7: Send confirmation ACK to Client
            ack_msg = MessageProtocol.ack(msg_status, sig_status, decrypted_message)
            send_json(conn, ack_msg)

    finally:
        server_sock.close()
        print("\n[*] Server socket closed.")


def main():
    parser = argparse.ArgumentParser(description="Secure Message Exchange Server (Raghav Gupta - 44275)")
    parser.add_argument("--host", default="127.0.0.1", help="Server host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=12345, help="Server port (default: 12345)")
    parser.add_argument("--p", type=int, default=None, help="Optional prime p for Server ElGamal")
    parser.add_argument("--g", type=int, default=None, help="Optional generator g for Server ElGamal")
    parser.add_argument("--x", type=int, default=None, help="Optional private exponent x for Server ElGamal")
    parser.add_argument("--interactive", action="store_true", help="Prompt interactively for key parameters")
    args = parser.parse_args()

    run_server(
        host=args.host,
        port=args.port,
        custom_p=args.p,
        custom_g=args.g,
        custom_x=args.x,
        interactive=args.interactive
    )


if __name__ == "__main__":
    main()
