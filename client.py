"""
Client Application for Secure Message Exchange
==============================================
Author: Raghav Gupta
Roll Number: 44275
Assignment: Assignment 1 - Secure Client-Server Message Exchange
Course: Cryptography & Information Security | MNNIT Allahabad

Algorithms Assigned (Roll Number: 44275):
- Symmetric Key Algorithm (RollNo % 3 = 1): Simplified AES (S-AES / AES Variant)
- Asymmetric Key Algorithm (RollNo % 2 = 1): ElGamal Cryptosystem & Digital Signatures
- Hashing Algorithm: Whirlpool (ISO/IEC 10118-3, created from scratch)

Client Workflow (Matching Assignment 1 Specifications):
1. Accepts/prompts for:
   - Message
   - Secret Key (16-bit binary string for S-AES)
   - Client Key Parameters (ElGamal prime p, generator g, private exponent x)
2. Connects to Server and requests Server's ElGamal Public Key (p_s, g_s, y_s).
3. Encrypts Secret Key using Server's ElGamal Public Key: (c1, c2).
4. Encrypts Message using S-AES and records intermediate encryption process.
5. Computes Whirlpool Hash of original message (512 bits / 128 hex chars).
6. Computes Digital Signature over the Whirlpool hash using Client's ElGamal Private Key: (r, s).
7. Displays outputs according to the exact required assignment format.
8. Sends message bundle to Server:
   - Ciphertext
   - Encrypted Secret Key
   - Client Digital Signature
   - Client ElGamal Public Key
9. Awaits server acknowledgment.
"""

import socket
import argparse
import sys

from algorithms.saes import (
    encrypt_message as saes_encrypt_message,
    format_encryption_trace as format_saes_encryption_trace
)
from algorithms.elgamal import (
    DEFAULT_ELGAMAL_PRIME,
    DEFAULT_ELGAMAL_GENERATOR,
    generate_keypair,
    encrypt_elgamal,
    sign_digest
)
from algorithms.whirlpool import whirlpool_hash
from network.protocol import MessageProtocol, send_json, recv_json


def get_interactive_inputs():
    """Prompts the user interactively with friendly defaults and validation."""
    print("\n" + "=" * 65)
    print("  INTERACTIVE CLIENT INPUT CONFIGURATION (Raghav Gupta - 44275)")
    print("=" * 65)

    # 1. Message Input
    default_msg = "CONFIDENTIAL CRYPTO MESSAGE 2026 - RAGHAV GUPTA (44275)"
    print(f"\n[1] Enter the Message to send securely:")
    print(f"    (Press ENTER to use default: '{default_msg}')")
    user_msg = input("    > ").strip()
    message = user_msg if user_msg else default_msg
    print(f"    -> Selected Message: '{message}'")

    # 2. Secret Key Input (16-bit binary string for S-AES)
    default_key = "1010000010110001"
    print(f"\n[2] Enter 16-bit binary Secret Key for S-AES (AES Variant):")
    print(f"    (Press ENTER to use default: '{default_key}' = 0x{int(default_key, 2):04X})")
    while True:
        user_key = input("    > ").strip()
        if not user_key:
            secret_key = default_key
            break
        elif len(user_key) == 16 and all(c in "01" for c in user_key):
            secret_key = user_key
            break
        else:
            print("    [!] Error: Secret Key must be exactly 16 binary digits (0 or 1).")
            print(f"        Example: {default_key}. Please try again:")

    print(f"    -> Selected Secret Key: {secret_key} (hex: 0x{int(secret_key, 2):04X}, int: {int(secret_key, 2)})")

    # 3. Public and Private Key Parameters (ElGamal)
    print(f"\n[3] Enter Client Key Generation Parameters (ElGamal):")
    print(f"    (Press ENTER to use standard 512-bit safe prime & generator g=2)")
    p_in = input("    Enter Prime p (or press ENTER for default): ").strip()
    g_in = input("    Enter Generator g (or press ENTER for 2): ").strip()
    x_in = input("    Enter Private Exponent x (or press ENTER for random): ").strip()

    custom_p = int(p_in) if p_in.isdigit() else None
    custom_g = int(g_in) if g_in.isdigit() else None
    custom_x = int(x_in) if x_in.isdigit() else None

    if custom_p:
        print(f"    -> Using custom ElGamal parameters: p={custom_p}, g={custom_g or 2}")
    else:
        print(f"    -> Using default verified 512-bit safe prime & generator g=2")

    print("=" * 65)
    return message, secret_key, custom_p, custom_g, custom_x


def run_client(
    host="127.0.0.1",
    port=12345,
    message=None,
    secret_key=None,
    custom_p=None,
    custom_g=None,
    custom_x=None,
    interactive=False
):
    """
    Runs the secure message exchange client.
    """
    print("=" * 75)
    print("SECURE MESSAGE EXCHANGE CLIENT")
    print("Author: Raghav Gupta | Roll Number: 44275 | MNNIT Allahabad")
    print("Algorithms: S-AES (Symmetric) | ElGamal (Asymmetric) | Whirlpool (Hash)")
    print("=" * 75)

    # 1. Gather Inputs
    if interactive:
        message, secret_key, custom_p, custom_g, custom_x = get_interactive_inputs()
    else:
        if not message:
            message = "CONFIDENTIAL CRYPTO MESSAGE 2026 - RAGHAV GUPTA (44275)"
        if not secret_key:
            secret_key = "1010000010110001"

    # Validate secret key format (16-bit binary for S-AES)
    if len(secret_key) != 16 or not all(c in "01" for c in secret_key):
        raise ValueError(f"Secret Key must be a 16-bit binary string (e.g. '1010000010110001'), got '{secret_key}'")

    secret_key_int = int(secret_key, 2)

    # 2. Client Key Generation (ElGamal: p, g, y) and (p, g, x)
    # (Refer to Page 1: Client side computation -> Generate client public and client private key)
    print("\n[+] Generating Client ElGamal key parameters (512-bit prime)...")
    pub_key, priv_key = generate_keypair(p=custom_p, g=custom_g, x=custom_x)
    client_p, client_g, client_y = pub_key
    _, _, client_x = priv_key

    # 3. Connect to Server
    print(f"\n[*] Connecting to Server at {host}:{port}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        try:
            sock.connect((host, port))
        except ConnectionRefusedError:
            print(f"\n[-] ERROR: Could not connect to Server at {host}:{port}!")
            print("    Please ensure the Server is running first by executing:")
            print(f"    py server.py --port {port}")
            return False

        print("[+] Connected to Server successfully.")

        # --------------------------------------------------------------------
        # MESSAGE FLOW STEP 1: Client requests public key of the server
        # (Refer to Page 1: Message Flow -> Bullet 1)
        # --------------------------------------------------------------------
        req = MessageProtocol.request_server_key()
        send_json(sock, req)
        print("[*] Sent request for Server Public Key.")

        # --------------------------------------------------------------------
        # MESSAGE FLOW STEP 2: Server sends the public key
        # (Refer to Page 1: Message Flow -> Bullet 2)
        # --------------------------------------------------------------------
        resp_json = recv_json(sock)
        server_pub_key = MessageProtocol.parse_public_key(resp_json)
        print(f"[+] Received Server Public Key: (p={server_pub_key[0]}, g={server_pub_key[1]}, y={server_pub_key[2]})")

        # --------------------------------------------------------------------
        # CLIENT-SIDE COMPUTATIONS
        # (Refer to Page 1 & Page 2: Client side computation)
        # --------------------------------------------------------------------
        # A. Encrypt Secret Key with ElGamal using Server Public Key:
        #    c1 = g^k mod p, c2 = (Secret_Key * y^k) mod p
        encrypted_secret_key = encrypt_elgamal(secret_key_int, server_pub_key)

        # B. Encrypt Message through assigned symmetric key algorithm (Part 1: S-AES):
        #    Input: Message and Secret Key -> Output: Ciphertext
        ciphertext_hex, enc_traces = saes_encrypt_message(message, secret_key_int)

        # C. Compute hash of message using Whirlpool algorithm from scratch:
        #    Output: 512-bit Message Digest
        hash_code_hex = whirlpool_hash(message)

        # D. Compute digital signature over computed hash using asymmetric key algorithm (Part 2: ElGamal):
        #    r = g^k mod p, s = (h - x*r)*k^(-1) mod (p-1)
        digital_signature = sign_digest(hash_code_hex, priv_key)

        # --------------------------------------------------------------------
        # DISPLAY OUTPUT (Strictly matches format on Page 2 and Page 3)
        # --------------------------------------------------------------------
        print("\n" + "=" * 75)
        print("REQUIRED ASSIGNMENT OUTPUT (CLIENT SIDE)")
        print("Author: Raghav Gupta | Roll No: 44275")
        print("=" * 75)
        print("Client Side:")
        print(f"Input: Message: <{message}>")
        print(f"Secret Key: <{secret_key}>")
        print(f"Public Key parameters: (p={client_p}, g={client_g}, y={client_y})")
        print(f"Private key parameters: (p={client_p}, g={client_g}, x={client_x})")
        print(f"Encrypted Secret Key: <{encrypted_secret_key}>")
        print(f"\nIntermediate encryption process:")
        print(format_saes_encryption_trace(enc_traces, secret_key_int, max_blocks_to_show=3))
        print(f"\nCipher text: <{ciphertext_hex}>")
        print(f"Hash code: <{hash_code_hex}>")
        print(f"Digital Signature: <{digital_signature}>")
        print("=" * 75)

        # --------------------------------------------------------------------
        # MESSAGE FLOW STEP 3: Client sends Ciphertext + Encrypted Secret Key
        #                      + Client Signature + Client Public Key
        # (Refer to Page 1: Message Flow -> Bullet 3)
        # --------------------------------------------------------------------
        payload = MessageProtocol.payload(
            ciphertext_hex,
            encrypted_secret_key,
            digital_signature,
            pub_key
        )
        send_json(sock, payload)
        print("\n[+] Sent payload bundle to Server.")

        # --------------------------------------------------------------------
        # MESSAGE FLOW STEP 4: Await Server Acknowledgment
        # --------------------------------------------------------------------
        ack_json = recv_json(sock)
        print(f"[+] Server Response received:")
        print(f"    Status:    {ack_json.get('status')}")
        print(f"    Signature: {ack_json.get('signature')}")
        print(f"    Message:   '{ack_json.get('received_message')}'")
        return True

    finally:
        sock.close()
        print("[*] Connection closed.")


def main():
    parser = argparse.ArgumentParser(description="Secure Message Exchange Client (Raghav Gupta - 44275)")
    parser.add_argument("--host", default="127.0.0.1", help="Server host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=12345, help="Server port (default: 12345)")
    parser.add_argument("--message", default=None, help="Message to encrypt and send")
    parser.add_argument("--key", default=None, help="16-bit binary secret key (e.g. 1010000010110001)")
    parser.add_argument("--p", type=int, default=None, help="Optional prime p for Client ElGamal")
    parser.add_argument("--g", type=int, default=None, help="Optional generator g for Client ElGamal")
    parser.add_argument("--x", type=int, default=None, help="Optional private exponent x for Client ElGamal")
    parser.add_argument("--interactive", action="store_true", help="Prompt interactively for inputs")
    args = parser.parse_args()

    run_client(
        host=args.host,
        port=args.port,
        message=args.message,
        secret_key=args.key,
        custom_p=args.p,
        custom_g=args.g,
        custom_x=args.x,
        interactive=args.interactive
    )


if __name__ == "__main__":
    main()
