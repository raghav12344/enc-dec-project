"""
Client Application for Secure Message Exchange
==============================================
Author: Raghav Gupta
Roll Number: 20243226
Assignment: Assignment 1 - Secure Client-Server Message Exchange

Algorithms Assigned:
- Symmetric Key Algorithm (RollNo % 3 = 0): Simplified DES (S-DES)
- Asymmetric Key Algorithm (RollNo % 2 = 0): RSA
- Hashing Algorithm: Whirlpool (from scratch)

Client Workflow:
1. Accepts/prompts for:
   - Message
   - Secret Key (10-bit binary string)
   - Client RSA Key Parameters (generates or uses specified primes)
2. Connects to Server and requests Server's RSA Public Key.
3. Encrypts Secret Key using Server's RSA Public Key.
4. Encrypts Message using S-DES and records intermediate encryption process.
5. Computes Whirlpool Hash of original message.
6. Computes Digital Signature over the Whirlpool hash using Client's RSA Private Key.
7. Displays outputs according to the exact required assignment format.
8. Sends message bundle to Server:
   - Ciphertext
   - Encrypted Secret Key
   - Client Digital Signature
   - Client RSA Public Key
9. Awaits server acknowledgment.
"""

import socket
import json
import argparse
import sys
from rsa import generate_rsa_keys, generate_keypair_from_primes, encrypt_rsa, sign_digest
from sdes import encrypt_message, format_encryption_trace
from whirlpool import whirlpool_hash


def get_interactive_inputs():
    """Prompts the user interactively with friendly defaults and validation."""
    print("\n" + "=" * 60)
    print("  INTERACTIVE CLIENT INPUT CONFIGURATION")
    print("=" * 60)

    # 1. Message Input
    default_msg = "CONFIDENTIAL CRYPTO MESSAGE 2026"
    print(f"\n[1] Enter the Message to send securely:")
    print(f"    (Press ENTER to use default: '{default_msg}')")
    user_msg = input("    > ").strip()
    message = user_msg if user_msg else default_msg
    print(f"    -> Selected Message: '{message}'")

    # 2. Secret Key Input
    default_key = "1010000010"
    print(f"\n[2] Enter 10-bit binary Secret Key for S-DES:")
    print(f"    (Press ENTER to use default: '{default_key}')")
    while True:
        user_key = input("    > ").strip()
        if not user_key:
            secret_key = default_key
            break
        elif len(user_key) == 10 and all(c in "01" for c in user_key):
            secret_key = user_key
            break
        else:
            print("    [!] Error: Secret Key must be exactly 10 binary digits (0 or 1).")
            print(f"        Example: {default_key}. Please try again:")

    # 3. Public and Private Key Parameters (RSA)
    print(f"\n[3] Enter Client Key Generation Parameters (RSA):")
    print(f"    (Press ENTER to auto-generate secure 280-bit primes where modulus n > 512 bits)")
    p_in = input("    Enter Prime p (or press ENTER for default): ").strip()
    q_in = input("    Enter Prime q (or press ENTER for default): ").strip()
    e_in = input("    Enter Public Exponent e (or press ENTER for 65537): ").strip()

    custom_p = int(p_in) if p_in.isdigit() else None
    custom_q = int(q_in) if q_in.isdigit() else None
    custom_e = int(e_in) if e_in.isdigit() else 65537

    if custom_p and custom_q:
        print(f"    -> Using custom key parameters: p={custom_p}, q={custom_q}, e={custom_e}")
    else:
        print(f"    -> Using auto-generated key parameters (modulus > 512 bits to accommodate Whirlpool)")

    print("=" * 60)
    return message, secret_key, custom_p, custom_q, custom_e


def run_client(
    host="127.0.0.1",
    port=12345,
    message=None,
    secret_key=None,
    custom_p=None,
    custom_q=None,
    custom_e=65537,
    interactive=False
):
    """
    Runs the secure message exchange client.
    """
    print("=" * 70)
    print("SECURE MESSAGE EXCHANGE CLIENT")
    print("Author: Raghav Gupta | Roll Number: 20243226 | MNNIT Allahabad")
    print("Algorithms: S-DES (Symmetric) | RSA (Asymmetric) | Whirlpool (Hash)")
    print("=" * 70)

    # 1. Gather Inputs
    if interactive:
        message, secret_key, custom_p, custom_q, custom_e = get_interactive_inputs()
    else:
        if not message:
            message = "CONFIDENTIAL CRYPTO MESSAGE 2026"
        if not secret_key:
            secret_key = "1010000010"

    # Validate secret key format
    if len(secret_key) != 10 or not all(c in "01" for c in secret_key):
        raise ValueError(f"Secret Key must be a 10-bit binary string (e.g. '1010000010'), got '{secret_key}'")

    secret_key_int = int(secret_key, 2)

    # 2. Client Key Generation (RSA)
    if custom_p and custom_q:
        print(f"\n[+] Using provided primes for Client RSA: p={custom_p}, q={custom_q}, e={custom_e}")
        pub_key, priv_key, params = generate_keypair_from_primes(custom_p, custom_q, custom_e)
    else:
        print("\n[+] Generating Client RSA key parameters (280-bit primes, modulus > 512 bits)...")
        pub_key, priv_key, params = generate_rsa_keys(bits=280, e=custom_e)

    client_e, client_n = pub_key
    client_d, _ = priv_key

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

        # Step 1: Request Server Public Key
        req = json.dumps({"type": "REQUEST_SERVER_PUBLIC_KEY"})
        sock.sendall(req.encode("utf-8"))
        print("[*] Sent request for Server Public Key.")

        # Step 2: Receive Server Public Key
        resp_raw = sock.recv(4096).decode("utf-8")
        resp_json = json.loads(resp_raw)
        server_pub_key = (int(resp_json["e"]), int(resp_json["n"]))
        print(f"[+] Received Server Public Key: (e={server_pub_key[0]}, n={server_pub_key[1]})")

        # 4. Client Side Computations
        # A. Encrypt Secret Key using Server Public Key
        encrypted_secret_key = encrypt_rsa(secret_key_int, server_pub_key)

        # B. Encrypt Message using S-DES
        ciphertext_hex, enc_traces, k_trace = encrypt_message(message, secret_key)

        # C. Compute Whirlpool Hash of original Message
        hash_code_hex = whirlpool_hash(message)

        # D. Compute Digital Signature over Whirlpool Hash using Client Private Key
        digital_signature = sign_digest(hash_code_hex, priv_key)

        # 5. Display Client Outputs strictly according to the format required by assignment
        print("\n" + "=" * 70)
        print("REQUIRED ASSIGNMENT OUTPUT (CLIENT SIDE)")
        print("Author: Raghav Gupta | Roll No: 20243226")
        print("=" * 70)
        print("Client Side:")
        print(f"Input: Message: <{message}>")
        print(f"Secret Key: <{secret_key}>")
        print(f"Public Key parameters: (e={client_e}, n={client_n})")
        print(f"Private key parameters: (d={client_d}, n={client_n})")
        print(f"Encrypted Secret Key: <{encrypted_secret_key}>")
        print(f"\nIntermediate encryption process:")
        print(format_encryption_trace(enc_traces, k_trace, max_blocks=3))
        print(f"\nCipher text: <{ciphertext_hex}>")
        print(f"Hash code: <{hash_code_hex}>")
        print(f"Digital Signature: <{digital_signature}>")
        print("=" * 70)

        # 6. Send payload to Server
        # Payload bundle: Ciphertext + Encrypted secret key + Client Signature + Client Public Key
        payload = json.dumps({
            "type": "PAYLOAD",
            "ciphertext": ciphertext_hex,
            "encrypted_secret_key": str(encrypted_secret_key),
            "client_signature": str(digital_signature),
            "client_public_key": {
                "e": str(client_e),
                "n": str(client_n)
            }
        })
        sock.sendall(payload.encode("utf-8"))
        print("\n[+] Sent payload bundle to Server.")

        # 7. Await Server Acknowledgment
        ack_raw = sock.recv(4096).decode("utf-8")
        ack_json = json.loads(ack_raw)
        print(f"[+] Server Response received:")
        print(f"    Status:    {ack_json.get('status')}")
        print(f"    Signature: {ack_json.get('signature')}")
        print(f"    Message:   '{ack_json.get('received_message')}'")
        return True

    finally:
        sock.close()
        print("[*] Connection closed.")


def main():
    parser = argparse.ArgumentParser(description="Secure Message Exchange Client (Raghav Gupta - 20243226)")
    parser.add_argument("--host", default="127.0.0.1", help="Server host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=12345, help="Server port (default: 12345)")
    parser.add_argument("--message", default=None, help="Message to encrypt and send")
    parser.add_argument("--key", default=None, help="10-bit binary secret key (e.g. 1010000010)")
    parser.add_argument("--p", type=int, default=None, help="Optional prime p for Client RSA")
    parser.add_argument("--q", type=int, default=None, help="Optional prime q for Client RSA")
    parser.add_argument("--e", type=int, default=65537, help="Public exponent e (default: 65537)")
    parser.add_argument("--interactive", action="store_true", help="Prompt interactively for inputs")
    args = parser.parse_args()

    run_client(
        host=args.host,
        port=args.port,
        message=args.message,
        secret_key=args.key,
        custom_p=args.p,
        custom_q=args.q,
        custom_e=args.e,
        interactive=args.interactive
    )


if __name__ == "__main__":
    main()
