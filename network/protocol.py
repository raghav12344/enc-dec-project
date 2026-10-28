"""
Socket Protocol and Message Serialization
=========================================
Author: Raghav Gupta
Roll Number: 44275
Assignment: Assignment 1 - Secure Client-Server Message Exchange
Course: Cryptography & Information Security | MNNIT Allahabad

This module provides standardized message creation, transmission,
and reception functions for the secure client-server socket protocol.
Supports both ElGamal (p, g, y) and RSA (e, n) parameter schemas.
"""

import json
import socket


class MessageProtocol:
    """Standard message builders for the secure exchange protocol."""

    REQ_PUBLIC_KEY = "REQUEST_SERVER_PUBLIC_KEY"
    RESP_PUBLIC_KEY = "SERVER_PUBLIC_KEY"
    PAYLOAD = "PAYLOAD"
    ACK = "ACK"

    @staticmethod
    def request_server_key():
        return {"type": MessageProtocol.REQ_PUBLIC_KEY}

    @staticmethod
    def response_server_key(pub_key):
        """
        Builds server public key message.
        Supports ElGamal (p, g, y) or RSA (e, n).
        """
        if len(pub_key) == 3:
            p, g, y = pub_key
            return {
                "type": MessageProtocol.RESP_PUBLIC_KEY,
                "algo": "ElGamal",
                "p": str(p),
                "g": str(g),
                "y": str(y)
            }
        else:
            e, n = pub_key
            return {
                "type": MessageProtocol.RESP_PUBLIC_KEY,
                "algo": "RSA",
                "e": str(e),
                "n": str(n)
            }

    @staticmethod
    def parse_public_key(msg):
        """Extracts public key tuple from server or client key message/dict."""
        if "algo" in msg and msg["algo"] == "RSA":
            return (int(msg["e"]), int(msg["n"]))
        if "p" in msg and "g" in msg and "y" in msg:
            return (int(msg["p"]), int(msg["g"]), int(msg["y"]))
        if "e" in msg and "n" in msg:
            return (int(msg["e"]), int(msg["n"]))
        if isinstance(msg, list):
            return tuple(int(x) for x in msg)
        raise ValueError(f"Unrecognized public key structure: {msg}")

    @staticmethod
    def payload(ciphertext_hex, encrypted_secret_key, client_signature, client_public_key):
        """
        Serializes the complete transmission bundle:
        - ciphertext: Hex string
        - encrypted_secret_key: (c1, c2) or int
        - client_signature: (r, s) or int
        - client_public_key: (p, g, y) or (e, n)
        """
        enc_key_repr = [str(x) for x in encrypted_secret_key] if isinstance(encrypted_secret_key, (list, tuple)) else str(encrypted_secret_key)
        sig_repr = [str(x) for x in client_signature] if isinstance(client_signature, (list, tuple)) else str(client_signature)
        pub_repr = [str(x) for x in client_public_key] if isinstance(client_public_key, (list, tuple)) else str(client_public_key)

        return {
            "type": MessageProtocol.PAYLOAD,
            "ciphertext": ciphertext_hex,
            "encrypted_secret_key": enc_key_repr,
            "client_signature": sig_repr,
            "client_public_key": pub_repr
        }

    @staticmethod
    def ack(status, signature, received_message):
        return {
            "type": MessageProtocol.ACK,
            "status": status,
            "signature": signature,
            "received_message": received_message
        }


def send_json(sock, data_dict):
    """Encodes a dictionary as JSON and sends it over the socket with delimiter."""
    raw = json.dumps(data_dict) + "\n"
    sock.sendall(raw.encode("utf-8"))


def recv_json(sock, buffer_size=4096):
    """Receives and decodes a newline-delimited or complete JSON object from socket."""
    data = ""
    while True:
        chunk = sock.recv(buffer_size).decode("utf-8")
        if not chunk:
            break
        data += chunk
        if "\n" in data:
            line, _, _ = data.partition("\n")
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                pass
        try:
            return json.loads(data)
        except json.JSONDecodeError:
            continue
    if data.strip():
        return json.loads(data.strip())
    return None
