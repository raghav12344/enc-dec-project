"""
Socket Protocol and Message Serialization
=========================================
Author: Raghav Gupta
Roll Number: 20243226
Assignment: Assignment 1 - Secure Client-Server Message Exchange

This module provides standardized message creation, transmission,
and reception functions for the secure client-server socket protocol.
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
    def response_server_key(e, n):
        return {
            "type": MessageProtocol.RESP_PUBLIC_KEY,
            "e": str(e),
            "n": str(n)
        }

    @staticmethod
    def payload(ciphertext_hex, encrypted_secret_key, client_signature, client_public_key):
        return {
            "type": MessageProtocol.PAYLOAD,
            "ciphertext": ciphertext_hex,
            "encrypted_secret_key": str(encrypted_secret_key),
            "client_signature": str(client_signature),
            "client_public_key": {
                "e": str(client_public_key[0]),
                "n": str(client_public_key[1])
            }
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
