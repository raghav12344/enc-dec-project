"""
Network Protocol Package
========================
Author: Raghav Gupta
Roll Number: 20243226
Assignment: Assignment 1 - Secure Client-Server Message Exchange

This package handles network communications, socket packet framing,
and JSON message serialization for the secure exchange protocol.
"""

from .protocol import (
    MessageProtocol,
    send_json,
    recv_json
)

__all__ = [
    "MessageProtocol",
    "send_json",
    "recv_json"
]
