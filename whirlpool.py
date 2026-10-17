"""
Whirlpool Cryptographic Hash Function (Scratch Implementation)
=============================================================
Author: Raghav Gupta
Roll Number: 20243226
Assignment: Assignment 1 - Secure Client-Server Message Exchange

This module provides a pure-Python, zero-dependency, from-scratch implementation
of the Whirlpool cryptographic hash algorithm (ISO/IEC 10118-3).

Whirlpool is an iterated cryptographic hash function based on the Miyaguchi-Preneel
construction with an underlying 10-round 512-bit block cipher (W cipher).
It operates on 512-bit blocks (64 bytes) and outputs a 512-bit digest (128 hex chars).
"""

import struct

# Number of rounds in Whirlpool
ROUNDS = 10

# Round constants (10 64-bit words) for key schedule
RC = [
    0x1823c6e887b8014f,
    0x36a6d2f5796f9152,
    0x60bc9b8ea30c7b35,
    0x1de0d7c22e4bfede,
    0x57157737e59ff04a,
    0xda58c9290ab1a06b,
    0x85bd5d10f4cb3e05,
    0x67e427418ba77d95,
    0xd8fbeebb7c66dd17,
    0x479ecacdbf07ad5a
]

# S-box (8x8 non-linear substitution box)
SBOX = [
    0x18, 0x23, 0xc6, 0xe8, 0x87, 0xb8, 0x01, 0x4f, 0x36, 0xa6, 0xd2, 0xf5, 0x79, 0x6f, 0x91, 0x52,
    0x60, 0xbc, 0x9b, 0x8e, 0xa3, 0x0c, 0x7b, 0x35, 0x1d, 0xe0, 0xd7, 0xc2, 0x2e, 0x4b, 0xfe, 0x57,
    0x15, 0x77, 0x37, 0xe5, 0x9f, 0xf0, 0x4a, 0xda, 0x58, 0xc9, 0x29, 0x0a, 0xb1, 0xa0, 0x6b, 0x85,
    0xbd, 0x5d, 0x10, 0xf4, 0xcb, 0x3e, 0x05, 0x67, 0xe4, 0x27, 0x41, 0x8b, 0xa7, 0x7d, 0x95, 0xd8,
    0xfb, 0xee, 0x7c, 0x66, 0xdd, 0x17, 0x47, 0x9e, 0xca, 0x2d, 0xbf, 0x07, 0xad, 0x5a, 0x83, 0x33,
    0x63, 0x02, 0xaa, 0x71, 0xc8, 0x19, 0x49, 0xd9, 0xf2, 0xe3, 0x5b, 0x88, 0x9a, 0x26, 0x32, 0xb0,
    0xe9, 0x0f, 0xd5, 0x80, 0xbe, 0xcd, 0x34, 0x48, 0xff, 0x7a, 0x90, 0x5f, 0x20, 0x68, 0x1a, 0xae,
    0xb4, 0x54, 0x93, 0x22, 0x64, 0xf1, 0x73, 0x12, 0x40, 0x08, 0xc3, 0xec, 0xdb, 0xa1, 0x8d, 0x3d,
    0x97, 0x00, 0xcf, 0x2b, 0x76, 0x82, 0xd6, 0x1b, 0xb5, 0xaf, 0x6a, 0x50, 0x45, 0xf3, 0x30, 0xef,
    0x3f, 0x55, 0xa2, 0xea, 0x65, 0xba, 0x2f, 0xc0, 0xde, 0x1c, 0xfd, 0x4d, 0x92, 0x75, 0x06, 0x8a,
    0xb2, 0xe6, 0x0e, 0x1f, 0x62, 0xd4, 0xa8, 0x96, 0xf9, 0xc5, 0x25, 0x59, 0x84, 0x72, 0x39, 0x4c,
    0x5e, 0x78, 0x38, 0x8c, 0xd1, 0xa5, 0xe2, 0x61, 0xb3, 0x21, 0x9c, 0x1e, 0x43, 0xc7, 0xfc, 0x04,
    0x51, 0x99, 0x6d, 0x0d, 0xfa, 0xdf, 0x7e, 0x24, 0x3b, 0xab, 0xce, 0x11, 0x8f, 0x4e, 0xb7, 0xeb,
    0x3c, 0x81, 0x94, 0xf7, 0xb9, 0x13, 0x2c, 0xd3, 0xe7, 0x6e, 0xc4, 0x03, 0x56, 0x44, 0x7f, 0xa9,
    0x2a, 0xbb, 0xc1, 0x53, 0xdc, 0x0b, 0x9d, 0x6c, 0x31, 0x74, 0xf6, 0x46, 0xac, 0x89, 0x14, 0xe1,
    0x16, 0x3a, 0x69, 0x09, 0x70, 0xb6, 0xd0, 0xed, 0xcc, 0x42, 0x98, 0xa4, 0x28, 0x5c, 0xf8, 0x86
]


def _gf_mul(a, b):
    """Galois Field GF(2^8) multiplication with reduction polynomial 0x11D."""
    res = 0
    for _ in range(8):
        if b & 1:
            res ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1D
        b >>= 1
    return res


def _build_tables():
    """
    Constructs the precomputed 64-bit round transformation tables C0..C7
    by combining SubBytes, ShiftColumns, and MixRows (diffusion matrix).
    Diffusion row generator: [1, 1, 4, 1, 8, 5, 2, 9].
    """
    row_coeffs = [1, 1, 4, 1, 8, 5, 2, 9]
    c0 = []
    for x in range(256):
        s = SBOX[x]
        w = 0
        for coeff in row_coeffs:
            w = (w << 8) | _gf_mul(s, coeff)
        c0.append(w)

    c_tables = [c0]
    for i in range(1, 8):
        prev = c_tables[i - 1]
        # Rotate 64-bit word right by 8 bits
        curr = [((w >> 8) | ((w & 0xFF) << 56)) & 0xFFFFFFFFFFFFFFFF for w in prev]
        c_tables.append(curr)

    return c_tables


# Build transformation tables C0..C7
C_TABLES = _build_tables()


class Whirlpool:
    """
    Pure Python Whirlpool Hash Function implementation created from scratch.
    Author: Raghav Gupta (Roll No: 20243226)
    """

    def __init__(self, message=b""):
        # 512-bit hash state as 8 64-bit big-endian words
        self.hash_state = [0] * 8
        self.buffer = bytearray()
        self.bit_length = 0

        if isinstance(message, str):
            message = message.encode("utf-8")
        if message:
            self.update(message)

    def update(self, data):
        """Processes an arbitrary byte string, buffering into 64-byte blocks."""
        if isinstance(data, str):
            data = data.encode("utf-8")

        self.buffer.extend(data)
        self.bit_length += len(data) * 8

        while len(self.buffer) >= 64:
            block = bytes(self.buffer[:64])
            self._transform(block)
            self.buffer = self.buffer[64:]

    def _transform(self, block):
        """
        Processes a single 512-bit (64-byte) block using the W block cipher
        under the Miyaguchi-Preneel hashing mode:
        H_i = W(H_{i-1}, m_i) XOR H_{i-1} XOR m_i
        """
        # Parse 64 bytes into 8 64-bit words (big-endian)
        block_words = list(struct.unpack(">8Q", block))

        # Initial cipher state and round key
        k = list(self.hash_state)
        s = [b ^ k_i for b, k_i in zip(block_words, k)]

        # 10 Encryption rounds
        for r in range(ROUNDS):
            # 1. Update key schedule
            new_k = [0] * 8
            for i in range(8):
                w = 0
                for j in range(8):
                    idx = (k[(i - j) % 8] >> (56 - 8 * j)) & 0xFF
                    w ^= C_TABLES[j][idx]
                if i == 0:
                    w ^= RC[r]
                new_k[i] = w & 0xFFFFFFFFFFFFFFFF
            k = new_k

            # 2. Update cipher state
            new_s = [0] * 8
            for i in range(8):
                w = 0
                for j in range(8):
                    idx = (s[(i - j) % 8] >> (56 - 8 * j)) & 0xFF
                    w ^= C_TABLES[j][idx]
                w ^= k[i]
                new_s[i] = w & 0xFFFFFFFFFFFFFFFF
            s = new_s

        # Miyaguchi-Preneel feed-forward
        for i in range(8):
            self.hash_state[i] ^= s[i] ^ block_words[i]

    def digest(self):
        """Finalizes padding and returns the 64-byte (512-bit) digest."""
        # Work on a copy of state to allow idempotent digest calls
        saved_hash = list(self.hash_state)
        pad_buf = bytearray(self.buffer)
        total_bits = self.bit_length

        # Append '1' bit (0x80 byte)
        pad_buf.append(0x80)

        # Pad with 0s until (len * 8) % 512 == 256 (32 bytes from block boundary)
        while (len(pad_buf) % 64) != 32:
            pad_buf.append(0x00)

        # Append 256-bit (32 bytes) big-endian representation of total bit length
        # Python supports arbitrary-size integers:
        length_bytes = total_bits.to_bytes(32, byteorder="big")
        pad_buf.extend(length_bytes)

        # Process all remaining blocks
        for i in range(0, len(pad_buf), 64):
            self._transform(bytes(pad_buf[i:i + 64]))

        result = struct.pack(">8Q", *self.hash_state)
        # Restore state
        self.hash_state = saved_hash
        return result

    def hexdigest(self):
        """Returns the 512-bit digest as a 128-character lowercase hexadecimal string."""
        return self.digest().hex()


def whirlpool_hash(data):
    """Convenience helper function to compute Whirlpool hash of a string or bytes."""
    return Whirlpool(data).hexdigest()


if __name__ == "__main__":
    print(f"=== Whirlpool Hash Verification (Author: Raghav Gupta, Roll No: 20243226) ===")
    test_cases = [
        "",
        "a",
        "abc",
        "message digest",
        "The quick brown fox jumps over the lazy dog"
    ]
    for msg in test_cases:
        h = whirlpool_hash(msg)
        print(f"Input: '{msg}'")
        print(f"Hash:  {h}\n")
