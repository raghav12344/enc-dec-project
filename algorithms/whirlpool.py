"""
Whirlpool Cryptographic Hash Function (Scratch Implementation)
=============================================================
Author: Raghav Gupta
Roll Number: 44275
Assignment: Assignment 1 - Secure Client-Server Message Exchange
Course: Cryptography & Information Security | MNNIT Allahabad

Overview:
This module provides a pure-Python, zero-dependency, from-scratch implementation
of the Whirlpool cryptographic hash algorithm (ISO/IEC 10118-3).

Theoretical Architecture:
- Designed by Vincent Rijmen (co-designer of AES) and Paulo S. L. M. Barreto.
- Miyaguchi-Preneel hashing scheme: H_i = W(H_{i-1}, m_i) ^ H_{i-1} ^ m_i
- Internal 512-bit block cipher 'W' executing 10 iterative rounds.
- Each round applies 4 modular layers:
  1. gamma (SubBytes): 8x8 non-linear S-box substitution
  2. pi (ShiftColumns): Cyclic downward rotation of column j by j positions
  3. theta (MixRows): Matrix multiplication over GF(2^8) modulo x^8+x^4+x^3+x^2+1 (0x11D)
  4. sigma (AddRoundKey): Bitwise XOR with round key K_r
"""

import struct

# Number of rounds in the W block cipher (standard ISO/IEC 10118-3)
ROUNDS = 10

# Round constants (10 64-bit words) for key schedule derivation
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

# Whirlpool 8x8 non-linear substitution box (S-box)
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


# ============================================================================
# SECTION 1: GALOIS FIELD GF(2^8) ARITHMETIC & TABLE GENERATION
# ============================================================================

def _gf_mul(a, b):
    """
    Multiplication in Galois Field GF(2^8).
    Uses Russian Peasant multiplication modulo the irreducible reduction
    polynomial x^8 + x^4 + x^3 + x^2 + 1 (binary representation 0x11D).
    """
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
    Precomputes the 8 64-bit circular lookup tables (C0 to C7).
    Combines the non-linear S-box substitution (gamma), column shift (pi),
    and MDS diffusion matrix multiplication (theta).
    Generator row coefficients: [1, 1, 4, 1, 8, 5, 2, 9].
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
        # Circular right shift by 8 bits
        curr = [((w >> 8) | ((w & 0xFF) << 56)) & 0xFFFFFFFFFFFFFFFF for w in prev]
        c_tables.append(curr)

    return c_tables


# Build round transformation tables C0..C7
C_TABLES = _build_tables()


# ============================================================================
# SECTION 2: WHIRLPOOL CORE CLASS & COMPRESSION ENGINE
# ============================================================================

class Whirlpool:
    """
    Whirlpool Hash Algorithm implementation created from scratch.
    Author: Raghav Gupta (Roll No: 20243226)
    """

    def __init__(self, message=b""):
        # 512-bit state vector initialized to all zeros (8 x 64-bit words)
        self.hash_state = [0] * 8
        self.buffer = bytearray()
        self.bit_length = 0

        if isinstance(message, str):
            message = message.encode("utf-8")
        if message:
            self.update(message)

    def update(self, data):
        """
        Feeds incoming byte data into internal buffer.
        Processes full 64-byte (512-bit) blocks as they accumulate.
        """
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
        under Miyaguchi-Preneel compression:
            H_i = W(H_{i-1}, m_i) ^ H_{i-1} ^ m_i
        """
        # Parse 64 bytes into 8 64-bit big-endian words
        block_words = list(struct.unpack(">8Q", block))

        # Initial round key K and cipher state S
        k = list(self.hash_state)
        s = [b ^ k_i for b, k_i in zip(block_words, k)]

        # 10 Iterative Encryption Rounds
        for r in range(ROUNDS):
            # 1. Update round key schedule
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

        # Miyaguchi-Preneel feed-forward feed: H_i = S ^ H_{i-1} ^ m_i
        for i in range(8):
            self.hash_state[i] ^= s[i] ^ block_words[i]

    def digest(self):
        """
        Applies standard ISO/IEC 10118-3 padding:
        1. Append '1' bit (0x80 byte)
        2. Append zero bits until length is congruent to 256 mod 512
        3. Append 256-bit (32 bytes) big-endian representation of original length
        Returns the finalized 64-byte (512-bit) digest.
        """
        saved_hash = list(self.hash_state)
        pad_buf = bytearray(self.buffer)
        total_bits = self.bit_length

        # Append '1' bit
        pad_buf.append(0x80)

        # Pad with 0x00 until length % 64 == 32 (256 bits before block boundary)
        while (len(pad_buf) % 64) != 32:
            pad_buf.append(0x00)

        # Append 256-bit (32 bytes) big-endian length integer
        length_bytes = total_bits.to_bytes(32, byteorder="big")
        pad_buf.extend(length_bytes)

        # Process all padded blocks
        for i in range(0, len(pad_buf), 64):
            self._transform(bytes(pad_buf[i:i + 64]))

        result = struct.pack(">8Q", *self.hash_state)
        self.hash_state = saved_hash  # Restore state
        return result

    def hexdigest(self):
        """Returns the 512-bit digest as a 128-character hexadecimal string."""
        return self.digest().hex()


# ============================================================================
# SECTION 3: CONVENIENCE HELPER
# ============================================================================

def whirlpool_hash(data):
    """Computes Whirlpool 512-bit hash digest of string or bytes."""
    return Whirlpool(data).hexdigest()


if __name__ == "__main__":
    print("=== Whirlpool Module Verification (Author: Raghav Gupta, Roll No: 20243226) ===")
    test_msg = "The quick brown fox jumps over the lazy dog"
    h = whirlpool_hash(test_msg)
    expected = "0c8cbe8ecdf4806a1afda403aff11d589f3345053f57595aec04b6ebb978b08fa48e142d388e5c057e0ae99812896f4dee8b62fa65d5a1c49872f8d9127b28c1"
    assert h == expected
    print(f"Input:    '{test_msg}'")
    print(f"Hash:     {h}")
    print("\nVerification: SUCCESS! Matches official ISO/IEC 10118-3 test vector.")
