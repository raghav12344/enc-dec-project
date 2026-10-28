"""
Simplified Advanced Encryption Standard (S-AES) Implementation
==============================================================
Author: Raghav Gupta
Roll Number: 44275
Assignment: Assignment 1 - Secure Client-Server Message Exchange
Course: Cryptography & Information Security | MNNIT Allahabad

Overview:
This module provides an educational, platform-independent implementation of the
Simplified AES (S-AES) algorithm originally developed by Prof. Mohammad A. Musa,
Edward F. Schaefer, and Stephen Wedig (Cryptologia, 2003).

Theoretical Architecture:
- Block Size: 16 bits (represented as a 2x2 matrix of 4-bit nibbles)
- Key Size: 16 bits (expanded into three 16-bit round keys: Key0, Key1, Key2)
- Structure: Substitution-Permutation Network (SPN) with 2 rounds
- Arithmetic: Galois Field GF(2^4) modulo the irreducible polynomial x^4 + x + 1 (0x13)

Rounds:
- Round 0: AddRoundKey(Key0)
- Round 1: SubNibbles, ShiftRows, MixColumns, AddRoundKey(Key1)
- Round 2: SubNibbles, ShiftRows, AddRoundKey(Key2) (MixColumns skipped in final round)

Theoretical References:
- Mohammad A. Musa, Edward F. Schaefer, Stephen Wedig,
  "A Simplified AES: An Education Oriented Alternate to AES", Cryptologia, 2003.
- William Stallings, "Cryptography and Network Security", Appendix on S-AES.
"""

# ============================================================================
# SECTION 1: LOOKUP TABLES & GALOIS FIELD GF(2^4) ARITHMETIC
# ============================================================================

# Irreducible polynomial for GF(2^4): x^4 + x + 1 (binary 10011 = 0x13)
GF_MODULUS = 0x13

# S-AES 4-bit Substitution Box (S-Box)
# SBox[x] maps a 4-bit nibble x (0..15) to its non-linear substitution
SBOX = [
    0x9, 0x4, 0xA, 0xB,
    0xD, 0x1, 0x8, 0x5,
    0x6, 0x2, 0x0, 0x3,
    0xC, 0xE, 0xF, 0x7
]

# Inverse Substitution Box (InvSBox) for decryption
# InvSBox[SBox[x]] == x
INVSBOX = [
    0xA, 0x5, 0x9, 0xB,
    0x1, 0x7, 0x8, 0xF,
    0x6, 0x0, 0x2, 0x3,
    0xC, 0x4, 0xD, 0xE
]

# Round Constants for Key Expansion (defined as 8-bit values)
# Rcon(1) = x^(1+2) = x^3 = 1000 0000_2 = 0x80
# Rcon(2) = x^(2+2) = x^4 = x + 1 = 0011 0000_2 = 0x30
RCON = [0x80, 0x30]


def gf_mult(a, b):
    """
    Multiplication in Galois Field GF(2^4) modulo x^4 + x + 1 (0x13).
    
    Parameters:
        a (int): 4-bit nibble (0..15)
        b (int): 4-bit nibble (0..15)
    Returns:
        int: 4-bit product in GF(2^4)
    """
    p = 0
    a &= 0x0F
    b &= 0x0F
    while b > 0:
        if b & 1:
            p ^= a
        a <<= 1
        if a & 0x10:  # Overflow beyond degree 3 (x^4)
            a ^= GF_MODULUS
        b >>= 1
    return p & 0x0F


# ============================================================================
# SECTION 2: KEY EXPANSION (16-bit Master Key -> w0..w5 -> 3 Round Keys)
# ============================================================================

def sub_nib_byte(b):
    """
    Applies S-Box substitution to each 4-bit nibble of an 8-bit byte.
    """
    n0 = (b >> 4) & 0x0F
    n1 = b & 0x0F
    return (SBOX[n0] << 4) | SBOX[n1]


def rot_nib(b):
    """
    Rotates the two 4-bit nibbles of an 8-bit byte (RotNib):
    [n0, n1] -> [n1, n0]
    """
    return ((b & 0x0F) << 4) | ((b >> 4) & 0x0F)


def generate_subkeys(key_16bit):
    """
    Expands a 16-bit master key into three 16-bit round keys: Key0, Key1, Key2.
    
    Formulas (Musa et al. / Stallings):
        w0 = key[15..8], w1 = key[7..0]
        w2 = w0 ^ Rcon(1) ^ SubNib(RotNib(w1))
        w3 = w2 ^ w1
        w4 = w2 ^ Rcon(2) ^ SubNib(RotNib(w3))
        w5 = w4 ^ w3
        
        Round 0 Key = (w0 << 8) | w1
        Round 1 Key = (w2 << 8) | w3
        Round 2 Key = (w4 << 8) | w5
        
    Parameters:
        key_16bit (int): 16-bit integer (0..0xFFFF)
    Returns:
        tuple[int, int, int]: (key0, key1, key2) as 16-bit integers
    """
    w0 = (key_16bit >> 8) & 0xFF
    w1 = key_16bit & 0xFF

    w2 = w0 ^ RCON[0] ^ sub_nib_byte(rot_nib(w1))
    w3 = w2 ^ w1

    w4 = w2 ^ RCON[1] ^ sub_nib_byte(rot_nib(w3))
    w5 = w4 ^ w3

    key0 = (w0 << 8) | w1
    key1 = (w2 << 8) | w3
    key2 = (w4 << 8) | w5

    return key0, key1, key2


# ============================================================================
# SECTION 3: CORE S-AES TRANSFORMATIONS (STATE: 2x2 NIBBLE MATRIX)
# ============================================================================

def block_to_matrix(block):
    """
    Maps 16-bit block into a 2x2 nibble matrix (column-major):
    nibble 0 (bits 15..12) -> s00
    nibble 1 (bits 11..8)  -> s10
    nibble 2 (bits 7..4)   -> s01
    nibble 3 (bits 3..0)   -> s11
    """
    s00 = (block >> 12) & 0x0F
    s10 = (block >> 8) & 0x0F
    s01 = (block >> 4) & 0x0F
    s11 = block & 0x0F
    return [[s00, s01], [s10, s11]]


def matrix_to_block(m):
    """
    Reconstructs 16-bit integer from 2x2 nibble matrix.
    """
    return ((m[0][0] & 0x0F) << 12) | ((m[1][0] & 0x0F) << 8) | ((m[0][1] & 0x0F) << 4) | (m[1][1] & 0x0F)


def add_round_key(state, key):
    """
    Bitwise XOR of 16-bit state with 16-bit round key.
    """
    return state ^ key


def sub_nibbles(state_m):
    """
    SubNibbles: Applies 4-bit S-Box to each nibble of the 2x2 state.
    """
    return [
        [SBOX[state_m[0][0]], SBOX[state_m[0][1]]],
        [SBOX[state_m[1][0]], SBOX[state_m[1][1]]]
    ]


def inv_sub_nibbles(state_m):
    """
    InvSubNibbles: Applies inverse S-Box to each nibble of the 2x2 state.
    """
    return [
        [INVSBOX[state_m[0][0]], INVSBOX[state_m[0][1]]],
        [INVSBOX[state_m[1][0]], INVSBOX[state_m[1][1]]]
    ]


def shift_rows(state_m):
    """
    ShiftRows: Cyclically shifts row 1 by 1 nibble (swaps s10 and s11).
    Row 0 remains unchanged. Note that 2-element swap is self-inverse!
    """
    return [
        [state_m[0][0], state_m[0][1]],
        [state_m[1][1], state_m[1][0]]
    ]


def mix_columns(state_m):
    """
    MixColumns: Multiplies state matrix by [[1, 4], [4, 1]] over GF(2^4).
    s'00 = (1 * s00) ^ (4 * s10)
    s'10 = (4 * s00) ^ (1 * s10)
    s'01 = (1 * s01) ^ (4 * s11)
    s'11 = (4 * s01) ^ (1 * s11)
    """
    s00, s01 = state_m[0][0], state_m[0][1]
    s10, s11 = state_m[1][0], state_m[1][1]

    sp00 = s00 ^ gf_mult(4, s10)
    sp10 = gf_mult(4, s00) ^ s10
    sp01 = s01 ^ gf_mult(4, s11)
    sp11 = gf_mult(4, s01) ^ s11

    return [[sp00, sp01], [sp10, sp11]]


def inv_mix_columns(state_m):
    """
    InvMixColumns: Multiplies state matrix by inverse matrix [[9, 2], [2, 9]] over GF(2^4).
    s'00 = (9 * s00) ^ (2 * s10)
    s'10 = (2 * s00) ^ (9 * s10)
    s'01 = (9 * s01) ^ (2 * s11)
    s'11 = (2 * s01) ^ (9 * s11)
    """
    s00, s01 = state_m[0][0], state_m[0][1]
    s10, s11 = state_m[1][0], state_m[1][1]

    sp00 = gf_mult(9, s00) ^ gf_mult(2, s10)
    sp10 = gf_mult(2, s00) ^ gf_mult(9, s10)
    sp01 = gf_mult(9, s01) ^ gf_mult(2, s11)
    sp11 = gf_mult(2, s01) ^ gf_mult(9, s11)

    return [[sp00, sp01], [sp10, sp11]]


# ============================================================================
# SECTION 4: BLOCK ENGINES WITH GRANULAR INTERMEDIATE TRACING
# ============================================================================

def encrypt_block_with_trace(pt_16bit, subkeys):
    """
    Encrypts a single 16-bit block with S-AES and returns the ciphertext
    along with full intermediate state traces for educational inspection.
    """
    k0, k1, k2 = subkeys
    trace = {"plaintext": pt_16bit, "round_keys": subkeys}

    # Round 0: AddRoundKey
    st0 = add_round_key(pt_16bit, k0)
    trace["round0_ark"] = st0

    # Round 1:
    m = block_to_matrix(st0)
    m_sub = sub_nibbles(m)
    trace["round1_sub"] = matrix_to_block(m_sub)

    m_shift = shift_rows(m_sub)
    trace["round1_shift"] = matrix_to_block(m_shift)

    m_mix = mix_columns(m_shift)
    st_mix = matrix_to_block(m_mix)
    trace["round1_mix"] = st_mix

    st1 = add_round_key(st_mix, k1)
    trace["round1_ark"] = st1

    # Round 2:
    m2 = block_to_matrix(st1)
    m2_sub = sub_nibbles(m2)
    trace["round2_sub"] = matrix_to_block(m2_sub)

    m2_shift = shift_rows(m2_sub)
    st2_shift = matrix_to_block(m2_shift)
    trace["round2_shift"] = st2_shift

    # MixColumns is skipped in Round 2
    ct_16bit = add_round_key(st2_shift, k2)
    trace["round2_ark"] = ct_16bit
    trace["ciphertext"] = ct_16bit

    return ct_16bit, trace


def decrypt_block_with_trace(ct_16bit, subkeys):
    """
    Decrypts a single 16-bit block with S-AES and returns the plaintext
    along with full intermediate state traces.
    
    Decryption Flow:
    - AddRoundKey(Key2)
    - InvShiftRows (= ShiftRows)
    - InvSubNibbles
    - AddRoundKey(Key1)
    - InvMixColumns
    - InvShiftRows
    - InvSubNibbles
    - AddRoundKey(Key0)
    """
    k0, k1, k2 = subkeys
    trace = {"ciphertext": ct_16bit, "round_keys": subkeys}

    # Initial AddRoundKey with Key2
    st2 = add_round_key(ct_16bit, k2)
    trace["round2_ark"] = st2

    m2 = block_to_matrix(st2)
    m2_shift = shift_rows(m2)  # ShiftRows is self-inverse
    trace["round2_inv_shift"] = matrix_to_block(m2_shift)

    m2_sub = inv_sub_nibbles(m2_shift)
    st2_sub = matrix_to_block(m2_sub)
    trace["round2_inv_sub"] = st2_sub

    # Round 1
    st1_ark = add_round_key(st2_sub, k1)
    trace["round1_ark"] = st1_ark

    m1_mix = inv_mix_columns(block_to_matrix(st1_ark))
    trace["round1_inv_mix"] = matrix_to_block(m1_mix)

    m1_shift = shift_rows(m1_mix)
    trace["round1_inv_shift"] = matrix_to_block(m1_shift)

    m1_sub = inv_sub_nibbles(m1_shift)
    st1_sub = matrix_to_block(m1_sub)
    trace["round1_inv_sub"] = st1_sub

    pt_16bit = add_round_key(st1_sub, k0)
    trace["round0_ark"] = pt_16bit
    trace["plaintext"] = pt_16bit

    return pt_16bit, trace


def encrypt_block(pt_16bit, key_16bit):
    """Encrypts a single 16-bit block."""
    subkeys = generate_subkeys(key_16bit)
    ct, _ = encrypt_block_with_trace(pt_16bit, subkeys)
    return ct


def decrypt_block(ct_16bit, key_16bit):
    """Decrypts a single 16-bit block."""
    subkeys = generate_subkeys(key_16bit)
    pt, _ = decrypt_block_with_trace(ct_16bit, subkeys)
    return pt


# ============================================================================
# SECTION 5: STRING ENCRYPTION / DECRYPTION (ARBITRARY LENGTH TEXT)
# ============================================================================

def encrypt_message(plaintext, key_16bit):
    """
    Encrypts an arbitrary string message using S-AES (2 characters = 16 bits per block).
    If odd length, pads with a space or null byte.
    
    Returns:
        tuple[str, list[dict]]: (ciphertext_hex, list_of_block_traces)
    """
    raw_bytes = plaintext.encode("utf-8")
    if len(raw_bytes) % 2 != 0:
        raw_bytes += b" "  # Pad with space for even 16-bit boundary

    subkeys = generate_subkeys(key_16bit)
    cipher_words = []
    traces = []

    for i in range(0, len(raw_bytes), 2):
        b0 = raw_bytes[i]
        b1 = raw_bytes[i + 1]
        block = (b0 << 8) | b1
        ct, trace = encrypt_block_with_trace(block, subkeys)
        cipher_words.append(ct)
        traces.append(trace)

    ciphertext_hex = "".join(f"{w:04x}" for w in cipher_words)
    return ciphertext_hex, traces


def decrypt_message(ciphertext_hex, key_16bit):
    """
    Decrypts an S-AES ciphertext hex string back into original plaintext string.
    
    Returns:
        tuple[str, list[dict]]: (decrypted_string, list_of_block_traces)
    """
    subkeys = generate_subkeys(key_16bit)
    recovered_bytes = bytearray()
    traces = []

    for i in range(0, len(ciphertext_hex), 4):
        chunk = ciphertext_hex[i:i + 4]
        if not chunk:
            break
        ct = int(chunk, 16)
        pt, trace = decrypt_block_with_trace(ct, subkeys)
        traces.append(trace)
        recovered_bytes.append((pt >> 8) & 0xFF)
        recovered_bytes.append(pt & 0xFF)

    plaintext = recovered_bytes.decode("utf-8", errors="replace").rstrip(" ")
    return plaintext, traces


# ============================================================================
# SECTION 6: INTERMEDIATE PROCESS TRACE FORMATTERS
# ============================================================================

def format_encryption_trace(traces, key_16bit, max_blocks_to_show=3):
    """
    Formats the intermediate encryption process output for display.
    """
    k0, k1, k2 = generate_subkeys(key_16bit)
    w0 = (key_16bit >> 8) & 0xFF
    w1 = key_16bit & 0xFF
    w2 = (k1 >> 8) & 0xFF
    w3 = k1 & 0xFF
    w4 = (k2 >> 8) & 0xFF
    w5 = k2 & 0xFF

    lines = [
        "--- Intermediate Encryption Process (Simplified AES) ---",
        f"1. Key Schedule Expansion (16-bit master key: 0x{key_16bit:04X} = {key_16bit:016b}b):",
        f"   Words w0, w1 : w0 = 0x{w0:02X} ({w0:08b}b), w1 = 0x{w1:02X} ({w1:08b}b)",
        f"   Words w2, w3 : w2 = 0x{w2:02X} ({w2:08b}b), w3 = 0x{w3:02X} ({w3:08b}b)",
        f"   Words w4, w5 : w4 = 0x{w4:02X} ({w4:08b}b), w5 = 0x{w5:02X} ({w5:08b}b)",
        f"   -> Round 0 Key (K0): 0x{k0:04X} ({k0:016b}b)",
        f"   -> Round 1 Key (K1): 0x{k1:04X} ({k1:016b}b)",
        f"   -> Round 2 Key (K2): 0x{k2:04X} ({k2:016b}b)",
        "",
        f"2. Block-by-Block S-AES Encryption (showing {min(len(traces), max_blocks_to_show)} of {len(traces)} block(s)):"
    ]

    for idx, t in enumerate(traces[:max_blocks_to_show]):
        pt = t["plaintext"]
        c0 = chr((pt >> 8) & 0xFF) if 32 <= ((pt >> 8) & 0xFF) < 127 else "?"
        c1 = chr(pt & 0xFF) if 32 <= (pt & 0xFF) < 127 else "?"
        lines.append(f"   [Block {idx + 1}: Chars '{c0}{c1}' (16-bit: 0x{pt:04X} = {pt:016b}b)]")
        lines.append(f"     -> Round 0 AddRoundKey (K0): 0x{t['round0_ark']:04X}")
        lines.append(f"     -> Round 1 SubNibbles      : 0x{t['round1_sub']:04X}")
        lines.append(f"     -> Round 1 ShiftRows       : 0x{t['round1_shift']:04X}")
        lines.append(f"     -> Round 1 MixColumns      : 0x{t['round1_mix']:04X}")
        lines.append(f"     -> Round 1 AddRoundKey (K1): 0x{t['round1_ark']:04X}")
        lines.append(f"     -> Round 2 SubNibbles      : 0x{t['round2_sub']:04X}")
        lines.append(f"     -> Round 2 ShiftRows       : 0x{t['round2_shift']:04X}")
        lines.append(f"     -> Round 2 AddRoundKey (K2): 0x{t['round2_ark']:04X} (Cipher block: 0x{t['ciphertext']:04X})")

    if len(traces) > max_blocks_to_show:
        lines.append(f"   ... ({len(traces) - max_blocks_to_show} remaining 16-bit block(s) encrypted similarly)")

    return "\n".join(lines)


def format_decryption_trace(traces, key_16bit, max_blocks_to_show=3):
    """
    Formats the intermediate decryption process output for display.
    """
    k0, k1, k2 = generate_subkeys(key_16bit)

    lines = [
        "--- Intermediate Decryption Process (Simplified AES) ---",
        "1. Round Subkeys Applied in Reverse Order:",
        f"   Round 2 Key (K2): 0x{k2:04X} ({k2:016b}b)",
        f"   Round 1 Key (K1): 0x{k1:04X} ({k1:016b}b)",
        f"   Round 0 Key (K0): 0x{k0:04X} ({k0:016b}b)",
        "",
        f"2. Block-by-Block S-AES Decryption (showing {min(len(traces), max_blocks_to_show)} of {len(traces)} block(s)):"
    ]

    for idx, t in enumerate(traces[:max_blocks_to_show]):
        ct = t["ciphertext"]
        pt = t["plaintext"]
        c0 = chr((pt >> 8) & 0xFF) if 32 <= ((pt >> 8) & 0xFF) < 127 else "?"
        c1 = chr(pt & 0xFF) if 32 <= (pt & 0xFF) < 127 else "?"
        lines.append(f"   [Block {idx + 1}: Cipher 0x{ct:04X} ({ct:016b}b)]")
        lines.append(f"     -> AddRoundKey (K2)        : 0x{t['round2_ark']:04X}")
        lines.append(f"     -> InvShiftRows            : 0x{t['round2_inv_shift']:04X}")
        lines.append(f"     -> InvSubNibbles           : 0x{t['round2_inv_sub']:04X}")
        lines.append(f"     -> AddRoundKey (K1)        : 0x{t['round1_ark']:04X}")
        lines.append(f"     -> InvMixColumns           : 0x{t['round1_inv_mix']:04X}")
        lines.append(f"     -> InvShiftRows            : 0x{t['round1_inv_shift']:04X}")
        lines.append(f"     -> InvSubNibbles           : 0x{t['round1_inv_sub']:04X}")
        lines.append(f"     -> AddRoundKey (K0)        : 0x{t['round0_ark']:04X} -> Decrypted Chars: '{c0}{c1}'")

    if len(traces) > max_blocks_to_show:
        lines.append(f"   ... ({len(traces) - max_blocks_to_show} remaining 16-bit block(s) decrypted similarly)")

    return "\n".join(lines)


# Self-test block when executed directly
if __name__ == "__main__":
    print("[*] Verifying S-AES against Musa / Stallings textbook test vector...")
    test_pt = 0xD728  # 1101 0111 0010 1000
    test_key = 0x4AF5  # 0100 1010 1111 0101
    test_expected_ct = 0x24EC  # 0010 0100 1110 1100

    ct = encrypt_block(test_pt, test_key)
    pt = decrypt_block(ct, test_key)
    print(f"    Plaintext  : 0x{test_pt:04X}")
    print(f"    Key        : 0x{test_key:04X}")
    print(f"    Ciphertext : 0x{ct:04X} (Expected: 0x{test_expected_ct:04X})")
    print(f"    Recovered  : 0x{pt:04X}")
    assert ct == test_expected_ct, f"Ciphertext mismatch! Got {ct:04X}, expected {test_expected_ct:04X}"
    assert pt == test_pt, f"Decryption mismatch! Got {pt:04X}, expected {test_pt:04X}"
    print("[+] S-AES textbook test vector PASSED!")
