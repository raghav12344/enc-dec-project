"""
Simplified Data Encryption Standard (S-DES) Implementation
==========================================================
Author: Raghav Gupta
Roll Number: 20243226
Assignment: Assignment 1 - Secure Client-Server Message Exchange
Course: Cryptography & Information Security | MNNIT Allahabad

Overview:
This module provides an educational, platform-independent implementation of the
Simplified DES (S-DES) algorithm originally designed by Prof. Edward Schaefer.
It operates on an 8-bit plaintext block under a 10-bit master secret key using
a 2-round Feistel structure.

Theoretical References:
- William Stallings, "Cryptography and Network Security: Principles and Practice"
- Edward Schaefer, "A Simplified Data Encryption Standard", Cryptologia, 1996
"""

# ============================================================================
# SECTION 1: PERMUTATION ARRAYS & S-BOX DEFINITIONS (STANDARD STALLINGS)
# ============================================================================

# Permutation P10: Reorders 10-bit key before split
# Indices: 1-indexed representation from standard literature
P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]

# Permutation P8: Compresses two 5-bit shifted halves into an 8-bit subkey
P8 = [6, 3, 7, 4, 8, 5, 10, 9]

# Initial Permutation (IP): Applied to the 8-bit plaintext block at round start
IP = [2, 6, 3, 1, 4, 8, 5, 7]

# Inverse Initial Permutation (IP^-1): Applied to pre-output block at round end
IP_INV = [4, 1, 3, 5, 7, 2, 8, 6]

# Expansion Permutation (EP): Expands 4-bit right half to 8 bits for subkey XOR
EP = [4, 1, 2, 3, 2, 3, 4, 1]

# Permutation P4: Reorders 4-bit output of combined S0 and S1 substitutions
P4 = [2, 4, 3, 1]

# Substitution Box S0 (4x4 matrix: 2-bit row x 2-bit col -> 2-bit value)
# Row determined by outer bits (b0, b3); Col determined by inner bits (b1, b2)
S0 = [
    [1, 0, 3, 2],
    [3, 2, 1, 0],
    [0, 2, 1, 3],
    [3, 1, 3, 2]
]

# Substitution Box S1 (4x4 matrix: 2-bit row x 2-bit col -> 2-bit value)
S1 = [
    [0, 1, 2, 3],
    [2, 0, 1, 3],
    [3, 0, 1, 0],
    [2, 1, 0, 3]
]


# ============================================================================
# SECTION 2: BITWISE HELPER PRIMITIVES
# ============================================================================

def permute(bits, table):
    """
    Applies a 1-indexed permutation table to an array of bits.
    Formula: output[i] = bits[table[i] - 1]
    """
    return [bits[i - 1] for i in table]


def left_shift(bits, n):
    """
    Performs circular left shift (LS-n) on an array of bits.
    Elements rotated past the left end wrap around to the right.
    """
    return bits[n:] + bits[:n]


def bits_to_str(bits):
    """Converts a bit list [1, 0, 1] to a readable binary string '101'."""
    return "".join(str(b) for b in bits)


def str_to_bits(s):
    """Converts a binary string '101' to a bit list [1, 0, 1]."""
    return [int(c) for c in s if c in "01"]


# ============================================================================
# SECTION 3: KEY SCHEDULE (10-BIT KEY -> SUBKEYS K1 & K2)
# ============================================================================

def generate_subkeys(key_10bit):
    """
    Derives two 8-bit subkeys (K1 and K2) from a 10-bit master secret key.

    Step-by-Step Mathematical Process:
    1. Apply P10 to master key: P10(Key)
    2. Split 10-bit output into Left (5 bits) and Right (5 bits)
    3. Perform circular left shift by 1 (LS-1) on both halves
    4. Apply P8 to combined halves -> Subkey K1 (8 bits)
    5. Perform circular left shift by 2 (LS-2) on previous shifted halves
    6. Apply P8 to combined halves -> Subkey K2 (8 bits)

    Returns:
        (k1, k2, trace_dictionary)
    """
    if isinstance(key_10bit, str):
        key_10bit = str_to_bits(key_10bit)

    if len(key_10bit) != 10:
        raise ValueError(f"S-DES key must be exactly 10 bits, got {len(key_10bit)}")

    trace = {"key": bits_to_str(key_10bit)}

    # Step 1: P10 Permutation
    p10 = permute(key_10bit, P10)
    trace["p10"] = bits_to_str(p10)

    # Step 2: Split into 5-bit halves
    left, right = p10[:5], p10[5:]
    trace["p10_left"] = bits_to_str(left)
    trace["p10_right"] = bits_to_str(right)

    # Step 3: Circular left shift by 1 bit (LS-1)
    l1 = left_shift(left, 1)
    r1 = left_shift(right, 1)
    trace["ls1_left"] = bits_to_str(l1)
    trace["ls1_right"] = bits_to_str(r1)

    # Step 4: Generate Subkey K1 via P8
    k1 = permute(l1 + r1, P8)
    trace["k1"] = bits_to_str(k1)

    # Step 5: Circular left shift by 2 bits (LS-2)
    l2 = left_shift(l1, 2)
    r2 = left_shift(r1, 2)
    trace["ls2_left"] = bits_to_str(l2)
    trace["ls2_right"] = bits_to_str(r2)

    # Step 6: Generate Subkey K2 via P8
    k2 = permute(l2 + r2, P8)
    trace["k2"] = bits_to_str(k2)

    return k1, k2, trace


# ============================================================================
# SECTION 4: FEISTEL ROUND FUNCTION F(R, K)
# ============================================================================

def _sbox_lookup(nibble_4bit, sbox_table):
    """
    Performs non-linear S-box substitution on a 4-bit nibble.
    - Outer bits (bit 0 and bit 3) select the row (0 to 3).
    - Inner bits (bit 1 and bit 2) select the column (0 to 3).
    - Returns a 2-bit substituted value.
    """
    row = (nibble_4bit[0] << 1) | nibble_4bit[3]
    col = (nibble_4bit[1] << 1) | nibble_4bit[2]
    val = sbox_table[row][col]
    return [(val >> 1) & 1, val & 1]


def _round_function(right_4bit, subkey_8bit):
    """
    Executes the Feistel round function F(R, K):
    1. Expansion Permutation (EP): 4 bits -> 8 bits
    2. Bitwise XOR with subkey: EP(R) ^ Subkey
    3. Split 8-bit result: Left 4 bits -> S0, Right 4 bits -> S1
    4. Combine 2-bit S0 and 2-bit S1 outputs into 4 bits
    5. Permute through P4: P4(S0 || S1) -> 4 bits
    """
    # 1. Expand 4 bits to 8 bits
    ep = permute(right_4bit, EP)

    # 2. XOR with round subkey
    xored = [a ^ b for a, b in zip(ep, subkey_8bit)]

    # 3. S-box substitution
    s0_out = _sbox_lookup(xored[:4], S0)
    s1_out = _sbox_lookup(xored[4:], S1)

    # 4. P4 permutation
    p4_out = permute(s0_out + s1_out, P4)

    return p4_out, {
        "ep": bits_to_str(ep),
        "xor_key": bits_to_str(xored),
        "s0_out": bits_to_str(s0_out),
        "s1_out": bits_to_str(s1_out),
        "p4_out": bits_to_str(p4_out)
    }


# ============================================================================
# SECTION 5: BLOCK ENCRYPTION & DECRYPTION ENGINES
# ============================================================================

def encrypt_block_with_trace(pt_8bit, k1, k2):
    """
    Encrypts a single 8-bit plaintext block using S-DES with detailed tracing.

    Steps:
    1. Apply Initial Permutation (IP) -> (L0, R0)
    2. Round 1: L1 = L0 ^ F(R0, K1), R1 = R0
    3. Switch/Swap (SW): L_sw = R1, R_sw = L1
    4. Round 2: L2 = L_sw ^ F(R_sw, K2), R2 = R_sw (No swap)
    5. Pre-output = (L2 || R2)
    6. Apply Inverse IP (IP^-1) -> 8-bit Ciphertext
    """
    if isinstance(pt_8bit, str):
        pt_8bit = str_to_bits(pt_8bit)

    trace = {"pt": bits_to_str(pt_8bit)}

    # Step 1: Initial Permutation (IP)
    ip = permute(pt_8bit, IP)
    trace["ip"] = bits_to_str(ip)
    l0, r0 = ip[:4], ip[4:]
    trace["l0"] = bits_to_str(l0)
    trace["r0"] = bits_to_str(r0)

    # Step 2: Round 1 (Subkey K1)
    f1, f1_trace = _round_function(r0, k1)
    trace["r1_f"] = f1_trace
    l1 = [a ^ b for a, b in zip(l0, f1)]
    trace["r1_l1"] = bits_to_str(l1)

    # Step 3: Switch/Swap Halves (SW)
    l_sw, r_sw = r0, l1
    trace["sw_left"] = bits_to_str(l_sw)
    trace["sw_right"] = bits_to_str(r_sw)

    # Step 4: Round 2 (Subkey K2)
    f2, f2_trace = _round_function(r_sw, k2)
    trace["r2_f"] = f2_trace
    l2 = [a ^ b for a, b in zip(l_sw, f2)]
    trace["r2_l2"] = bits_to_str(l2)
    r2 = r_sw

    # Step 5: Pre-output (L2 + R2 without swap)
    pre_out = l2 + r2
    trace["pre_out"] = bits_to_str(pre_out)

    # Step 6: Inverse Initial Permutation (IP^-1)
    ct = permute(pre_out, IP_INV)
    trace["ct"] = bits_to_str(ct)

    return ct, trace


def decrypt_block_with_trace(ct_8bit, k1, k2):
    """
    Decrypts a single 8-bit ciphertext block using S-DES with detailed tracing.
    Decryption is identical to encryption except subkeys are applied in reverse:
    - Round 1 uses Subkey K2
    - Round 2 uses Subkey K1
    """
    if isinstance(ct_8bit, str):
        ct_8bit = str_to_bits(ct_8bit)

    trace = {"ct": bits_to_str(ct_8bit)}

    # Step 1: Initial Permutation (IP)
    ip = permute(ct_8bit, IP)
    trace["ip"] = bits_to_str(ip)
    l0, r0 = ip[:4], ip[4:]
    trace["l0"] = bits_to_str(l0)
    trace["r0"] = bits_to_str(r0)

    # Step 2: Round 1 (Subkey K2 for decryption)
    f1, f1_trace = _round_function(r0, k2)
    trace["r1_f"] = f1_trace
    l1 = [a ^ b for a, b in zip(l0, f1)]
    trace["r1_l1"] = bits_to_str(l1)

    # Step 3: Switch/Swap Halves (SW)
    l_sw, r_sw = r0, l1
    trace["sw_left"] = bits_to_str(l_sw)
    trace["sw_right"] = bits_to_str(r_sw)

    # Step 4: Round 2 (Subkey K1 for decryption)
    f2, f2_trace = _round_function(r_sw, k1)
    trace["r2_f"] = f2_trace
    l2 = [a ^ b for a, b in zip(l_sw, f2)]
    trace["r2_l2"] = bits_to_str(l2)
    r2 = r_sw

    # Step 5: Pre-output
    pre_out = l2 + r2
    trace["pre_out"] = bits_to_str(pre_out)

    # Step 6: Inverse Initial Permutation (IP^-1)
    pt = permute(pre_out, IP_INV)
    trace["pt"] = bits_to_str(pt)

    return pt, trace


# ============================================================================
# SECTION 6: STRING / MESSAGE LEVEL INTERFACES
# ============================================================================

def encrypt_message(message_str, key_10bit):
    """
    Encrypts an ASCII string using S-DES by converting each character into
    an 8-bit binary block. Returns the full ciphertext as a hex string.
    """
    k1, k2, key_trace = generate_subkeys(key_10bit)
    traces = []
    ct_bytes = bytearray()

    for idx, ch in enumerate(message_str):
        byte_val = ord(ch)
        pt_bits = [(byte_val >> (7 - i)) & 1 for i in range(8)]
        ct_bits, b_trace = encrypt_block_with_trace(pt_bits, k1, k2)
        b_trace["char"] = ch
        b_trace["byte_val"] = byte_val
        b_trace["block_idx"] = idx + 1
        traces.append(b_trace)

        # Convert 8 bits to byte
        out_byte = 0
        for b in ct_bits:
            out_byte = (out_byte << 1) | b
        ct_bytes.append(out_byte)

    return ct_bytes.hex(), traces, key_trace


def decrypt_message(ciphertext_hex, key_10bit):
    """
    Decrypts a hexadecimal ciphertext back to an ASCII string using S-DES.
    """
    k1, k2, key_trace = generate_subkeys(key_10bit)
    ct_bytes = bytes.fromhex(ciphertext_hex)
    traces = []
    recovered_chars = []

    for idx, byte_val in enumerate(ct_bytes):
        ct_bits = [(byte_val >> (7 - i)) & 1 for i in range(8)]
        pt_bits, b_trace = decrypt_block_with_trace(ct_bits, k1, k2)

        pt_val = 0
        for b in pt_bits:
            pt_val = (pt_val << 1) | b
        recovered_ch = chr(pt_val)

        b_trace["char"] = recovered_ch
        b_trace["byte_val"] = pt_val
        b_trace["block_idx"] = idx + 1
        traces.append(b_trace)
        recovered_chars.append(recovered_ch)

    return "".join(recovered_chars), traces, key_trace


# ============================================================================
# SECTION 7: INTERMEDIATE PROCESS FORMATTERS FOR ASSIGNMENT OUTPUT
# ============================================================================

def format_encryption_trace(traces, key_trace, max_blocks=3):
    """Formats intermediate encryption steps matching the assignment template."""
    lines = []
    lines.append("--- Intermediate Encryption Process ---")
    lines.append(f"1. Key Generation (10-bit key: {key_trace['key']}):")
    lines.append(f"   P10 Permutation: {key_trace['p10']} -> Left: {key_trace['p10_left']}, Right: {key_trace['p10_right']}")
    lines.append(f"   Left Shift 1 (LS-1): Left: {key_trace['ls1_left']}, Right: {key_trace['ls1_right']}")
    lines.append(f"   Subkey K1 (P8 applied): {key_trace['k1']}")
    lines.append(f"   Left Shift 2 (LS-2): Left: {key_trace['ls2_left']}, Right: {key_trace['ls2_right']}")
    lines.append(f"   Subkey K2 (P8 applied): {key_trace['k2']}")
    lines.append("")

    num_show = min(len(traces), max_blocks)
    lines.append(f"2. Block-by-Block S-DES Encryption (showing {num_show} of {len(traces)} block(s)):")
    for t in traces[:num_show]:
        lines.append(f"   [Block {t['block_idx']}: Char '{t['char']}' (ASCII {t['byte_val']} = {t['pt']})]")
        lines.append(f"     -> Initial Permutation (IP): {t['ip']} (L0: {t['l0']}, R0: {t['r0']})")
        lines.append(f"     -> Round 1 (Subkey K1={key_trace['k1']}):")
        lines.append(f"        EP(R0): {t['r1_f']['ep']} ^ K1 = {t['r1_f']['xor_key']}")
        lines.append(f"        S-boxes: S0->{t['r1_f']['s0_out']}, S1->{t['r1_f']['s1_out']} | P4: {t['r1_f']['p4_out']}")
        lines.append(f"        L0 ^ P4 = {t['r1_l1']} | After Swap (SW): Left={t['sw_left']}, Right={t['sw_right']}")
        lines.append(f"     -> Round 2 (Subkey K2={key_trace['k2']}):")
        lines.append(f"        EP(R_sw): {t['r2_f']['ep']} ^ K2 = {t['r2_f']['xor_key']}")
        lines.append(f"        S-boxes: S0->{t['r2_f']['s0_out']}, S1->{t['r2_f']['s1_out']} | P4: {t['r2_f']['p4_out']}")
        lines.append(f"        Pre-output: {t['pre_out']}")
        lines.append(f"     -> Inverse IP (IP^-1): {t['ct']}")
    if len(traces) > max_blocks:
        lines.append(f"   ... ({len(traces) - max_blocks} remaining block(s) encrypted similarly)")
    return "\n".join(lines)


def format_decryption_trace(traces, key_trace, max_blocks=3):
    """Formats intermediate decryption steps matching the assignment template."""
    lines = []
    lines.append("--- Intermediate Decryption Process ---")
    lines.append(f"1. Subkeys Used (K2 first, then K1):")
    lines.append(f"   Subkey K2: {key_trace['k2']}")
    lines.append(f"   Subkey K1: {key_trace['k1']}")
    lines.append("")

    num_show = min(len(traces), max_blocks)
    lines.append(f"2. Block-by-Block S-DES Decryption (showing {num_show} of {len(traces)} block(s)):")
    for t in traces[:num_show]:
        lines.append(f"   [Block {t['block_idx']}: Cipher bits {t['ct']}]")
        lines.append(f"     -> Initial Permutation (IP): {t['ip']} (L0: {t['l0']}, R0: {t['r0']})")
        lines.append(f"     -> Round 1 (Subkey K2={key_trace['k2']}):")
        lines.append(f"        EP(R0): {t['r1_f']['ep']} ^ K2 = {t['r1_f']['xor_key']}")
        lines.append(f"        S-boxes: S0->{t['r1_f']['s0_out']}, S1->{t['r1_f']['s1_out']} | P4: {t['r1_f']['p4_out']}")
        lines.append(f"        L0 ^ P4 = {t['r1_l1']} | After Swap (SW): Left={t['sw_left']}, Right={t['sw_right']}")
        lines.append(f"     -> Round 2 (Subkey K1={key_trace['k1']}):")
        lines.append(f"        EP(R_sw): {t['r2_f']['ep']} ^ K1 = {t['r2_f']['xor_key']}")
        lines.append(f"        S-boxes: S0->{t['r2_f']['s0_out']}, S1->{t['r2_f']['s1_out']} | P4: {t['r2_f']['p4_out']}")
        lines.append(f"        Pre-output: {t['pre_out']}")
        lines.append(f"     -> Inverse IP (IP^-1): {t['pt']} -> Decrypted Char: '{t['char']}' (ASCII {t['byte_val']})")
    if len(traces) > max_blocks:
        lines.append(f"   ... ({len(traces) - max_blocks} remaining block(s) decrypted similarly)")
    return "\n".join(lines)


if __name__ == "__main__":
    print("=== S-DES Module Verification (Author: Raghav Gupta, Roll No: 20243226) ===")
    test_key = "1010000010"
    test_msg = "CRYPTOGRAPHY"
    ct_hex, enc_traces, k_trace = encrypt_message(test_msg, test_key)
    recovered, dec_traces, _ = decrypt_message(ct_hex, test_key)
    assert recovered == test_msg
    print(f"Message:   '{test_msg}'")
    print(f"Key:       {test_key}")
    print(f"Cipher:    {ct_hex}")
    print(f"Recovered: '{recovered}'")
    print("\nVerification: SUCCESS! Decrypted message matches original perfectly.")
