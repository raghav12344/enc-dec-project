# Cryptography Assignment 1: Secure Client-Server Message Exchange

**Author:** Raghav Gupta  
**Roll Number:** 20243226  
**Department:** Computer Science and Engineering  
**Institution:** Motilal Nehru National Institute of Technology (MNNIT) Allahabad  
**Submission:** Assignment 1 - Secure Client-Server Message Protocol  

---

## 1. Algorithm Selection Mapping

Based on the assignment formula using Roll Number **20243226**:

1. **Symmetric Key Algorithm:**
   $$\text{RollNo} \pmod 3 = 20243226 \pmod 3 = 0 \implies \mathbf{Simplified\ DES\ (S\text{-}DES)}$$
2. **Asymmetric Key Algorithm:**
   $$\text{RollNo} \pmod 2 = 20243226 \pmod 2 = 0 \implies \mathbf{RSA}$$
3. **Hashing Algorithm:**
   $$\mathbf{Whirlpool\ Hash\ Algorithm\ (Created\ from\ Scratch)}$$

---

## 2. System Architecture & Message Flow

```
+------------------------------------------------------------------------------+
|                                    CLIENT                                    |
| 1. Generate Client RSA Keypair: (e_client, n_client) & (d_client, n_client)  |
| 2. Request Server's Public Key -----------------------------------+         |
|                                                                   |          |
+-------------------------------------------------------------------|----------+
                                                                    |
                                        [REQUEST_SERVER_PUBLIC_KEY] |
                                                                    v
+------------------------------------------------------------------------------+
|                                    SERVER                                    |
| 1. Generate Server RSA Keypair: (e_server, n_server) & (d_server, n_server)  |
| 2. Listen on Port (default 12345)                                            |
| 3. Send Server Public Key (e_server, n_server) -------------------+          |
+-------------------------------------------------------------------|----------+
                                                                    |
                                            [SERVER_PUBLIC_KEY]     |
                                                                    v
+------------------------------------------------------------------------------+
|                                    CLIENT                                    |
| 3. Encrypt 10-bit Secret Key with Server RSA Public Key:                     |
|    Encrypted_Secret_Key = (Secret_Key ^ e_server) mod n_server               |
| 4. Encrypt Message with S-DES using 10-bit Secret Key:                       |
|    Ciphertext = S_DES_Encrypt(Message, Secret_Key)                           |
| 5. Compute Message Digest using Whirlpool from scratch:                      |
|    Hash_Code = Whirlpool(Message)                                            |
| 6. Compute Digital Signature with Client RSA Private Key:                    |
|    Digital_Signature = (Hash_Code ^ d_client) mod n_client                   |
| 7. Send Bundle to Server: ----------------------------------------+          |
|    [Ciphertext + Encrypted Secret Key + Signature + Client Public Key]       |
+-------------------------------------------------------------------|----------+
                                                                    |
                                        [SECURE PAYLOAD BUNDLE]     |
                                                                    v
+------------------------------------------------------------------------------+
|                                    SERVER                                    |
| 4. Decrypt Secret Key with Server RSA Private Key:                           |
|    Secret_Key = (Encrypted_Secret_Key ^ d_server) mod n_server               |
| 5. Decrypt Ciphertext with S-DES using decrypted Secret Key:                 |
|    Decrypted_Message = S_DES_Decrypt(Ciphertext, Secret_Key)                 |
| 6. Compute Whirlpool Hash of Decrypted Message:                              |
|    Computed_Hash = Whirlpool(Decrypted_Message)                              |
| 7. Verify Client Digital Signature using Client RSA Public Key:              |
|    Verification_Code = (Digital_Signature ^ e_client) mod n_client           |
|    Check: Verification_Code == Computed_Hash                                 |
| 8. Status: Signature <valid/invalid>, Message <Accepted/Rejected>            |
| 9. Send ACK back to Client                                                   |
+------------------------------------------------------------------------------+
```

---

## 3. Repository File Structure & Function Directory

| File | Description |
| :--- | :--- |
| `main.py` | Master interactive control panel with numbered menu for one-click demo, server, client, tests, and packaging. |
| `run.bat` | One-click Windows batch script to launch the project directly from File Explorer. |
| `.vscode/` | VS Code launch configurations (`launch.json`) and task definitions (`tasks.json`) for F5 debugging and one-click execution. |
| `whirlpool.py` | Complete from-scratch implementation of ISO/IEC 10118-3 Whirlpool hash function (no third-party dependencies). |
| `sdes.py` | Complete implementation of Simplified DES (S-DES) with full intermediate process logging. |
| `rsa.py` | Complete RSA asymmetric cryptosystem with Miller-Rabin primality testing, key generation, encryption, decryption, and signature verification. |
| `server.py` | Standalone command-line server implementing TCP socket listener, payload decryption, signature verification, and formatted reporting. |
| `client.py` | Standalone command-line client implementing interactive/automated inputs, key generation, encryption, signing, and transmission. |
| `test_suite.py` | Comprehensive automated test suite verifying S-DES, Whirlpool test vectors, RSA arithmetic, and socket communications. |
| `run_demo.py` | Script that executes the client and server end-to-end, logs stdout to text files, and generates execution screenshots. |
| `client_output.txt` | Captured console output for Client execution. |
| `server_output.txt` | Captured console output for Server execution. |
| `client_execution_screenshot.png` | Terminal execution window screenshot for Client. |
| `server_execution_screenshot.png` | Terminal execution window screenshot for Server. |

---

## 4. Detailed Function Explanations

### `whirlpool.py`
- `_gf_mul(a, b)`: Galois Field $GF(2^8)$ multiplication with irreducible reduction polynomial $x^8 + x^4 + x^3 + x^2 + 1$ (`0x11D`).
- `_build_tables()`: Precomputes the 8 64-bit circular round transformation lookup tables ($C_0 \dots C_7$) combining the non-linear substitution layer (S-box), column shift permutation, and matrix diffusion layer.
- `Whirlpool.__init__(message)`: Initializes 512-bit state vector, internal buffer, and bit-length counter.
- `Whirlpool.update(data)`: Feeds incoming byte data into 64-byte blocks and invokes `_transform`.
- `Whirlpool._transform(block)`: Executes the 10-round $W$ block cipher using the Miyaguchi-Preneel compression function:
  $$H_i = W(H_{i-1}, m_i) \oplus H_{i-1} \oplus m_i$$
- `Whirlpool.digest()`: Appends ISO padding ('1' bit, zeros, and 256-bit big-endian representation of original length) and finalizes the 64-byte digest.
- `Whirlpool.hexdigest()`: Returns the 512-bit digest as a 128-character hexadecimal string.
- `whirlpool_hash(data)`: Helper utility to hash any string or byte array in a single call.

### `sdes.py`
- `permute(bits, table)`: Reorders bit arrays according to 1-indexed permutation tables (`P10`, `P8`, `IP`, `IP_INV`, `EP`, `P4`).
- `left_shift(bits, n)`: Performs circular left shift by $n$ bit positions.
- `generate_subkeys(key_10bit)`: Derives two 8-bit subkeys ($K_1, K_2$) from a 10-bit master key using `P10`, circular left shifts (`LS-1`, `LS-2`), and `P8`.
- `_sbox_lookup(nibble, sbox_table)`: Computes row from outer bits (bits 1 and 4) and column from inner bits (bits 2 and 3) to retrieve 2 output bits from $S_0$ or $S_1$.
- `_round_function(right_4bit, subkey_8bit)`: Feistel round function $F(R, K)$ applying Expansion Permutation (`EP`), key XOR, S-box substitution, and `P4` permutation.
- `encrypt_block_with_trace(pt_8bit, k1, k2)`: Encrypts 8-bit plaintext block through `IP`, Round 1 ($K_1$), Halves Swap (`SW`), Round 2 ($K_2$), and `IP^-1`, collecting granular traces of every intermediate step.
- `decrypt_block_with_trace(ct_8bit, k1, k2)`: Decrypts 8-bit ciphertext block through `IP`, Round 1 ($K_2$), Halves Swap (`SW`), Round 2 ($K_1$), and `IP^-1`.
- `encrypt_message(message_str, key_10bit)`: Encrypts multi-character ASCII strings block-by-block.
- `decrypt_message(ciphertext_hex, key_10bit)`: Decrypts hexadecimal ciphertexts back into original ASCII strings.
- `format_encryption_trace(traces, key_trace)`: Formats step-by-step intermediate encryption details for display.
- `format_decryption_trace(traces, key_trace)`: Formats step-by-step intermediate decryption details for display.

### `rsa.py`
- `extended_gcd(a, b)`: Extended Euclidean Algorithm computing greatest common divisor and Bézout coefficients.
- `mod_inverse(e, phi)`: Computes private modular inverse exponent $d \equiv e^{-1} \pmod{\phi(n)}$.
- `is_prime(n, k=40)`: Miller-Rabin probabilistic primality test with 40 rounds of witnesses.
- `generate_prime(bits=280)`: Generates cryptographically sound random primes of specified bit length.
- `generate_keypair_from_primes(p, q, e=65537)`: Calculates $n = p \times q$, $\phi(n) = (p-1)(q-1)$, verifies coprime condition, and computes $d$.
- `generate_rsa_keys(bits=280, e=65537)`: Generates complete RSA keypair with modulus $n > 2^{512}$ to naturally handle 512-bit Whirlpool digests directly.
- `encrypt_rsa(plaintext_int, public_key)`: Encrypts integer $m$ via modular exponentiation: $c = m^e \pmod n$.
- `decrypt_rsa(ciphertext_int, private_key)`: Decrypts ciphertext integer $c$ via modular exponentiation: $m = c^d \pmod n$.
- `sign_digest(digest_hex_or_int, private_key)`: Computes RSA digital signature over hash digest: $S = H^d \pmod n$.
- `verify_digest_signature(signature, expected_digest, public_key)`: Computes verification code $V = S^e \pmod n$ and verifies authenticity against expected hash.

### `server.py`
- `run_server(host, port, ...)`: Coordinates socket initialization, key generation, public key delivery, payload reception, secret key RSA decryption, S-DES message decryption, Whirlpool hash calculation, signature verification, and strictly formatted console reporting.

### `client.py`
- `run_client(host, port, message, secret_key, ...)`: Coordinates socket connection, server public key retrieval, secret key RSA encryption, S-DES message encryption, Whirlpool hash calculation, digital signature generation, payload bundle transmission, and strictly formatted console reporting.

---

## 5. Execution Instructions (Command Line)

The project is implemented entirely in standard Python 3 with **zero external package requirements**.

### Running the Server:
Open a terminal / command prompt and run:
```bash
py server.py --port 12345
```
*(Optional flags: `--host`, `--port`, `--p`, `--q`, `--e`)*

### Running the Client:
Open a second terminal / command prompt and run:
```bash
py client.py --port 12345
```
*(Optional flags: `--message "YOUR MESSAGE"`, `--key 1010000010`, `--interactive`)*

### Running the Automated Test Suite:
```bash
py test_suite.py
```

### Running the Demo & Screenshot Generator:
```bash
py run_demo.py
```

---

## 6. Sample Output Verification

### Client Side:
```
Client Side:
Input: Message: <ANTIGRAVITY SECURE PROTOCOL - RAGHAV GUPTA (20243226)>
Secret Key: <1010000010> (integer: 642)
Public Key parameters: (e=65537, n=1414619119789195648366439989948751329219586354582150811391082184793843398519446195257469136238930506151763430508881520155914590976147291059348245947042419460237033248793)
Private key parameters: (d=292606875320236449780360109613581229212516786284322388867624549446348491849331104915969578977230070779908606743171211251204799151247015400231880911686391020542712541777, n=1414619119789195648366439989948751329219586354582150811391082184793843398519446195257469136238930506151763430508881520155914590976147291059348245947042419460237033248793)
Encrypted Secret Key: <27535575404219596719712410773485120554274132088873023815659622460709890076005307468049078155651912431533460712256819191721379029452947615821789578162957770966087835597>

Intermediate encryption process:
--- Intermediate Encryption Process ---
1. Key Generation (10-bit key: 1010000010):
   P10 Permutation: 1000001100 -> Left: 10000, Right: 01100
   Left Shift 1 (LS-1): Left: 00001, Right: 11000
   Subkey K1 (P8 applied): 10100100
   Left Shift 2 (LS-2): Left: 00100, Right: 00011
   Subkey K2 (P8 applied): 01000011

2. Block-by-Block S-DES Encryption (showing 3 of 53 block(s)):
   [Block 1: Char 'A' (ASCII 65 = 01000001)]
     -> Initial Permutation (IP): 10000100 (L0: 1000, R0: 0100)
     -> Round 1 (Subkey K1=10100100):
        EP(R0): 00101000 ^ K1 = 10001100
        S-boxes: S0->00, S1->01 | P4: 0100
        L0 ^ P4 = 1100 | After Swap (SW): Left=0100, Right=1100
     -> Round 2 (Subkey K2=01000011):
        EP(R_sw): 01101001 ^ K2 = 00101010
        S-boxes: S0->00, S1->00 | P4: 0000
        Pre-output: 01001100
     -> Inverse IP (IP^-1): 00010101
   ...

Cipher text: <15b222af019f153aaf22aa624f5044c19f5062a39f4722474447a56236629f1501e0153a6201c1a3221562dc231f23ba732323a293>
Hash code: <fd7b348520c15e0a64618da2abd975bf6dd4991bb06c20cf8bf7a72f80ab84e5210e5ed41a314fba9d471a5150d8f17aad64766dd1bf8bb39afce8e8b8a075ad>
Digital Signature: <1196850174425335996620642141383777095915052422921150604922165174064005122335396726622619572881512853048012004008047184393010087772441384041170849518399153024753790393247>
```

### Server Side:
```
Server Side:
Input: Public Key parameters: (e=65537, n=2423798548860765760040562872152925396393896995348787681268917065207347503245451823176969367834795381184142089174392651492496844298527623500350274629419878043242667614543)
       Private key parameters: (d=636599850794823703062059732950368568108521125180259736601948051381876994268336393675199823741140388072449902658657447877908212017734777112800433839666256039447126180713, n=2423798548860765760040562872152925396393896995348787681268917065207347503245451823176969367834795381184142089174392651492496844298527623500350274629419878043242667614543)
Decrypted Secret key: 1010000010 (integer: 642)

Intermediate decryption process:
--- Intermediate Decryption Process ---
1. Subkeys Used (K2 first, then K1):
   Subkey K2: 01000011
   Subkey K1: 10100100

2. Block-by-Block S-DES Decryption (showing 3 of 53 block(s)):
   [Block 1: Cipher bits 00010101]
     -> Initial Permutation (IP): 01001100 (L0: 0100, R0: 1100)
     -> Round 1 (Subkey K2=01000011):
        EP(R0): 01101001 ^ K2 = 00101010
        S-boxes: S0->00, S1->00 | P4: 0000
        L0 ^ P4 = 0100 | After Swap (SW): Left=1100, Right=0100
     -> Round 2 (Subkey K1=10100100):
        EP(R_sw): 00101000 ^ K1 = 10001100
        S-boxes: S0->00, S1->01 | P4: 0100
        Pre-output: 10000100
     -> Inverse IP (IP^-1): 01000001 -> Decrypted Char: 'A' (ASCII 65)
   ...

Decrypt Message: ANTIGRAVITY SECURE PROTOCOL - RAGHAV GUPTA (20243226)
Hash code: fd7b348520c15e0a64618da2abd975bf6dd4991bb06c20cf8bf7a72f80ab84e5210e5ed41a314fba9d471a5150d8f17aad64766dd1bf8bb39afce8e8b8a075ad
Verification code: fd7b348520c15e0a64618da2abd975bf6dd4991bb06c20cf8bf7a72f80ab84e5210e5ed41a314fba9d471a5150d8f17aad64766dd1bf8bb39afce8e8b8a075ad
Signature: <valid>
Message: <Accepted>
```

---

## 7. Submission Checklist Verification

- [x] Platform-independent, command-line executable (Pure Python 3 standard library).
- [x] Author's name (**Raghav Gupta**) and roll number (**20243226**) in comments in every code file.
- [x] Comprehensive `README.md` explaining all functions, algorithms, and executions.
- [x] Sample output text files (`client_output.txt`, `server_output.txt`) reflecting author details.
- [x] Execution window screenshot files (`client_execution_screenshot.png`, `server_execution_screenshot.png`).
- [x] Formatted strictly according to the format required on Page 2 and Page 3.
- [x] Packaged zip file named `20243226_Raghav_Gupta.zip`.
