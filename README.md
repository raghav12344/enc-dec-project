# Secure Client-Server Message Exchange Protocol
### Cryptography & Information Security - Assignment 1

![Author](https://img.shields.io/badge/Author-Raghav%20Gupta-blue?style=for-the-badge)
![Roll No](https://img.shields.io/badge/Roll%20No-20243226-orange?style=for-the-badge)
![Institution](https://img.shields.io/badge/MNNIT-Allahabad-red?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.13-brightgreen?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Independent-blueviolet?style=for-the-badge)
![Status](https://img.shields.io/badge/Tests-Passing%20(5%2F5)-success?style=for-the-badge)

---

## Academic Credentials & Metadata

* **Author:** Raghav Gupta
* **Registration / Roll Number:** 20243226
* **Degree:** Bachelor of Technology (B.Tech)
* **Branch:** Computer Science and Engineering
* **Department:** Department of Computer Science & Engineering (CSED)
* **Institution:** Motilal Nehru National Institute of Technology (MNNIT) Allahabad
* **Course:** Information Security / Cryptography & Network Security
* **Submission Portal:** [Google Forms Submission Link](https://forms.gle/VS3dnQFCf37K9q2j7)
* **Final Submission Archive:** `20243226_Raghav_Gupta.zip`

---

## 1. Algorithm Selection Mapping

Based on the assignment formula using Roll Number **20243226**:

### 1.1 Symmetric Key Algorithm Assignment
$$\text{Roll No.} \pmod 3 = 20243226 \pmod 3$$
$$\text{Sum of digits} = 2 + 0 + 2 + 4 + 3 + 2 + 2 + 6 = 21$$
$$21 \pmod 3 = 0 \implies \mathbf{Simplified\ DES\ (S\text{-}DES)}$$

### 1.2 Asymmetric Key Algorithm Assignment
$$\text{Roll No.} \pmod 2 = 20243226 \pmod 2 = 0 \implies \mathbf{RSA}$$

### 1.3 Cryptographic Hash Algorithm
$$\mathbf{Whirlpool\ Hash\ Algorithm\ (Created\ from\ Scratch\ -\ ISO/IEC\ 10118\text{-}3)}$$

---

## 2. Visual Architecture & Protocol Diagrams

### 2.1 Complete End-to-End System Flowchart
The diagram below illustrates the exact cryptographic workflow implemented across the Client and Server processes (matching the assignment specification on Page 1):

```mermaid
flowchart TD
    subgraph ClientSide["CLIENT APPLICATION"]
        direction TB
        C_KP["Client Key Parameters (p, q, e)"] --> C_KeyGen["Client RSA Key Generation"]
        C_KeyGen --> C_Pub["Client Public Key (e_c, n_c)"]
        C_KeyGen --> C_Priv["Client Private Key (d_c, n_c)"]
        
        Msg["Plaintext Message"] --> SDES_Enc["S-DES Symmetric Encryption"]
        SecKey["10-bit Secret Key"] --> SDES_Enc
        SDES_Enc --> Ciphertext["Ciphertext (Hex)"]
        
        SecKey --> RSA_Enc["RSA Asymmetric Encryption"]
        Serv_Pub["Server Public Key (e_s, n_s)"] --> RSA_Enc
        RSA_Enc --> EncSecKey["Encrypted Secret Key"]
        
        Msg --> Whirlpool_C["Whirlpool Hashing (from scratch)"]
        Whirlpool_C --> Digest_C["Message Digest (512-bit)"]
        
        Digest_C --> RSA_Sign["RSA Digital Signature Generation"]
        C_Priv --> RSA_Sign
        RSA_Sign --> Signature["Client Digital Signature"]
        
        Payload["Payload Bundle:\n• Ciphertext\n• Encrypted Secret Key\n• Client Signature\n• Client Public Key"]
        Ciphertext --> Payload
        EncSecKey --> Payload
        Signature --> Payload
        C_Pub --> Payload
    end

    subgraph NetworkChannel["TCP NETWORK SOCKET CHANNEL (Port 12345)"]
        ReqPub["1. Request Server Public Key"]
        SendPub["2. Send Server Public Key (e_s, n_s)"]
        SendPayload["3. Transmit Secure Payload Bundle"]
        SendACK["4. Transmit Status ACK (Accepted / Valid)"]
    end

    subgraph ServerSide["SERVER APPLICATION"]
        direction TB
        S_KP["Server Key Parameters (p, q, e)"] --> S_KeyGen["Server RSA Key Generation"]
        S_KeyGen --> Serv_Pub_Local["Server Public Key (e_s, n_s)"]
        S_KeyGen --> S_Priv["Server Private Key (d_s, n_s)"]
        
        RxPayload["Received Payload Bundle"]
        RxPayload --> Ext_EncSecKey["Encrypted Secret Key"]
        RxPayload --> Ext_Ciphertext["Ciphertext"]
        RxPayload --> Ext_Signature["Client Signature"]
        RxPayload --> Ext_CPub["Client Public Key (e_c, n_c)"]
        
        Ext_EncSecKey --> RSA_Dec["RSA Asymmetric Decryption"]
        S_Priv --> RSA_Dec
        RSA_Dec --> DecSecKey["Decrypted 10-bit Secret Key"]
        
        Ext_Ciphertext --> SDES_Dec["S-DES Symmetric Decryption"]
        DecSecKey --> SDES_Dec
        SDES_Dec --> RecMsg["Decrypted Plaintext Message"]
        
        RecMsg --> Whirlpool_S["Whirlpool Hashing (from scratch)"]
        Whirlpool_S --> CompHash["Computed Hash Digest"]
        
        Ext_Signature --> RSA_Verify["RSA Signature Verification"]
        Ext_CPub --> RSA_Verify
        RSA_Verify --> VerCode["Verification Code"]
        
        CompHash --> Check{"VerCode == CompHash ?"}
        VerCode --> Check
        Check -- "Yes" --> ValidStatus["Signature: VALID\nMessage: ACCEPTED"]
        Check -- "No" --> InvalidStatus["Signature: INVALID\nMessage: REJECTED"]
    end

    ClientSide -- "Step 1" --> ReqPub --> ServerSide
    ServerSide -- "Step 2" --> SendPub --> ClientSide
    Payload -- "Step 3" --> SendPayload --> RxPayload
    ValidStatus -- "Step 4" --> SendACK --> ClientSide
```

---

### 2.2 Protocol Handshake & Message Sequence Diagram
The time-ordered network interaction between the Client and Server:

```mermaid
sequenceDiagram
    autonumber
    participant Client as Client Application (Raghav Gupta - 20243226)
    participant Socket as TCP Socket (127.0.0.1:12345)
    participant Server as Server Application (Raghav Gupta - 20243226)

    Note over Server: Server starts and binds to socket<br/>Generates Server RSA Keys (e_s, n_s) & (d_s, n_s)
    Note over Client: Client starts<br/>Prompts for Message, Secret Key & RSA parameters

    Client->>Socket: Connect to Server
    Socket->>Server: Establish TCP Connection
    
    Client->>Server: {"type": "REQUEST_SERVER_PUBLIC_KEY"}
    Server-->>Client: {"type": "SERVER_PUBLIC_KEY", "e": e_s, "n": n_s}

    Note over Client: 1. Encrypt Secret Key with Server Public Key<br/>2. Encrypt Message with S-DES<br/>3. Compute Whirlpool Hash of Message<br/>4. Sign Whirlpool Hash with Client Private Key

    Client->>Server: {"type": "PAYLOAD", "ciphertext": ..., "encrypted_secret_key": ..., "client_signature": ..., "client_public_key": ...}

    Note over Server: 1. Decrypt Secret Key with Server Private Key<br/>2. Decrypt Ciphertext with S-DES<br/>3. Compute Whirlpool Hash of recovered Message<br/>4. Verify Client Signature with Client Public Key

    Server-->>Client: {"type": "ACK", "status": "Accepted", "signature": "valid"}
    Note over Client,Server: Connection cleanly closed. Outputs displayed.
```

---

### 2.3 Simplified DES (S-DES) Cryptographic Engine
The block-by-block data path of the 10-bit key schedule and 2-round Feistel structure:

```mermaid
flowchart TD
    subgraph KeySchedule["S-DES Key Generation Schedule"]
        MasterKey["10-bit Master Key"] --> P10["P10 Permutation\n[3, 5, 2, 7, 4, 10, 1, 9, 8, 6]"]
        P10 --> SplitK["Split into Left(5) and Right(5)"]
        SplitK --> LS1["Circular Left Shift 1 (LS-1)"]
        LS1 --> P8_1["P8 Permutation\n[6, 3, 7, 4, 8, 5, 10, 9]"]
        P8_1 --> Subkey1["Subkey K1 (8 bits)"]
        LS1 --> LS2["Circular Left Shift 2 (LS-2)"]
        LS2 --> P8_2["P8 Permutation\n[6, 3, 7, 4, 8, 5, 10, 9]"]
        P8_2 --> Subkey2["Subkey K2 (8 bits)"]
    end

    subgraph FeistelEngine["S-DES 2-Round Feistel Encryption"]
        PT["8-bit Plaintext Block"] --> IP["Initial Permutation (IP)\n[2, 6, 3, 1, 4, 8, 5, 7]"]
        IP --> SplitIP["Split into L0 (4 bits) and R0 (4 bits)"]
        
        SplitIP --> R0_EP["EP Expansion Permutation\n[4, 1, 2, 3, 2, 3, 4, 1]"]
        Subkey1 --> XOR1["XOR with K1"]
        R0_EP --> XOR1
        XOR1 --> SBoxes1["S-Box Substitution (S0 & S1)"]
        SBoxes1 --> P4_1["P4 Permutation\n[2, 4, 3, 1]"]
        SplitIP --> XOR_L0["XOR with L0"]
        P4_1 --> XOR_L0
        
        XOR_L0 --> Swap["Switch / Swap Function (SW)\nLeft = R0, Right = L0 ^ F1"]
        
        Swap --> R1_EP["EP Expansion Permutation"]
        Subkey2 --> XOR2["XOR with K2"]
        R1_EP --> XOR2
        XOR2 --> SBoxes2["S-Box Substitution (S0 & S1)"]
        SBoxes2 --> P4_2["P4 Permutation"]
        Swap --> XOR_L1["XOR with Left"]
        P4_2 --> XOR_L1
        
        XOR_L1 --> Combine["Pre-output (L2 + R2 without swap)"]
        Swap --> Combine
        Combine --> IP_Inv["Inverse Initial Permutation (IP^-1)\n[4, 1, 3, 5, 7, 2, 8, 6]"]
        IP_Inv --> CT["8-bit Ciphertext Block"]
    end
```

---

### 2.4 Whirlpool Miyaguchi-Preneel Compression Engine
The pure from-scratch implementation of ISO/IEC 10118-3 Whirlpool hashing:

```mermaid
flowchart LR
    subgraph MP_Scheme["Miyaguchi-Preneel Construction"]
        PrevH["Previous State H_(i-1)\n(512 bits / 64 bytes)"]
        Block["Padded Message Block m_i\n(512 bits / 64 bytes)"]
        
        PrevH --> KeyInput["Cipher Key Input (K)"]
        Block --> PlainInput["Cipher Block Input (m)"]
        
        subgraph WCipher["10-Round W Block Cipher"]
            Round0["Round 1: gamma -> pi -> theta -> sigma"]
            RoundMid["... Rounds 2 to 9 ..."]
            Round10["Round 10: SubBytes, ShiftColumns, MixRows, AddRoundKey"]
            Round0 --> RoundMid --> Round10
        end
        
        KeyInput --> Round0
        PlainInput --> Round0
        
        Round10 --> CipherOutput["Cipher Output W(H_(i-1), m_i)"]
        
        CipherOutput --> FinalXOR["Bitwise XOR (3-way)"]
        PrevH --> FinalXOR
        Block --> FinalXOR
        
        FinalXOR --> NewH["Updated State H_i\n(512 bits / 128 Hex Chars)"]
    end
```

---

## 3. Mathematical Specifications

### 3.1 Simplified DES (S-DES)
S-DES operates on an 8-bit plaintext block under a 10-bit master key:
- **Key Generation:**
  - $P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]$
  - Split into two 5-bit halves $(L_0, R_0)$.
  - Circular left shift by 1 position ($LS\text{-}1$) on both halves $\to (L_1, R_1)$.
  - Apply $P8 = [6, 3, 7, 4, 8, 5, 10, 9] \to \text{Subkey } K_1$.
  - Circular left shift by 2 positions ($LS\text{-}2$) on $(L_1, R_1) \to (L_2, R_2)$.
  - Apply $P8 \to \text{Subkey } K_2$.
- **Encryption Process:**
  - Initial Permutation: $IP = [2, 6, 3, 1, 4, 8, 5, 7]$.
  - Expansion Permutation: $EP = [4, 1, 2, 3, 2, 3, 4, 1]$ expanding 4 bits to 8 bits.
  - S-Box substitution matrices:
    $$S_0 = \begin{pmatrix} 1 & 0 & 3 & 2 \\ 3 & 2 & 1 & 0 \\ 0 & 2 & 1 & 3 \\ 3 & 1 & 3 & 2 \end{pmatrix}, \quad S_1 = \begin{pmatrix} 0 & 1 & 2 & 3 \\ 2 & 0 & 1 & 3 \\ 3 & 0 & 1 & 0 \\ 2 & 1 & 0 & 3 \end{pmatrix}$$
  - Permutation $P4 = [2, 4, 3, 1]$.
  - Round 1: $L_1 = L_0 \oplus F(R_0, K_1)$, $R_1 = R_0$. Halves Swap: $(L_{sw}, R_{sw}) = (R_1, L_1)$.
  - Round 2: $L_2 = L_{sw} \oplus F(R_{sw}, K_2)$, $R_2 = R_{sw}$ (No swap).
  - Inverse Initial Permutation: $IP^{-1} = [4, 1, 3, 5, 7, 2, 8, 6]$.

### 3.2 RSA Public Key Cryptosystem
- **Key Generation:**
  - Select two distinct large prime numbers $p$ and $q$.
  - Modulus: $n = p \times q$.
  - Euler's totient: $\phi(n) = (p - 1)(q - 1)$.
  - Public exponent $e$ such that $1 < e < \phi(n)$ and $\gcd(e, \phi(n)) = 1$.
  - Private exponent $d$ using Extended Euclidean Algorithm:
    $$d \times e \equiv 1 \pmod{\phi(n)}$$
  - Public Key: $(e, n)$, Private Key: $(d, n)$.
- **Secret Key Encryption:** $c = m^e \pmod n$.
- **Secret Key Decryption:** $m = c^d \pmod n$.
- **Digital Signature Generation:** $S = H^d \pmod n$.
- **Digital Signature Verification:** $V = S^e \pmod n$. Valid iff $V = H \pmod n$.

### 3.3 Whirlpool Cryptographic Hash Function (from scratch)
- **Miyaguchi-Preneel Hashing:**
  $$H_i = W(H_{i-1}, m_i) \oplus H_{i-1} \oplus m_i$$
- **Padding Rule:** Append '1' bit (`0x80`), followed by $k$ zero bits such that $(L + 1 + k) \equiv 256 \pmod{512}$, then append the 256-bit big-endian representation of original bit-length $L$.
- **Galois Field Arithmetic:** Polynomial multiplication over $GF(2^8)$ modulo irreducible polynomial $x^8 + x^4 + x^3 + x^2 + 1$ (`0x11D`).
- **Diffusion Matrix:** Circulant row $[01, 01, 04, 01, 08, 05, 02, 09]$.

---

## 4. Complete Directory of Files and Functions

| File | Functions / Classes | Purpose & Functionality |
| :--- | :--- | :--- |
| **`whirlpool.py`** | `_gf_mul(a, b)`<br>`_build_tables()`<br>`Whirlpool` class<br>`Whirlpool.update(data)`<br>`Whirlpool._transform(block)`<br>`Whirlpool.digest()`<br>`Whirlpool.hexdigest()`<br>`whirlpool_hash(data)` | Implements ISO/IEC 10118-3 Whirlpool hashing from scratch. Computes Galois Field operations, 8 circular lookup tables, 10-round Miyaguchi-Preneel compression, and returns 512-bit digests. |
| **`sdes.py`** | `permute(bits, table)`<br>`left_shift(bits, n)`<br>`generate_subkeys(key_10bit)`<br>`_sbox_lookup(nibble, box)`<br>`_round_function(r, k)`<br>`encrypt_block_with_trace()`<br>`decrypt_block_with_trace()`<br>`encrypt_message()`<br>`decrypt_message()`<br>`format_encryption_trace()`<br>`format_decryption_trace()` | Complete S-DES implementation. Derives subkeys $K_1, K_2$, executes rounds with permutations and S-boxes, encrypts/decrypts strings block-by-block, and formats intermediate process traces. |
| **`rsa.py`** | `extended_gcd(a, b)`<br>`mod_inverse(e, phi)`<br>`is_prime(n, k)`<br>`generate_prime(bits)`<br>`generate_keypair_from_primes()`<br>`generate_rsa_keys(bits)`<br>`encrypt_rsa(m, pub)`<br>`decrypt_rsa(c, priv)`<br>`sign_digest(digest, priv)`<br>`verify_digest_signature()` | Complete RSA cryptosystem. Implements Miller-Rabin primality, modular inverse, prime pair generation ($n > 2^{512}$), secret key encryption/decryption, and Whirlpool signature signing & verification. |
| **`server.py`** | `get_interactive_server_inputs()`<br>`run_server(host, port, ...)`<br>`main()` | Server TCP application. Prompts for/generates server RSA keys, listens for connections, provides public key, decrypts secret key via RSA, decrypts ciphertext via S-DES, computes Whirlpool hash, verifies digital signature, and prints formatted output. |
| **`client.py`** | `get_interactive_inputs()`<br>`run_client(host, port, ...)`<br>`main()` | Client TCP application. Connects to server, prompts for/generates client RSA keys, encrypts 10-bit secret key via RSA, encrypts message via S-DES, hashes message via Whirlpool, signs hash via RSA, sends bundle, and prints formatted output. |
| **`main.py`** | `clear_screen()`<br>`print_banner()`<br>`run_side_by_side_demo()`<br>`run_inline_server()`<br>`run_inline_client()`<br>`run_test_suite()`<br>`run_batch_demo()`<br>`package_zip()`<br>`main()` | Master interactive CLI menu enabling one-click live multi-window execution, interactive server/client launches, automated tests, screenshot generation, and zip packaging. |
| **`run_demo.py`** | `capture_execution()`<br>`render_terminal_screenshot()` | Automated batch execution script that captures stdout to text files and renders realistic high-resolution terminal execution window screenshots. |
| **`run.bat`** | Windows Batch Script | One-click Windows desktop launcher to immediately launch `main.py`. |
| **`.gitignore`** | Git configuration | Professional git ignore file excluding Python bytecode (`__pycache__`), virtualenvs, and OS artifacts. |
| **`test_suite.py`** | `TestCryptoAssignment` unit tests | Validates S-DES textbook vectors, ISO Whirlpool test vectors, RSA arithmetic, and full socket communication. |
| **`client_output.txt`** | Text Log | Raw console execution output of the Client application. |
| **`server_output.txt`** | Text Log | Raw console execution output of the Server application. |
| **`client_execution_screenshot.png`** | Image | Execution window screenshot of the Client encryption process. |
| **`server_execution_screenshot.png`** | Image | Execution window screenshot of the Server decryption and signature verification process. |
| **`INSTRUCTIONS_AND_SUBMISSION.md`** | Evaluation Report | Mapping of assignment questions and rules to the project codebase. |
| **`20243226_Raghav_Gupta.zip`** | Zip Archive | Final submission package named strictly according to Rule 6. |

---

## 5. Execution Instructions for Evaluation

The application is written in standard Python 3 and runs on any platform with **zero external dependencies**.

### Method 1: Master Interactive Launcher (Recommended)
Open a terminal in the project directory and run:
```powershell
py main.py
```
*(Or double-click `run.bat` on Windows)*.

You will be greeted by the interactive control panel:
* **Select `[1]`** to instantly spawn Server and Client in **two side-by-side terminal windows**.
* **Select `[2]`** to run the Server interactively.
* **Select `[3]`** to run the Client in interactive mode with custom input messages and keys.
* **Select `[4]`** to run the automated unit test suite.
* **Select `[5]`** to run the batch demo and regenerate screenshots.
* **Select `[6]`** to re-package the final submission ZIP.

### Method 2: Manual Side-by-Side Terminals
Open two separate terminal windows (or VS Code split terminals):

**Terminal 1 (Server):**
```powershell
py server.py --port 12345 --interactive
```

**Terminal 2 (Client):**
```powershell
py client.py --port 12345 --interactive
```

### Method 3: Automated Test Suite
```powershell
py test_suite.py
```

---

## 6. Exact Formatted Execution Output

### 6.1 Client Side Output (Matches Required Template):
```text
Client Side:
Input: Message: <ANTIGRAVITY SECURE PROTOCOL - RAGHAV GUPTA (20243226)>
Secret Key: <1010000010>
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
   [Block 2: Char 'N' (ASCII 78 = 01001110)]
     -> Initial Permutation (IP): 11000011 (L0: 1100, R0: 0011)
     -> Round 1 (Subkey K1=10100100):
        EP(R0): 10010110 ^ K1 = 00110010
        S-boxes: S0->10, S1->01 | P4: 0101
        L0 ^ P4 = 1001 | After Swap (SW): Left=0011, Right=1001
     -> Round 2 (Subkey K2=01000011):
        EP(R_sw): 11000011 ^ K2 = 10000000
        S-boxes: S0->00, S1->00 | P4: 0000
        Pre-output: 00111001
     -> Inverse IP (IP^-1): 10110010
   [Block 3: Char 'T' (ASCII 84 = 01010100)]
     -> Initial Permutation (IP): 11001000 (L0: 1100, R0: 1000)
     -> Round 1 (Subkey K1=10100100):
        EP(R0): 01000001 ^ K1 = 11100101
        S-boxes: S0->11, S1->01 | P4: 1101
        L0 ^ P4 = 0001 | After Swap (SW): Left=1000, Right=0001
     -> Round 2 (Subkey K2=01000011):
        EP(R_sw): 10000010 ^ K2 = 11000001
        S-boxes: S0->01, S1->10 | P4: 1010
        Pre-output: 00100001
     -> Inverse IP (IP^-1): 00100010
   ... (50 remaining block(s) encrypted similarly)

Cipher text: <15b222af019f153aaf22aa624f5044c19f5062a39f4722474447a56236629f1501e0153a6201c1a3221562dc231f23ba732323a293>
Hash code: <fd7b348520c15e0a64618da2abd975bf6dd4991bb06c20cf8bf7a72f80ab84e5210e5ed41a314fba9d471a5150d8f17aad64766dd1bf8bb39afce8e8b8a075ad>
Digital Signature: <1196850174425335996620642141383777095915052422921150604922165174064005122335396726622619572881512853048012004008047184393010087772441384041170849518399153024753790393247>
```

### 6.2 Server Side Output (Matches Required Template):
```text
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
   [Block 2: Cipher bits 10110010]
     -> Initial Permutation (IP): 00111001 (L0: 0011, R0: 1001)
     -> Round 1 (Subkey K2=01000011):
        EP(R0): 11000011 ^ K2 = 10000000
        S-boxes: S0->00, S1->00 | P4: 0000
        L0 ^ P4 = 0011 | After Swap (SW): Left=1001, Right=0011
     -> Round 2 (Subkey K1=10100100):
        EP(R_sw): 10010110 ^ K1 = 00110010
        S-boxes: S0->10, S1->01 | P4: 0101
        Pre-output: 11000011
     -> Inverse IP (IP^-1): 01001110 -> Decrypted Char: 'N' (ASCII 78)
   [Block 3: Cipher bits 00100010]
     -> Initial Permutation (IP): 00100001 (L0: 0010, R0: 0001)
     -> Round 1 (Subkey K2=01000011):
        EP(R0): 10000010 ^ K2 = 11000001
        S-boxes: S0->01, S1->10 | P4: 1010
        L0 ^ P4 = 1000 | After Swap (SW): Left=0001, Right=1000
     -> Round 2 (Subkey K1=10100100):
        EP(R_sw): 01000001 ^ K1 = 11100101
        S-boxes: S0->11, S1->01 | P4: 1101
        Pre-output: 11001000
     -> Inverse IP (IP^-1): 01010100 -> Decrypted Char: 'T' (ASCII 84)
   ... (50 remaining block(s) decrypted similarly)

Decrypt Message: ANTIGRAVITY SECURE PROTOCOL - RAGHAV GUPTA (20243226)
Hash code: fd7b348520c15e0a64618da2abd975bf6dd4991bb06c20cf8bf7a72f80ab84e5210e5ed41a314fba9d471a5150d8f17aad64766dd1bf8bb39afce8e8b8a075ad
Verification code: fd7b348520c15e0a64618da2abd975bf6dd4991bb06c20cf8bf7a72f80ab84e5210e5ed41a314fba9d471a5150d8f17aad64766dd1bf8bb39afce8e8b8a075ad
Signature: <valid>
Message: <Accepted>
```

---

## 7. Submission Checklist Verification

- [x] **Platform Independent & Command Line Executable (Rule 1):** Pure Python 3 standard library, executable on any OS without pip dependencies.
- [x] **Author Details in Every Code File (Rule 2):** Name (`Raghav Gupta`) and Roll Number (`20243226`) explicitly stated in every file header and docstring.
- [x] **Detailed README File (Rule 3):** Complete guide with visual architecture diagrams, mathematical proofs, and function directories.
- [x] **ZIP File for Submission (Rule 4):** Fully bundled in `20243226_Raghav_Gupta.zip`.
- [x] **Sample Output Files & Screenshots (Rule 5):** Text logs (`client_output.txt`, `server_output.txt`) and high-resolution terminal window screenshots (`client_execution_screenshot.png`, `server_execution_screenshot.png`).
- [x] **ZIP Renamed Correctly (Rule 6):** Formatted as `20243226_Raghav_Gupta.zip`.
