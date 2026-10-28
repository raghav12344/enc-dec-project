# Assignment 1 - Evaluation & Submission Guide

**Student Name:** Raghav Gupta  
**Roll Number:** 44275  
**Branch:** B.Tech Computer Science and Engineering  
**Institute:** MNNIT Allahabad  
**Submission Link:** [https://forms.gle/VS3dnQFCf37K9q2j7](https://forms.gle/VS3dnQFCf37K9q2j7)  
**Submission Package:** `44275_Raghav_Gupta.zip`  

---

## 1. Quick Start for the Evaluator

This project is fully self-contained using the **pure Python 3 standard library** (zero `pip` dependencies).

Start the entire application with a single command:
```powershell
py main.py
```
*(Or double-click `run.bat` on Windows)*.

This opens the master interactive control panel:
- **Option `[1]`:** Spawns two native Windows terminal windows side-by-side, executing Server and Client live.
- **Option `[2]` & `[3]`:** Run Server and Client interactively in current console.
- **Option `[4]`:** Runs all 5 unit and integration tests (`Ran 5 tests in ~0.5s - OK`).
- **Option `[5]`:** Re-generates output files and screenshots.
- **Option `[6]`:** Re-packages the submission zip file (`44275_Raghav_Gupta.zip`).

---

## 3. Strict Assignment Requirements Audit

| Requirement from Question Paper | How It Is Satisfied | Verified Location |
| :--- | :--- | :--- |
| **1. Platform Independent & Command Line Executable** | Built with pure Python 3 without external libraries. Works on Windows, Linux, and macOS via CLI. | `server.py`, `client.py`, `algorithms/` |
| **2. Author Name & Roll No in Code Comments** | Author header and inline comments embedded in every single file: `Author: Raghav Gupta`, `Roll Number: 44275`. | Lines 1–15 in all `.py` files across root, `algorithms/`, and `network/` |
| **3. Readme File Explaining All Functions & Files** | Comprehensive `README.md` explaining mathematical derivations, protocol flowchart, modular packages, and every function and class. | `README.md` |
| **4. Submit ZIP Containing All Files & Readme** | Packaged into `44275_Raghav_Gupta.zip`. | `44275_Raghav_Gupta.zip` |
| **5. Sample Output Files & Execution Window Screenshots** | Individual logs (`client_output.txt`, `server_output.txt`) and high-resolution terminal window screenshots (`client_execution_screenshot.png`, `server_execution_screenshot.png`). | Included in root & zip |
| **6. Rename ZIP to Roll Number and Name** | Exactly named: `44275_Raghav_Gupta.zip`. | Root directory |

---

## 4. Algorithm Calculation Verification

From Page 3 of the Question Paper:
1. **Symmetric Algorithm:**
   $$44275 \pmod 3 = 1 \implies \mathbf{AES\ variant\ (Simplified\ AES\ /\ S\text{-}AES)}$$
   *Formula: $44275 = 3 \times 14758 + 1 \implies \text{Remainder } 1$*
2. **Asymmetric Algorithm:**
   $$44275 \pmod 2 = 1 \implies \mathbf{Elgamal}$$
   *Formula: $44275 = 2 \times 22137 + 1 \implies \text{Remainder } 1$*
3. **Hash Algorithm:**
   $$\mathbf{Whirlpool\ Hash\ (Created\ from\ scratch\ -\ ISO/IEC\ 10118\text{-}3)}$$
