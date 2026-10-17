# Assignment 1 - Evaluation & Submission Guide

**Student Name:** Raghav Gupta  
**Roll Number:** 20243226  
**Branch:** B.Tech Computer Science and Engineering  
**Institute:** MNNIT Allahabad  
**Submission Link:** [https://forms.gle/VS3dnQFCf37K9q2j7](https://forms.gle/VS3dnQFCf37K9q2j7)  
**Submission Package:** `20243226_Raghav_Gupta.zip`  

---

## 1. Quick Verification for the Evaluator

This project is fully self-contained using **pure Python 3 standard library** (no `pip install` required).

### Quick 10-Second Test:
To run the complete automated test suite verifying S-DES, Whirlpool from scratch, RSA, and live socket transmission:
```powershell
py test_suite.py
```
*Expected Result: `Ran 5 tests in ~1.1s - OK`*

---

## 2. One-Click Interactive Demonstration
Run:
```powershell
py main.py
```
*(Or double-click `run.bat` on Windows)*.
- **Option 1:** Spawns two native Windows terminal windows side-by-side, executing the Server and Client live.
- **Option 2 & 3:** Run Server and Client interactively in current console.
- **Option 4:** Runs unit tests.
- **Option 5:** Re-generates output files and screenshots.
- **Option 6:** Re-packages the submission zip file.

---

## 3. Strict Assignment Requirements Audit

| Requirement from Question Paper | How It Is Satisfied | Verified Location |
| :--- | :--- | :--- |
| **1. Platform Independent & Command Line Executable** | Built with pure Python 3 without external libraries. Works on Windows, Linux, and macOS via CLI. | `server.py`, `client.py`, `algorithms/` |
| **2. Author Name & Roll No in Code Comments** | Author header and inline comments embedded in every single file: `Author: Raghav Gupta`, `Roll No: 20243226`. | Lines 1–15 in all `.py` files across root, `algorithms/`, and `network/` |
| **3. Readme File Explaining All Functions & Files** | Comprehensive `README.md` explaining mathematical derivations, protocol flowchart, modular packages, and every function and class. | `README.md` |
| **4. Submit ZIP Containing All Files & Readme** | Packaged into `20243226_Raghav_Gupta.zip`. | `20243226_Raghav_Gupta.zip` |
| **5. Sample Output Files & Execution Window Screenshots** | Individual logs (`client_output.txt`, `server_output.txt`) and high-resolution terminal window screenshots (`client_execution_screenshot.png`, `server_execution_screenshot.png`). | Included in root & zip |
| **6. Rename ZIP to Roll Number and Name** | Exactly named: `20243226_Raghav_Gupta.zip`. | Root directory |

---

## 4. Algorithm Calculation Verification

- **Symmetric Algorithm:**
  $$20243226 \pmod 3 = 0 \implies \mathbf{Simplified\ DES\ (S\text{-}DES)}$$
- **Asymmetric Algorithm:**
  $$20243226 \pmod 2 = 0 \implies \mathbf{RSA}$$
- **Hash Algorithm:**
  $$\mathbf{Whirlpool\ Hash\ (Created\ from\ scratch)}$$
