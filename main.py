"""
Master Interactive Control Panel
================================
Author: Raghav Gupta
Roll Number: 20243226
Assignment: Assignment 1 - Secure Client-Server Message Exchange

This master script provides a user-friendly CLI menu for executing,
testing, debugging, and packaging the complete Cryptography assignment.
"""

import os
import sys
import time
import subprocess
import zipfile


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def print_banner():
    print("=" * 72)
    print("  SECURE MESSAGE PROTOCOL - CRYPTOGRAPHY ASSIGNMENT 1")
    print("  Author: Raghav Gupta | Roll Number: 20243226 | MNNIT Allahabad")
    print("  Assigned: S-DES (Symmetric) | RSA (Asymmetric) | Whirlpool (Hash)")
    print("=" * 72)


def run_side_by_side_demo():
    """Spawns Server and Client in separate Windows terminal windows."""
    print("\n[+] Launching Server and Client in separate terminal windows...")

    if os.name == "nt":
        # Windows: Use start powershell
        server_cmd = 'start powershell -NoExit -Command "py server.py --port 12345"'
        client_cmd = 'start powershell -NoExit -Command "py client.py --port 12345 --interactive"'

        subprocess.Popen(server_cmd, shell=True)
        print("[*] Server terminal launched on port 12345. Waiting 2 seconds for initialization...")
        time.sleep(2)
        subprocess.Popen(client_cmd, shell=True)
        print("[*] Client terminal launched. Check the new windows on your desktop!")
    else:
        print("[!] Non-Windows environment detected. Running inline demo instead...")
        run_batch_demo()


def run_inline_server():
    """Runs the server in current terminal."""
    from server import run_server
    print("\n[+] Starting Server in current terminal (Press Ctrl+C to stop)...")
    try:
        run_server(host="127.0.0.1", port=12345, interactive=True)
    except KeyboardInterrupt:
        print("\n[*] Server stopped by user.")


def run_inline_client():
    """Runs the client interactively in current terminal."""
    from client import run_client
    print("\n[+] Starting Client in interactive mode...")
    run_client(host="127.0.0.1", port=12345, interactive=True)


def run_test_suite():
    """Runs all automated unit tests."""
    print("\n[+] Running automated test suite (test_suite.py)...")
    subprocess.run([sys.executable, "test_suite.py"])


def run_batch_demo():
    """Runs demo, saves outputs to txt files, and generates screenshots."""
    print("\n[+] Running batch demo and updating logs and screenshots...")
    subprocess.run([sys.executable, "run_demo.py"])


def package_zip():
    """Packages all required submission files into the designated ZIP."""
    zip_name = "20243226_Raghav_Gupta.zip"
    files_to_zip = [
        "whirlpool.py",
        "sdes.py",
        "rsa.py",
        "server.py",
        "client.py",
        "test_suite.py",
        "run_demo.py",
        "main.py",
        "run.bat",
        ".gitignore",
        "README.md",
        "INSTRUCTIONS_AND_SUBMISSION.md",
        "client_output.txt",
        "server_output.txt",
        "client_execution_screenshot.png",
        "server_execution_screenshot.png"
    ]

    print(f"\n[+] Packaging files into '{zip_name}'...")
    with zipfile.ZipFile(zip_name, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in files_to_zip:
            if os.path.exists(f):
                zf.write(f)
                print(f"    + Added {f} ({os.path.getsize(f):,} bytes)")
            else:
                print(f"    - Skipping missing file: {f}")

    print(f"\n[SUCCESS] Package created: {zip_name} ({os.path.getsize(zip_name):,} bytes)")


def main():
    while True:
        clear_screen()
        print_banner()
        print("\nPlease choose an option:")
        print("  [1] 🚀 Launch Live Demo (Spawns Server & Client in Side-by-Side Windows)")
        print("  [2] 🖥️ Start Server (Current Terminal)")
        print("  [3] 📱 Start Client (Interactive / Send Custom Message)")
        print("  [4] 🧪 Run Automated Unit & Integration Tests (test_suite.py)")
        print("  [5] 📸 Run Batch Demo & Generate Output Logs + Screenshots")
        print("  [6] 📦 Package Submission ZIP ('20243226_Raghav_Gupta.zip')")
        print("  [0] ❌ Exit")
        print("=" * 72)

        choice = input("Enter choice [0-6]: ").strip()

        if choice == "1":
            run_side_by_side_demo()
            input("\nPress ENTER to return to menu...")
        elif choice == "2":
            run_inline_server()
            input("\nPress ENTER to return to menu...")
        elif choice == "3":
            run_inline_client()
            input("\nPress ENTER to return to menu...")
        elif choice == "4":
            run_test_suite()
            input("\nPress ENTER to return to menu...")
        elif choice == "5":
            run_batch_demo()
            input("\nPress ENTER to return to menu...")
        elif choice == "6":
            package_zip()
            input("\nPress ENTER to return to menu...")
        elif choice == "0":
            print("\nExiting. Thank you!")
            break
        else:
            print("\n[!] Invalid option. Please choose between 0 and 6.")
            time.sleep(1)


if __name__ == "__main__":
    main()
