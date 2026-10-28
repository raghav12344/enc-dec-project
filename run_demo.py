"""
Demonstration Runner and Terminal Screenshot Generator
======================================================
Author: Raghav Gupta
Roll Number: 44275
Assignment: Assignment 1 - Secure Client-Server Message Exchange
Course: Cryptography & Information Security | MNNIT Allahabad

This script runs the Server and Client with a sample demonstration message,
captures raw stdout to 'server_output.txt' and 'client_output.txt',
and renders realistic terminal execution screenshots ('server_execution_screenshot.png'
and 'client_execution_screenshot.png') using Pillow with monospace font rendering.
"""

import subprocess
import time
import os
from PIL import Image, ImageDraw, ImageFont


def capture_execution():
    """Runs server and client in separate processes, capturing console output."""
    server_cmd = ["py", "server.py", "--port", "12345"]
    client_cmd = [
        "py", "client.py",
        "--port", "12345",
        "--message", "ANTIGRAVITY SECURE PROTOCOL - RAGHAV GUPTA (44275)",
        "--key", "1010000010110001"
    ]

    print("[*] Starting Server process...")
    server_proc = subprocess.Popen(
        server_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8"
    )

    # Give server time to bind and listen
    time.sleep(1.5)

    print("[*] Starting Client process...")
    client_proc = subprocess.Popen(
        client_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8"
    )

    client_stdout, _ = client_proc.communicate()
    server_stdout, _ = server_proc.communicate()

    with open("client_output.txt", "w", encoding="utf-8") as f:
        f.write(client_stdout)

    with open("server_output.txt", "w", encoding="utf-8") as f:
        f.write(server_stdout)

    print("[+] Saved 'client_output.txt' and 'server_output.txt'")
    return client_stdout, server_stdout


def render_terminal_screenshot(text, filename, title="Windows PowerShell"):
    """
    Renders text onto a realistic Windows Terminal / PowerShell window image.
    """
    lines = text.splitlines()

    # Try to load Consolas or Lucida Console or default
    font_size = 14
    try:
        font = ImageFont.truetype("consola.ttf", font_size)
    except Exception:
        try:
            font = ImageFont.truetype("cour.ttf", font_size)
        except Exception:
            font = ImageFont.load_default()

    # Measure line dimensions
    sample_bbox = font.getbbox("A")
    char_width = sample_bbox[2] - sample_bbox[0]
    line_height = int((sample_bbox[3] - sample_bbox[1]) * 1.6)

    max_cols = max(len(l) for l in lines) if lines else 80
    max_cols = max(max_cols, 80)
    width = max(char_width * max_cols + 40, 950)
    title_bar_height = 36
    height = title_bar_height + len(lines) * line_height + 40

    img = Image.new("RGB", (width, height), color=(12, 12, 12))  # Windows Terminal dark bg
    draw = ImageDraw.Draw(img)

    # Title Bar
    draw.rectangle([(0, 0), (width, title_bar_height)], fill=(31, 31, 31))
    draw.text((15, 10), title, fill=(204, 204, 204), font=font)

    # Window Controls (Minimize, Maximize, Close)
    draw.rectangle([(width - 45, 0), (width, title_bar_height)], fill=(31, 31, 31))
    draw.text((width - 32, 10), "X", fill=(180, 180, 180), font=font)
    draw.text((width - 65, 8), "[]", fill=(180, 180, 180), font=font)
    draw.text((width - 95, 8), "_", fill=(180, 180, 180), font=font)

    # Draw Text
    y = title_bar_height + 15
    for line in lines:
        if "====" in line or "---" in line:
            color = (100, 180, 255)
        elif line.startswith("Input:") or line.startswith("Server Side:") or line.startswith("Client Side:"):
            color = (255, 215, 0)
        elif "Accepted" in line or "valid" in line or "SUCCESS" in line:
            color = (80, 250, 123)
        elif line.startswith("[+]"):
            color = (139, 233, 253)
        elif line.startswith("[*]"):
            color = (241, 250, 140)
        else:
            color = (240, 240, 240)

        draw.text((20, y), line, fill=color, font=font)
        y += line_height

    img.save(filename)
    print(f"[+] Rendered terminal window screenshot: {filename}")


if __name__ == "__main__":
    c_out, s_out = capture_execution()
    render_terminal_screenshot(s_out, "server_execution_screenshot.png", "Server Terminal - Raghav Gupta (44275)")
    render_terminal_screenshot(c_out, "client_execution_screenshot.png", "Client Terminal - Raghav Gupta (44275)")
