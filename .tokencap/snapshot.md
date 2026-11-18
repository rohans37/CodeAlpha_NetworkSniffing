<!-- TokenCap v1.6 Savings: baseline 7,087 tok → actual 4,541 tok (35.9% saved) -->
# AI ENTRY POINT

This repository has been indexed by TokenCap.

Before analyzing files, read:

.tokencap/agent/START_HERE.md

Use:

- .tokencap/agent/agent-pack.md
- .tokencap/agent/allowed-context.json
- .tokencap/agent/context-manifest.json

Do not rediscover the repository from scratch.

---

# TokenCap Snapshot

| Field | Value |
| --- | --- |
| Generated | 2026-11-06T04:26:35.575Z |
| Workspace | c:\Users\Rohan\Downloads\COLLEGE\CodeAlpha_NetworkSniffing |
| Profile | balanced |
| Selected files | 6 |
| Source bytes | 27323 |
| Estimated source tokens | 7087 |

## Read First

This file is a compressed coding-session handoff. Read it before editing, then inspect the referenced files directly. Prefer the live repository over this snapshot when there is a conflict.

## TokenCap Intelligence Files

- TOKENCAP_GRAPH.md — Project dependency and architecture graph *(JS/TS projects only)*
- TOKENCAP_MEMORY.md — Developer notes, current task, constraints, and context memory

## Handoff Summary

| Field | Value |
| --- | --- |
| Read order | README.md > screenshots/README.md > requirements.txt > AGENTS.md > generate_traffic.py |
| Primary anchors | README.md, screenshots/README.md, requirements.txt |
| Changed files | 0 |
| TODO notes | 0 |
| File budget used | 7% |
| Source budget used | 12% |
| Token estimate | 7087 |
| Contents mode | enabled |

## Handoff Guidelines

- Preserve user changes; avoid reverting unrelated work.
- Start with changed files and files marked `high-signal` in the manifest.
- Treat the Git diff as intent and verify changes in source files.
- Update this snapshot after meaningful edits or before handing off.

## Git Snapshot

| Field | Value |
| --- | --- |
| Branch | unavailable |
| Git root | unavailable |

Recent commits:
```text
unavailable
```

Status:
```text
clean or unavailable
```

## Project Map

```text
screenshots/
AGENTS.md
README.md
generate_traffic.py
requirements.txt
screenshots/README.md
sniffer.py
```

## File Manifest

| File | Bytes | Score | Why |
| --- | ---: | ---: | --- |
| README.md | 8210 | 105 | project-metadata, high-signal-doc |
| screenshots/README.md | 671 | 105 | project-metadata, high-signal-doc |
| requirements.txt | 30 | 70 | project-metadata |
| AGENTS.md | 381 | 0 | context |
| generate_traffic.py | 1431 | 0 | context |
| sniffer.py | 16600 | -1 | context |

## Changed Files

No Git changes found, or this is not a Git repository.

## Git Diff Snippets

No diff available, or Git is unavailable.

## TODO / FIXME / HACK Notes

No TODO/FIXME/HACK notes found in selected files.

## Selected File Context

### README.md

| Field | Value |
| --- | --- |
| Bytes | 8210 |
| Score | 105 |
| Why | project-metadata, high-signal-doc |
| Status | Full content |


```markdown
# 🛡️ CodeAlpha Cyber Security Internship - Task 1: Basic Network Sniffer

[![Python Version](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Library](https://img.shields.io/badge/Library-Scapy-orange.svg)](https://scapy.net/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Internship](https://img.shields.io/badge/CodeAlpha-Cyber%20Security-red.svg)](https://codealpha.tech/)

A robust, real-time network packet sniffer developed in Python using the **Scapy** library. This tool monitors network traffic passing through local network interfaces, extracts critical packet header metadata, analyzes protocols (TCP, UDP, ICMP), calculates data sizes, and provides session statistical summaries.

---

## 📌 Project Objectives

As outlined in the **CodeAlpha Cyber Security Internship** curriculum for **Task 1**, this tool captures network packet metadata and clearly displays:
- **Source IP Address** (`src_ip`)
- **Destination IP Address** (`dst_ip`)
- **Protocol Identification** (TCP, UDP, ICMP, and raw protocols)
- **Packet Size** (length in bytes)
- **Transport Layer Information** (Source/Destination Ports, TCP Flags, ICMP Types/Codes)
- **Cumulative Traffic Analytics** (total packets, percentage by protocol, total volume in KB)

---

## ⚖️ Ethical & Privacy Disclaimer

> **IMPORTANT**: This project was developed strictly for academic, diagnostic, and cybersecurity defense learning within authorized private networks.
>
> - Captures traffic strictly from the user's authorized local host interface.
> - Packet payloads, sensitive application data, passwords, and user messages are **NOT** extracted, inspected, or logged to preserve complete data privacy and confidentiality.
> - Adheres to ethical computing standards and privacy best practices.

---

## 📂 Project Structure

```text
CodeAlpha_NetworkSniffer/
│
├── sniffer.py              # Main network sniffer script (live capture & demo mode)
├── generate_traffic.py     # Background traffic generator for local testing
├── requirements.txt        # Python dependency manifest
├── README.md               # Complete project documentation and guide
├── captured_packets.log    # Exported session capture logs (generated on run)
└── screenshots/            # Submission proof screenshots
    ├── 01_sniffer_startup.png
    ├── 02_packet_capture_live.png
    ├── 03_protocol_breakdown.png
    └── 04_session_summary.png
```

---

## ⚙️ Prerequisites & Installation

### 1. Install Python (3.8 or later)
- Download Python from [python.org](https://www.python.org/downloads/)
- **CRITICAL**: Make sure to check the box **"Add python.exe to PATH"** during installation.

### 2. Install Npcap (Windows Only)
On Windows, packet sniffing libraries require the Npcap packet capture driver:
- Download Npcap from [npcap.com](https://npcap.com/#download).
- During installation, check the option: **"Install Npcap in WinPcap API-compatible Mode"**.

### 3. Clone / Open Project Folder
Open your terminal or VS Code in the project folder:
```powershell
cd CodeAlpha_NetworkSniffing
```

### 4. Install Dependencies
```powershell
pip install -r requirements.txt
```

---

## 🚀 Usage Guide

### 1. Live Packet Sniffing (Requires Administrator Privileges)
Open your PowerShell or Command Prompt as **Administrator** and run:

```powershell
python sniffer.py
```

#### Optional Arguments:
| Option | Argument | Description |
|---|---|---|
| `-c`, `--count` | `NUMBER` | Stop capture automatically after capturing `N` packets. |
| `-i`, `--interface` | `IFACE` | Sniff on a specific network interface (e.g. `Wi-Fi`, `Ethernet`). |
| `-f`, `--filter` | `FILTER` | Apply a BPF filter (e.g. `"tcp"`, `"udp"`, `"icmp"`, `"port 443"`). |
| `-o`, `--output` | `FILE` | Save packet logs to a custom text file (default: `captured_packets.log`). |
| `--demo` | None | Run in simulated demonstration mode (no Admin or Npcap required). |

#### Examples:
```powershell
# Capture 50 packets and stop:
python sniffer.py -c 50

# Filter only DNS and HTTP/HTTPS traffic:
python sniffer.py -f "tcp or udp port 53"

# Sniff on a specific interface:
python sniffer.py -i "Wi-Fi" -c 100
```

### 2. Demonstration / Simulation Mode (Instant Testing & Screenshots)
If you are testing your environment before installing Npcap or without Administrator rights:
```powershell
python sniffer.py --demo
```
This generates realistic simulated TCP, UDP, and ICMP traffic with exact formatting, allowing you to verify the program and take screenshots instantly.

### 3. Generating Test Traffic
In a second terminal window, run the traffic generator script to trigger active packets:
```powershell
python generate_traffic.py
```

---

## 📊 Sample Output

```text
======================================================================
  ____          _            _     _       _             
 / ___|___   __| | ___  __ _| |   | |__   | |__   __ _   
| |   / _ \ / _` |/ _ \/ _` | |   | '_ \  | '_ \ / _` |  
| |__| (_) | (_| |  __/ (_| | |___| |_) | | |_) | (_| |  
 \____\___/ \__,_|\___|\__,_|_____|_.__/__|_.__/ \__,_|  
               BASIC NETWORK SNIFFER - TASK 1             
======================================================================
* Author      : Cyber Security Intern
* Organization: CodeAlpha Internship Program
* Capability  : IPv4/IPv6, TCP, UDP, ICMP Packet Metadata Extraction
* Privacy Note: Payload data is redacted to safeguard privacy and credentials.
======================================================================

[2026-11-06 09:15:22.140] [#00001] 192.168.1.105   -> 142.250.190.46  | TCP   | Size:   140 B | Port: 54322 (54322) -> 443 (HTTPS) | Flags: [SYN+ACK] | HTTPS Handshake
[2026-11-06 09:15:22.388] [#00002] 192.168.1.105   -> 8.8.8.8          | UDP   | Size:    74 B | Port: 53531 (53531) -> 53 (DNS) | DNS Query (example.com)
[2026-11-06 09:15:22.502] [#00003] 8.8.8.8         -> 192.168.1.105    | UDP   | Size:    90 B | Port: 53 (DNS) -> 53531 (53531) | DNS Response (93.184.216.34)
[2026-11-06 09:15:22.750] [#00004] 192.168.1.105   -> 1.1.1.1          | ICMP  | Size:    84 B | Type: 8/0 | Echo Request (Ping)
[2026-11-06 09:15:22.880] [#00005] 1.1.1.1         -> 192.168.1.105    | ICMP  | Size:    84 B | Type: 8/0 | Echo Reply (Pong)

======================================================================
             CAPTURE SESSION SUMMARY             
======================================================================
  Duration              : 5.42 seconds
  Total Packets Captured: 20
  Total Volume Captured : 15.34 KB (15708 bytes)
  ------------------------------------------------------------------
  TCP Packets           : 10     (50.0%)
  UDP Packets           : 6      (30.0%)
  ICMP Packets          : 4      (20.0%)
  Other/Raw Packets     : 0      (0.0%)
======================================================================
```

---

## 📸 Screenshots & Proof of Work

| Startup & Initialization | Real-Time Packet Sniffing | Session Summary Statistics |
|:---:|:---:|:---:|
| `screenshots/01_sniffer_startup.png` | `screenshots/02_packet_capture_live.png` | `screenshots/04_session_summary.png` |

---

## 💼 LinkedIn Project Description Template

```markdown
🚀 Excited to share that I have completed Task 1 of my Cyber Security Internship with @CodeAlpha!

🛡️ Project: Basic Network Sniffer (Python)
🔍 Objective: Develop a network packet capture tool to analyze real-time IP traffic and protocols while maintaining ethical data privacy standards.

Key Highlights:
✅ Implemented real-time packet capturing with Scapy.
✅ Parsed TCP, UDP, and ICMP protocols with header metadata extraction (Source IP, Destination IP, Ports, Flags, and Packet Sizes).
✅ Added session summary metrics (total volume, packet breakdown).
✅ Integrated automated file logging and safe simulation testing modes.

🔗 GitHub Repository: [Your GitHub URL]

#CyberSecurity #Python #Networking #InformationSecurity #PacketSniffing #CodeAlpha #Internship
```

---

## 📜 License
This project is licensed under the MIT License - see the LICENSE file for details.
```

### screenshots/README.md

| Field | Value |
| --- | --- |
| Bytes | 671 |
| Score | 105 |
| Why | project-metadata, high-signal-doc |
| Status | Full content |


```markdown
# Screenshots Directory

Save your internship project proof screenshots in this directory:

1. **`01_sniffer_startup.png`**: Terminal showing the script starting with the project banner and initialized interface.
2. **`02_packet_capture_live.png`**: Real-time packet capture showing Source IP, Destination IP, Protocol (TCP/UDP/ICMP), and Packet Size.
3. **`03_protocol_breakdown.png`**: Demonstration of TCP, UDP, and ICMP packets being detected.
4. **`04_session_summary.png`**: The final summary statistics showing total packets, total volume in KB, and protocol breakdown.
5. **`05_log_file.png`**: The saved `captured_packets.log` file opened in VS Code / notepad.
```

### requirements.txt

| Field | Value |
| --- | --- |
| Bytes | 30 |
| Score | 70 |
| Why | project-metadata |
| Status | Full content |


```txt
scapy>=2.5.0
colorama>=0.4.6
```

### AGENTS.md

| Field | Value |
| --- | --- |
| Bytes | 381 |
| Score | 0 |
| Why | context |
| Status | Full content |


```markdown
# TokenCap Start Here

Project intelligence is generated locally in `.tokencap/`.

1. Read `.tokencap/agent/START_HERE.md`.
2. Use `.tokencap/agent/allowed-context.json` to find task-relevant files.
3. Use the connected TokenCap MCP server for overview, search, impact, memory, and debug context.
4. Do not scan the repository broadly unless the generated context is insufficient.
```

### generate_traffic.py

| Field | Value |
| --- | --- |
| Bytes | 1431 |
| Score | 0 |
| Why | context |
| Status | Full content |


```py
#!/usr/bin/env python3
"""
Traffic Generator Utility for Testing the Basic Network Sniffer
Generates benign local network traffic (DNS lookups, HTTP pings, ICMP) to test packet detection.
"""

import sys
import time
import socket
import urllib.request

TARGETS = [
    "google.com",
    "github.com",
    "cloudflare.com",
    "wikipedia.org"
]

def main():
    print("=" * 60)
    print("   CodeAlpha - Network Traffic Generator (Test Helper)")
    print("=" * 60)
    print("[*] Generating benign background network activity for sniffer testing...\n")

    for domain in TARGETS:
        print(f"[+] 1. Performing DNS lookup for: {domain}...")
        try:
            ip = socket.gethostbyname(domain)
            print(f"    -> Resolved to IP: {ip}")
        except Exception as e:
            print(f"    -> DNS resolution failed: {e}")

        print(f"[+] 2. Sending HTTP request to: http://{domain}...")
        try:
            req = urllib.request.Request(
                f"http://{domain}",
                headers={"User-Agent": "CodeAlpha-Packet-Tester/1.0"}
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                print(f"    -> HTTP Status: {resp.status}")
        except Exception as e:
            print(f"    -> Request notice: {e}")

        time.sleep(1)

    print("\n[+] Done! Check your sniffer terminal for captured packets.")

if __name__ == "__main__":
    main()
```

### sniffer.py

| Field | Value |
| --- | --- |
| Bytes | 16600 |
| Score | -1 |
| Why | context |
| Status | Truncated (budget limit) |

**Structural Outline:**
  - `class Colors` (line 33)
  - `def print_banner` (line 104)
  - `def get_service_name` (line 123)
  - `def format_tcp_flags` (line 127)
  - `def process_packet` (line 143)
  - `def print_summary` (line 250)
  - `def percentage` (line 267)
  - `def run_simulation_mode` (line 270)
  - `def proto_name_padded` (line 347)
  - `def main` (line 350)
  - `interface to` (line 356)


```py
// … lines 1–47
#!/usr/bin/env python3
"""
=============================================================================
Project Name   : CodeAlpha Basic Network Sniffer
File Name      : sniffer.py
Author         : CodeAlpha Cyber Security Intern
Environment    : Python 3.x (Scapy / Cross-Platform)
Task           : Task 1 - Basic Network Sniffer
=============================================================================
Description:
A modular Python network packet sniffer that captures and inspects real-time
network packet metadata, extracting:
  - Source IP Address
  - Destination IP Address
  - Protocol (TCP, UDP, ICMP, etc.)
  - Packet Size (in bytes)
  - Detailed Transport Layer Metadata (Ports, Flags, Sequence Numbers)

Privacy & Ethics Notice:
  This tool is built solely for educational and network diagnostics purposes
  within authorized testing environments. To safeguard user privacy, this tool
  does NOT log full payload contents, passwords, or encrypted message bodies.
=============================================================================
"""

import os
import sys
import time
import argparse
from datetime import datetime

# ANSI Color Codes for terminal styling
class Colors:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"

# Initialize colorama on Windows if installed
try:
    import colorama
// … lines 103–108

def print_banner():
    """Prints the project banner and operational metadata."""
    banner = f"""
{Colors.CYAN}{Colors.BOLD}======================================================================
  ____          _            _     _       _             
// … lines 122–131

def get_service_name(port):
    """Resolves a well-known port to its service name."""
    return PORT_SERVICES.get(port, str(port))

def format_tcp_flags(flags_val):
    """Parses TCP flag representation into a readable comma-separated string."""
    flag_map = {
        'F': 'FIN',
        'S': 'SYN',
// … lines 142–147

def process_packet(packet, output_file=None):
    """
    Extracts and logs packet metadata:
      - Source IP, Destination IP
      - Protocol Name (TCP, UDP, ICMP, etc.)
// … lines 249–254

def print_summary():
    """Displays cumulative capture statistics when sniffing terminates."""
    elapsed = time.time() - (stats["start_time"] or time.time())
    print("\n" + Colors.CYAN + "=" * 70 + Colors.RESET)
    print(f"{Colors.BOLD}{Colors.GREEN}             CAPTURE SESSION SUMMARY             {Colors.RESET}")
// … lines 266–274

def percentage(part, total):
    return (part / total * 100) if total > 0 else 0.0

def run_simulation_mode(count=20, output_file=None):
    """
    Simulation mode generates realistic network packets.
    Used for instant testing, verification, and screenshot preparation without
    requiring administrator privileges or kernel-level packet drivers.
// … lines 346–360

def proto_name_padded(proto):
    return f"{proto:5s}"

def main():
    parser = argparse.ArgumentParser(
        description="CodeAlpha Basic Network Sniffer - Packet Metadata Inspector"
    )
    parser.add_argument(
        "-i", "--interface",
        help="Network interface to sniff on (e.g., 'Ethernet', 'Wi-Fi')",
        default=None
    )
    parser.add_argument(
        "positional_count",
```