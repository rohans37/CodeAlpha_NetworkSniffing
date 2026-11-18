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

