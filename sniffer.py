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
    colorama.init(autoreset=True)
except ImportError:
    pass

# Protocol mapping table
PROTOCOL_NAMES = {
    1:  "ICMP",
    2:  "IGMP",
    6:  "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "IPv6-ICMP",
    89: "OSPF",
}

# Common Port Name Resolution
PORT_SERVICES = {
    20: "FTP-Data",
    21: "FTP-Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    443: "HTTPS",
    465: "SMTPS",
    587: "Submission",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
}

# Global capture statistics
stats = {
    "total_packets": 0,
    "tcp_count": 0,
    "udp_count": 0,
    "icmp_count": 0,
    "other_count": 0,
    "total_bytes": 0,
    "start_time": None,
}

def print_banner():
    """Prints the project banner and operational metadata."""
    banner = f"""
{Colors.CYAN}{Colors.BOLD}======================================================================
  ____          _            _     _       _             
 / ___|___   __| | ___  __ _| |   | |__   | |__   __ _   
| |   / _ \\ / _` |/ _ \\/ _` | |   | '_ \\  | '_ \\ / _` |  
| |__| (_) | (_| |  __/ (_| | |___| |_) | | |_) | (_| |  
 \\____\\___/ \\__,_|\\___|\\__,_|_____|_.__/__|_.__/ \\__,_|  
               BASIC NETWORK SNIFFER - TASK 1             
======================================================================{Colors.RESET}
{Colors.GREEN}* Author      :{Colors.RESET} Cyber Security Intern
{Colors.GREEN}* Organization:{Colors.RESET} CodeAlpha Internship Program
{Colors.GREEN}* Capability  :{Colors.RESET} IPv4/IPv6, TCP, UDP, ICMP Packet Metadata Extraction
{Colors.YELLOW}* Privacy Note:{Colors.RESET} Payload data is redacted to safeguard privacy and credentials.
{Colors.CYAN}======================================================================{Colors.RESET}
"""
    print(banner)

def get_service_name(port):
    """Resolves a well-known port to its service name."""
    return PORT_SERVICES.get(port, str(port))

def format_tcp_flags(flags_val):
    """Parses TCP flag representation into a readable comma-separated string."""
    flag_map = {
        'F': 'FIN',
        'S': 'SYN',
        'R': 'RST',
        'P': 'PSH',
        'A': 'ACK',
        'U': 'URG',
        'E': 'ECE',
        'C': 'CWR',
    }
    flags_str = str(flags_val)
    parsed = [flag_map[char] for char in flags_str if char in flag_map]
    return "+".join(parsed) if parsed else flags_str

def process_packet(packet, output_file=None):
    """
    Extracts and logs packet metadata:
      - Source IP, Destination IP
      - Protocol Name (TCP, UDP, ICMP, etc.)
      - Packet Size (Length in bytes)
      - Port numbers and connection flags
    """
    global stats
    stats["total_packets"] += 1
    pkt_len = len(packet)
    stats["total_bytes"] += pkt_len
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    # Check for IP layer (Scapy IP or IPv6)
    has_ip = packet.haslayer("IP") if hasattr(packet, "haslayer") else False
    has_ipv6 = packet.haslayer("IPv6") if hasattr(packet, "haslayer") else False

    if not has_ip and not has_ipv6:
        stats["other_count"] += 1
        return

    # Extract IP layer attributes
    if has_ip:
        ip_layer = packet["IP"]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto_num = ip_layer.proto
        proto_name = PROTOCOL_NAMES.get(proto_num, f"Proto-{proto_num}")
    else:
        ip_layer = packet["IPv6"]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto_name = "IPv6"

    # Identify transport layer
    extra_info = ""
    proto_color = Colors.WHITE

    if packet.haslayer("TCP"):
        stats["tcp_count"] += 1
        proto_name = "TCP"
        proto_color = Colors.GREEN
        tcp = packet["TCP"]
        src_port = tcp.sport
        dst_port = tcp.dport
        flags_str = format_tcp_flags(tcp.flags)
        extra_info = (
            f"Port: {src_port} ({get_service_name(src_port)}) -> "
            f"{dst_port} ({get_service_name(dst_port)}) | Flags: [{flags_str}] | "
            f"Seq: {tcp.seq} Ack: {tcp.ack}"
        )

    elif packet.haslayer("UDP"):
        stats["udp_count"] += 1
        proto_name = "UDP"
        proto_color = Colors.CYAN
        udp = packet["UDP"]
        src_port = udp.sport
        dst_port = udp.dport
        extra_info = (
            f"Port: {src_port} ({get_service_name(src_port)}) -> "
            f"{dst_port} ({get_service_name(dst_port)}) | Len: {udp.len}"
        )

    elif packet.haslayer("ICMP"):
        stats["icmp_count"] += 1
        proto_name = "ICMP"
        proto_color = Colors.YELLOW
        icmp = packet["ICMP"]
        icmp_type = icmp.type
        icmp_code = icmp.code
        type_desc = "Echo Request" if icmp_type == 8 else ("Echo Reply" if icmp_type == 0 else f"Type {icmp_type}")
        extra_info = f"Type: {icmp_type} ({type_desc}) | Code: {icmp_code}"

    else:
        stats["other_count"] += 1
        proto_color = Colors.MAGENTA
        extra_info = f"Raw IP Payload: {pkt_len} bytes"

    # Format human-readable terminal line
    log_line_plain = (
        f"[{timestamp}] [#{stats['total_packets']:05d}] "
        f"{src_ip:15s} -> {dst_ip:15s} | "
        f"Proto: {proto_name:5s} | Size: {pkt_len:5d} B | {extra_info}"
    )

    log_line_color = (
        f"{Colors.DIM}[{timestamp}]{Colors.RESET} "
        f"{Colors.BOLD}[#{stats['total_packets']:05d}]{Colors.RESET} "
        f"{Colors.WHITE}{src_ip:15s}{Colors.RESET} -> "
        f"{Colors.WHITE}{dst_ip:15s}{Colors.RESET} | "
        f"{proto_color}{Colors.BOLD}{proto_name:5s}{Colors.RESET} | "
        f"{Colors.BLUE}Size: {pkt_len:5d} B{Colors.RESET} | "
        f"{Colors.DIM}{extra_info}{Colors.RESET}"
    )

    print(log_line_color)

    # Log to file if requested
    if output_file:
        try:
            with open(output_file, "a", encoding="utf-8") as f:
                f.write(log_line_plain + "\n")
        except Exception:
            pass

def print_summary():
    """Displays cumulative capture statistics when sniffing terminates."""
    elapsed = time.time() - (stats["start_time"] or time.time())
    print("\n" + Colors.CYAN + "=" * 70 + Colors.RESET)
    print(f"{Colors.BOLD}{Colors.GREEN}             CAPTURE SESSION SUMMARY             {Colors.RESET}")
    print(Colors.CYAN + "=" * 70 + Colors.RESET)
    print(f"  Duration              : {elapsed:.2f} seconds")
    print(f"  Total Packets Captured: {stats['total_packets']}")
    print(f"  Total Volume Captured : {stats['total_bytes'] / 1024:.2f} KB ({stats['total_bytes']} bytes)")
    print("  ------------------------------------------------------------------")
    print(f"  {Colors.GREEN}TCP Packets           : {stats['tcp_count']:<6d} ({percentage(stats['tcp_count'], stats['total_packets']):.1f}%){Colors.RESET}")
    print(f"  {Colors.CYAN}UDP Packets           : {stats['udp_count']:<6d} ({percentage(stats['udp_count'], stats['total_packets']):.1f}%){Colors.RESET}")
    print(f"  {Colors.YELLOW}ICMP Packets          : {stats['icmp_count']:<6d} ({percentage(stats['icmp_count'], stats['total_packets']):.1f}%){Colors.RESET}")
    print(f"  {Colors.MAGENTA}Other/Raw Packets     : {stats['other_count']:<6d} ({percentage(stats['other_count'], stats['total_packets']):.1f}%){Colors.RESET}")
    print(Colors.CYAN + "=" * 70 + Colors.RESET)
    print(f"{Colors.DIM}Session closed cleanly. Ready for report & screenshots.{Colors.RESET}\n")

def percentage(part, total):
    return (part / total * 100) if total > 0 else 0.0

def run_simulation_mode(count=20, output_file=None):
    """
    Simulation mode generates realistic network packets.
    Used for instant testing, verification, and screenshot preparation without
    requiring administrator privileges or kernel-level packet drivers.
    """
    import random
    print(f"{Colors.YELLOW}[*] Running in SIMULATION / DEMO MODE (safe educational packets)...{Colors.RESET}")
    print(f"{Colors.YELLOW}[*] Perfect for testing terminal output and capturing screenshots.{Colors.RESET}\n")

    sample_hosts = [
        ("192.168.1.105", "142.250.190.46", "TCP", 54322, 443, "SYN+ACK", "HTTPS Handshake"),
        ("192.168.1.105", "8.8.8.8", "UDP", 53531, 53, "", "DNS Query (example.com)"),
        ("8.8.8.8", "192.168.1.105", "UDP", 53, 53531, "", "DNS Response (93.184.216.34)"),
        ("192.168.1.105", "1.1.1.1", "ICMP", 0, 0, "", "Echo Request (Ping)"),
        ("1.1.1.1", "192.168.1.105", "ICMP", 0, 0, "", "Echo Reply (Pong)"),
        ("192.168.1.105", "104.244.42.1", "TCP", 49812, 443, "ACK+PSH", "TLS Encrypted Stream"),
        ("192.168.1.105", "192.168.1.1", "UDP", 68, 67, "", "DHCP Request"),
        ("192.168.1.1", "192.168.1.105", "UDP", 67, 68, "", "DHCP Ack"),
    ]

    packets_to_generate = count if count > 0 else 25

    for i in range(1, packets_to_generate + 1):
        src, dst, proto, sport, dport, flags, desc = random.choice(sample_hosts)
        pkt_len = random.randint(64, 1500)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        stats["total_packets"] += 1
        stats["total_bytes"] += pkt_len

        if proto == "TCP":
            stats["tcp_count"] += 1
            proto_color = Colors.GREEN
            extra_info = f"Port: {sport} ({get_service_name(sport)}) -> {dport} ({get_service_name(dport)}) | Flags: [{flags}] | {desc}"
        elif proto == "UDP":
            stats["udp_count"] += 1
            proto_color = Colors.CYAN
            extra_info = f"Port: {sport} ({get_service_name(sport)}) -> {dport} ({get_service_name(dport)}) | {desc}"
        elif proto == "ICMP":
            stats["icmp_count"] += 1
            proto_color = Colors.YELLOW
            extra_info = f"Type: 8/0 | {desc}"
        else:
            stats["other_count"] += 1
            proto_color = Colors.MAGENTA
            extra_info = desc

        log_line_plain = (
            f"[{timestamp}] [#{stats['total_packets']:05d}] "
            f"{src:15s} -> {dst:15s} | "
            f"Proto: {proto:5s} | Size: {pkt_len:5d} B | {extra_info}"
        )

        log_line_color = (
            f"{Colors.DIM}[{timestamp}]{Colors.RESET} "
            f"{Colors.BOLD}[#{stats['total_packets']:05d}]{Colors.RESET} "
            f"{Colors.WHITE}{src:15s}{Colors.RESET} -> "
            f"{Colors.WHITE}{dst:15s}{Colors.RESET} | "
            f"{proto_color}{Colors.BOLD}{proto_name_padded(proto)}{Colors.RESET} | "
            f"{Colors.BLUE}Size: {pkt_len:5d} B{Colors.RESET} | "
            f"{Colors.DIM}{extra_info}{Colors.RESET}"
        )

        print(log_line_color)

        if output_file:
            try:
                with open(output_file, "a", encoding="utf-8") as f:
                    f.write(log_line_plain + "\n")
            except Exception:
                pass

        time.sleep(random.uniform(0.1, 0.4))

    print_summary()

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
        nargs="?",
        type=int,
        default=None,
        help="Optional packet count (e.g. 'python sniffer.py 10')"
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        help="Number of packets to capture (default: 0 = continuous)",
        default=0
    )
    parser.add_argument(
        "-f", "--filter",
        help="BPF filter string (e.g., 'tcp', 'udp', 'icmp', 'port 80')",
        default=None
    )
    parser.add_argument(
        "-o", "--output",
        help="Path to output text log file (e.g., 'captured_packets.log')",
        default="captured_packets.log"
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run in demonstration/simulation mode to test output without Npcap or admin rights"
    )

    args = parser.parse_args()

    # Determine packet count (support both positional 'python sniffer.py 10' and flag '-c 10')
    target_count = args.count if args.count > 0 else (args.positional_count if args.positional_count is not None else 0)

    print_banner()
    stats["start_time"] = time.time()

    # If demo mode is explicitly passed
    if args.demo:
        run_simulation_mode(count=target_count or 20, output_file=args.output)
        return

    # Attempt live sniffing using Scapy
    try:
        from scapy.all import sniff, conf
    except ImportError:
        print(f"{Colors.RED}[!] Error: The 'scapy' library is not installed.{Colors.RESET}")
        print(f"{Colors.YELLOW}[*] Install it with:{Colors.RESET} pip install scapy")
        print(f"{Colors.CYAN}[*] Or test right now using demonstration mode:{Colors.RESET} python sniffer.py --demo\n")
        sys.exit(1)

    print(f"{Colors.GREEN}[+] Scapy initialized successfully.{Colors.RESET}")
    if args.interface:
        print(f"{Colors.GREEN}[+] Listening on Interface:{Colors.RESET} {args.interface}")
    else:
        print(f"{Colors.GREEN}[+] Listening on Default Interface:{Colors.RESET} {conf.iface}")

    if args.filter:
        print(f"{Colors.GREEN}[+] Active BPF Filter     :{Colors.RESET} {args.filter}")
    print(f"{Colors.GREEN}[+] Output Log File       :{Colors.RESET} {args.output}")
    print(f"{Colors.YELLOW}[*] Starting real-time capture. Press Ctrl+C to terminate...{Colors.RESET}\n")

    try:
        sniff(
            iface=args.interface,
            filter=args.filter,
            prn=lambda pkt: process_packet(pkt, output_file=args.output),
            count=target_count,
            store=False
        )
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[*] Capture terminated by user (KeyboardInterrupt).{Colors.RESET}")
    except PermissionError:
        print(f"\n{Colors.RED}[!] Permission Denied:{Colors.RESET} Raw packet sniffing requires Administrator privileges.")
        print(f"{Colors.YELLOW}[*] Please open your PowerShell or Command Prompt as Administrator and run the script again.{Colors.RESET}")
        print(f"{Colors.CYAN}[*] Or try the built-in demo mode without admin rights:{Colors.RESET} python sniffer.py --demo\n")
    except Exception as e:
        print(f"\n{Colors.RED}[!] Live capture error: {e}{Colors.RESET}")
        print(f"{Colors.YELLOW}[*] If Npcap is missing on Windows, install it from: https://npcap.com/#download{Colors.RESET}")
        print(f"{Colors.CYAN}[*] In the meantime, you can run simulated packets for testing & screenshots:{Colors.RESET}")
        print(f"    python sniffer.py --demo\n")
    finally:
        if stats["total_packets"] > 0:
            print_summary()

if __name__ == "__main__":
    main()

