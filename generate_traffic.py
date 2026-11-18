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

