#!/usr/bin/env python3
"""
generate_tcp_syn.py - TCP SYN Scan Traffic Generator
------------------------------------------------------
Simulates repeated TCP SYN packets without completing the handshake.
This is the core pattern used in port scanning and is one of the
primary behavioral indicators the analyzer is designed to detect.

Two modes:
  --scan   : Send SYN packets to multiple ports on one target (port scan)
  --flood  : Send many SYN packets to one port from one source

Usage:
    sudo python3 generate_tcp_syn.py -t 192.168.1.5 --scan
    sudo python3 generate_tcp_syn.py -t 192.168.1.5 --flood -p 80 -c 20

Ethical note: Only run against hosts you own or have explicit
authorization to test. This script is designed for isolated lab use.
"""

import argparse
import time
from scapy.all import IP, TCP, send, conf

conf.verb = 0


# Common ports used in a typical port scan scenario
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080
]


def syn_port_scan(target: str, ports: list, interval: float):
    """Send SYN packets to multiple ports on a single target."""
    print(f"[*] TCP SYN port scan -> {target}")
    print(f"    Ports  : {ports}")
    print(f"    Total  : {len(ports)} SYN packets")
    print(f"    Note   : No ACK will be sent. Handshake intentionally incomplete.\n")

    for port in ports:
        packet = IP(dst=target) / TCP(dport=port, flags="S")
        send(packet)
        print(f"    SYN -> {target}:{port}")
        time.sleep(interval)

    print(f"\n[*] Done. Sent {len(ports)} SYN packets to {target}.")
    print(f"    The analyzer should flag this as a possible port scan.")


def syn_flood(target: str, port: int, count: int, interval: float):
    """Send many SYN packets to a single port without completing the handshake."""
    print(f"[*] TCP SYN flood -> {target}:{port}")
    print(f"    Count  : {count} packets")
    print(f"    Note   : No ACK will be sent. Handshake intentionally incomplete.\n")

    for i in range(1, count + 1):
        packet = IP(dst=target) / TCP(dport=port, flags="S")
        send(packet)
        print(f"    [{i}/{count}] SYN -> {target}:{port}")
        time.sleep(interval)

    print(f"\n[*] Done. Sent {count} SYN packets.")
    print(f"    The analyzer should raise a SYN flood alert.")


def parse_args():
    parser = argparse.ArgumentParser(
        description="TCP SYN scan / flood traffic generator for lab testing."
    )
    parser.add_argument("-t", "--target", type=str, required=True,
                        help="Target IP address.")
    parser.add_argument("-p", "--port", type=int, default=80,
                        help="Target port for flood mode. Default: 80.")
    parser.add_argument("-c", "--count", type=int, default=20,
                        help="Packet count for flood mode. Default: 20.")
    parser.add_argument("--interval", type=float, default=0.1,
                        help="Seconds between packets. Default: 0.1.")
    parser.add_argument("--scan", action="store_true",
                        help="Port scan mode: SYN to multiple common ports.")
    parser.add_argument("--flood", action="store_true",
                        help="Flood mode: many SYN packets to one port.")
    parser.add_argument("--ports", nargs="+", type=int,
                        help="Custom port list for scan mode.")
    return parser.parse_args()


def main():
    args = parse_args()

    if not args.scan and not args.flood:
        print("[!] Specify --scan or --flood.")
        return

    if args.scan:
        ports = args.ports if args.ports else COMMON_PORTS
        syn_port_scan(args.target, ports, args.interval)

    if args.flood:
        syn_flood(args.target, args.port, args.count, args.interval)


if __name__ == "__main__":
    main()
