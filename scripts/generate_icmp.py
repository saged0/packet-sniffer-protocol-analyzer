#!/usr/bin/env python3
"""
generate_icmp.py - ICMP Host Discovery Traffic Generator
----------------------------------------------------------
Simulates ICMP echo request (ping) traffic for host discovery testing.
Sends a configurable number of echo requests to a target IP or range.

Usage:
    sudo python3 generate_icmp.py -t 192.168.1.1
    sudo python3 generate_icmp.py -t 192.168.1.1 -c 20 --flood
    sudo python3 generate_icmp.py --range 192.168.1.1 192.168.1.10

Ethical note: Only run against hosts you own or have explicit
authorization to test. This script is designed for isolated lab use.
"""

import argparse
import time
from scapy.all import IP, ICMP, send, conf

conf.verb = 0  # Suppress Scapy output


def send_icmp(target: str, count: int, interval: float, payload_size: int):
    """Send ICMP echo requests to a single target."""
    print(f"[*] Sending {count} ICMP echo requests to {target}")
    print(f"    Interval: {interval}s  Payload size: {payload_size} bytes\n")

    for i in range(1, count + 1):
        packet = IP(dst=target) / ICMP() / (b"X" * payload_size)
        send(packet)
        print(f"    [{i}/{count}] ICMP echo request -> {target}")
        time.sleep(interval)

    print(f"\n[*] Done. Sent {count} echo requests to {target}.")


def send_icmp_range(start_ip: str, end_ip: str, interval: float):
    """Send one ICMP echo request to each IP in a range."""
    # Parse the range from the last octet
    prefix = ".".join(start_ip.split(".")[:3])
    start  = int(start_ip.split(".")[-1])
    end    = int(end_ip.split(".")[-1])

    targets = [f"{prefix}.{i}" for i in range(start, end + 1)]
    print(f"[*] Scanning range {start_ip} to {end_ip} ({len(targets)} hosts)")
    print(f"    This simulates a ping sweep / host discovery scenario.\n")

    for target in targets:
        packet = IP(dst=target) / ICMP()
        send(packet)
        print(f"    ICMP echo request -> {target}")
        time.sleep(interval)

    print(f"\n[*] Done. Sent {len(targets)} echo requests across range.")


def parse_args():
    parser = argparse.ArgumentParser(
        description="ICMP host discovery traffic generator for lab testing."
    )
    parser.add_argument("-t", "--target", type=str, help="Single target IP address.")
    parser.add_argument("-c", "--count", type=int, default=15,
                        help="Number of echo requests to send. Default: 15.")
    parser.add_argument("--interval", type=float, default=0.2,
                        help="Seconds between packets. Default: 0.2.")
    parser.add_argument("--payload-size", type=int, default=56,
                        help="ICMP payload size in bytes. Default: 56.")
    parser.add_argument("--range", nargs=2, metavar=("START_IP", "END_IP"),
                        help="Send one ping to each IP in a range (e.g. 192.168.1.1 192.168.1.20).")
    return parser.parse_args()


def main():
    args = parse_args()

    if not args.target and not args.range:
        print("[!] Provide either -t <target> or --range <start> <end>.")
        return

    if args.range:
        send_icmp_range(args.range[0], args.range[1], args.interval)
    else:
        send_icmp(args.target, args.count, args.interval, args.payload_size)


if __name__ == "__main__":
    main()
