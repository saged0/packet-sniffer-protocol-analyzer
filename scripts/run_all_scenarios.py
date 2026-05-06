#!/usr/bin/env python3
"""
run_all_scenarios.py - Master Lab Scenario Runner
---------------------------------------------------
Runs all traffic generation scenarios in sequence to produce
a complete test capture session for evaluation and demonstration.

This script is designed to be run alongside the packet analyzer
on the same machine or a second VM in the lab network.

Usage (on the traffic generator VM):
    python3 run_all_scenarios.py --target 192.168.1.5

The analyzer should be running on the target or a monitoring VM:
    sudo python3 ../main.py -i eth0 -o results/full_test.csv

What this script generates:
    1. Normal DNS queries (baseline)
    2. ICMP host discovery ping sweep
    3. TCP SYN port scan
    4. TCP SYN flood
    5. DGA-style DNS queries (anomaly)
    6. DNS tunnel-style queries (anomaly)
    7. Cleartext HTTP GET and POST requests

Expected analyzer behavior:
    - SYN flood and port scan should trigger SYN alerts
    - ICMP sweep should trigger ICMP flood alert
    - DGA and tunnel DNS should trigger DNS anomaly alerts
    - HTTP requests should trigger cleartext HTTP alerts
"""

import argparse
import subprocess
import sys
import time


def run(cmd: list, label: str):
    print(f"\n{'=' * 60}")
    print(f"  SCENARIO: {label}")
    print(f"{'=' * 60}")
    result = subprocess.run(cmd, capture_output=False)
    time.sleep(1)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run all lab traffic generation scenarios."
    )
    parser.add_argument("-t", "--target", type=str, required=True,
                        help="Target IP address for ICMP and TCP scenarios.")
    parser.add_argument("--skip-http", action="store_true",
                        help="Skip HTTP scenarios (requires internet or local server).")
    return parser.parse_args()


def main():
    args = parse_args()
    target = args.target
    py = sys.executable

    print("=" * 60)
    print("  Full Lab Scenario Runner")
    print(f"  Target: {target}")
    print("=" * 60)
    print("  Starting in 3 seconds... Make sure the analyzer is running.")
    time.sleep(3)

    # 1. Normal DNS - baseline traffic
    run(
        [py, "generate_dns.py", "--normal", "-c", "8"],
        "Normal DNS Queries (baseline)"
    )

    # 2. ICMP ping sweep
    run(
        [py, "generate_icmp.py", "-t", target, "-c", "15", "--interval", "0.1"],
        "ICMP Echo Requests - Host Discovery"
    )

    # 3. TCP SYN port scan
    run(
        [py, "generate_tcp_syn.py", "-t", target, "--scan"],
        "TCP SYN Port Scan (20 common ports)"
    )

    # 4. TCP SYN flood
    run(
        [py, "generate_tcp_syn.py", "-t", target, "--flood",
         "-p", "80", "-c", "20", "--interval", "0.05"],
        "TCP SYN Flood (port 80)"
    )

    # 5. DGA-style DNS
    run(
        [py, "generate_dns.py", "--dga", "-c", "10"],
        "DGA-Style DNS Queries (high entropy)"
    )

    # 6. DNS tunnel-style
    run(
        [py, "generate_dns.py", "--tunnel", "-c", "5"],
        "DNS Tunnel-Style Queries (long subdomains)"
    )

    # 7. HTTP cleartext
    if not args.skip_http:
        run(
            [py, "generate_http.py", "--demo"],
            "Cleartext HTTP Sessions"
        )

    print("\n" + "=" * 60)
    print("  All scenarios complete.")
    print("  Check the analyzer output for alerts and the CSV for records.")
    print("=" * 60)


if __name__ == "__main__":
    main()
