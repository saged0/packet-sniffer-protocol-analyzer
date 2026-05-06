#!/usr/bin/env python3
"""
generate_http.py - Cleartext HTTP Traffic Generator
-----------------------------------------------------
Generates unencrypted HTTP requests to demonstrate that request data
including methods, host headers, paths, and cookies is visible
in cleartext to any observer on the same network segment.

This script uses Python's built-in urllib so it does not require sudo.
The analyzer will capture the HTTP packets on the network interface.

Usage:
    python3 generate_http.py --target http://httpbin.org/get
    python3 generate_http.py --demo
    python3 generate_http.py --target http://<lab-server-ip> -c 5

For the lab demo, spin up a simple HTTP server on another VM:
    python3 -m http.server 80

Then point this script at that VM's IP.

Ethical note: Only send cleartext HTTP to servers you control or
have permission to test. Never send credentials over HTTP on a
real network.
"""

import argparse
import time
import urllib.request
import urllib.error


# Demo targets using httpbin.org (a public HTTP testing service)
# Replace with your lab VM IP during the actual demo
DEMO_TARGETS = [
    "http://httpbin.org/get",
    "http://httpbin.org/headers",
    "http://httpbin.org/user-agent",
    "http://httpbin.org/ip",
]


def send_get(url: str, headers: dict = None):
    """Send an HTTP GET request and print the status."""
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            status = response.status
            print(f"    GET {url} -> {status} OK")
    except urllib.error.HTTPError as e:
        print(f"    GET {url} -> HTTP {e.code}")
    except Exception as e:
        print(f"    GET {url} -> ERROR: {e}")


def send_post(url: str, data: bytes):
    """Send an HTTP POST request with a body."""
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            print(f"    POST {url} -> {response.status} OK")
    except urllib.error.HTTPError as e:
        print(f"    POST {url} -> HTTP {e.code}")
    except Exception as e:
        print(f"    POST {url} -> ERROR: {e}")


def run_demo(interval: float):
    """
    Run a demo sequence that exercises GET and POST requests
    and shows what data is visible in cleartext.
    """
    print("[*] Running HTTP cleartext demo sequence.")
    print("    The analyzer should flag each of these as cleartext HTTP sessions.\n")

    print("  [1] Standard GET requests:")
    for url in DEMO_TARGETS:
        send_get(url)
        time.sleep(interval)

    print("\n  [2] GET with custom headers (visible in cleartext):")
    send_get(
        "http://httpbin.org/headers",
        headers={
            "X-Custom-Header": "sensitive-value",
            "Authorization": "Basic dXNlcjpwYXNz"  # base64 user:pass (demo only)
        }
    )
    time.sleep(interval)

    print("\n  [3] POST with form data (visible in cleartext):")
    send_post(
        "http://httpbin.org/post",
        data=b"username=demouser&password=demopass123"
    )
    time.sleep(interval)

    print("\n[*] Demo complete.")
    print("    In a real attack scenario, all of the above data would be")
    print("    readable by any observer on the same network segment.")


def run_target(url: str, count: int, interval: float):
    """Send repeated GET requests to a specific target."""
    print(f"[*] Sending {count} GET requests to {url}\n")
    for i in range(1, count + 1):
        print(f"  [{i}/{count}]", end=" ")
        send_get(url)
        time.sleep(interval)
    print(f"\n[*] Done. {count} HTTP requests sent.")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Cleartext HTTP traffic generator for lab testing."
    )
    parser.add_argument("--target", type=str,
                        help="HTTP URL to send GET requests to.")
    parser.add_argument("-c", "--count", type=int, default=5,
                        help="Number of requests to send. Default: 5.")
    parser.add_argument("--interval", type=float, default=0.5,
                        help="Seconds between requests. Default: 0.5.")
    parser.add_argument("--demo", action="store_true",
                        help="Run the full cleartext demo sequence.")
    return parser.parse_args()


def main():
    args = parse_args()

    if not args.target and not args.demo:
        print("[!] Specify --target <url> or --demo.")
        return

    if args.demo:
        run_demo(args.interval)
    elif args.target:
        run_target(args.target, args.count, args.interval)


if __name__ == "__main__":
    main()
