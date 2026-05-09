#!/usr/bin/env python3
"""
Network Protocol Analyzer and Packet Sniffer
Bowie State University - COSC 489
Spring 2026

Entry point for the packet analyzer. Run with sudo on Kali Linux.
Usage: sudo python3 main.py -i <interface> [-p <protocol>] [-c <count>] [-o <output.csv>]
"""

import argparse
import sys
from src.capture import CaptureEngine
from src.filter import FilterModule
from src.parser import ParserModule
from src.report import ReportingModule
from src.pcap_export import PCAPExporter


def parse_args():
    parser = argparse.ArgumentParser(
        description="Network Protocol Analyzer and Packet Sniffer"
    )
    parser.add_argument(
        "-i", "--interface",
        type=str,
        default=None,
        help="Network interface to capture on (e.g. eth0). Default: Scapy default."
    )
    parser.add_argument(
        "-p", "--protocol",
        type=str,
        default="all",
        choices=["all", "tcp", "udp", "icmp", "dns", "http"],
        help="Protocol filter. Default: all."
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=0,
        help="Number of packets to capture. 0 = unlimited. Default: 0."
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default=None,
        help="Optional CSV output file path (e.g. results/capture.csv)."
    )
    parser.add_argument(
        "--syn-threshold",
        type=int,
        default=5,
        help="Number of SYN packets from one source before alerting. Default: 5."
    )
    parser.add_argument(
        "--pcap",
        type=str,
        default=None,
        help="PCAP output file path (e.g. results/capture.pcap)."
    )
    return parser.parse_args()


def main():
    args = parse_args()

    print("=" * 60)
    print("  Network Protocol Analyzer and Packet Sniffer")
    print("  Bowie State University - Spring 2026")
    print("=" * 60)
    print(f"  Interface : {args.interface or 'default'}")
    print(f"  Protocol  : {args.protocol}")
    print(f"  Count     : {args.count if args.count > 0 else 'unlimited'}")
    print(f"  Output    : {args.output or 'console only'}")
    print(f"  PCAP      : {args.pcap or 'none'}")
    print(f"  SYN Alert : {args.syn_threshold} packets")
    print("=" * 60)
    print("  Starting capture... Press Ctrl+C to stop.\n")

    # Initialize modules
    report = ReportingModule(
        output_file=args.output,
        syn_threshold=args.syn_threshold
    )
    parser_mod = ParserModule()
    filter_mod = FilterModule(protocol=args.protocol)
    pcap_exp = PCAPExporter(args.pcap) if args.pcap else None

    def process_packet(packet):
        """Callback passed to the capture engine for each packet."""
        # Capture raw packet for PCAP export
        if pcap_exp:
            pcap_exp.add(packet)
        # Step 1: Filter
        if not filter_mod.matches(packet):
            return
        # Step 2: Parse
        record = parser_mod.parse(packet)
        if record is None:
            return
        # Step 3: Report
        report.handle(record)

    # Step 4: Capture
    engine = CaptureEngine(
        interface=args.interface,
        count=args.count,
        callback=process_packet
    )

    try:
        engine.start()
    except KeyboardInterrupt:
        print("\n\n[*] Capture stopped by user.")
    finally:
        report.summary()
        if args.output:
            report.write_csv()
            print(f"[*] Results saved to {args.output}")
        if pcap_exp:
            pcap_exp.write()


if __name__ == "__main__":
    if sys.version_info < (3, 7):
        print("[!] Python 3.7 or higher required.")
        sys.exit(1)
    main()
