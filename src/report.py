"""
report.py - Reporting Module
-----------------------------
Converts parsed packet records into readable console output and
flags simple behavioral indicators consistent with reconnaissance
activity or insecure data transmission.

Behavioral alerts supported:
  - Repeated TCP SYN packets from one source (possible port scan)
  - High-frequency ICMP echo requests (possible host discovery)
  - Cleartext HTTP sessions exposing request data
  - DNS queries with high-entropy or unusually long names (DGA indicator)

All records can also be exported to CSV for further analysis.
"""

import csv
import math
import string
from collections import defaultdict


# ANSI color codes for terminal output
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"


def _entropy(s: str) -> float:
    """Calculate Shannon entropy of a string. Higher = more random."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((f / length) * math.log2(f / length) for f in freq.values())


class ReportingModule:
    """
    Handles console output and behavioral alert logic.
    Maintains session-level state to detect patterns across packets.
    """

    # A domain name longer than this triggers a DGA length alert
    DGA_LENGTH_THRESHOLD = 30
    # Shannon entropy above this triggers a DGA entropy alert
    DGA_ENTROPY_THRESHOLD = 3.5
    # ICMP echo requests per source before alerting
    ICMP_FLOOD_THRESHOLD = 10

    def __init__(self, output_file=None, syn_threshold=5):
        """
        Parameters
        ----------
        output_file : str or None
            Path to write CSV output. None = console only.
        syn_threshold : int
            Number of SYN packets from one source before raising alert.
        """
        self.output_file = output_file
        self.syn_threshold = syn_threshold

        # Session state for behavioral detection
        self._syn_counts = defaultdict(int)       # src_ip -> SYN count
        self._syn_alerted = set()                 # sources already alerted
        self._icmp_echo_counts = defaultdict(int) # src_ip -> echo request count
        self._icmp_alerted = set()
        self._http_cleartext_count = 0
        self._dns_alert_count = 0

        # All records collected this session
        self._records = []

        # Summary counters
        self._proto_counts = defaultdict(int)
        self._total = 0

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def handle(self, record: dict):
        """Process one parsed packet record."""
        self._total += 1
        self._proto_counts[record["protocol"]] += 1
        self._records.append(record)

        self._print_record(record)
        self._check_alerts(record)

    def summary(self):
        """Print a session summary after capture ends."""
        print("\n" + "=" * 60)
        print(f"{BOLD}  Session Summary{RESET}")
        print("=" * 60)
        print(f"  Total packets captured : {self._total}")
        print()
        print("  Protocol breakdown:")
        for proto, count in sorted(self._proto_counts.items()):
            print(f"    {proto:<8} : {count}")
        print()
        print("  Behavioral alerts:")
        print(f"    SYN flood alerts     : {len(self._syn_alerted)}")
        print(f"    ICMP flood alerts    : {len(self._icmp_alerted)}")
        print(f"    HTTP cleartext       : {self._http_cleartext_count} session(s)")
        print(f"    DNS anomaly alerts   : {self._dns_alert_count}")
        print("=" * 60)

    def write_csv(self):
        """Write all captured records to a CSV file."""
        if not self._records:
            print("[!] No records to write.")
            return
        fieldnames = list(self._records[0].keys())
        with open(self.output_file, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(self._records)

    # ------------------------------------------------------------------
    # Console output
    # ------------------------------------------------------------------

    def _print_record(self, record: dict):
        """Print a formatted one-line summary of a packet."""
        proto = record["protocol"]
        ts    = record["timestamp"]
        src   = record["src_ip"]
        dst   = record["dst_ip"]
        length = record["length"]

        # Base line
        line = f"[{ts}] {proto:<5} {src:<16} -> {dst:<16} len={length}"

        # Protocol-specific additions
        if proto in ("TCP", "HTTP") and record["src_port"]:
            line += f" sport={record['src_port']} dport={record['dst_port']}"
        if proto == "TCP" and record["tcp_flags"]:
            line += f" flags={record['tcp_flags']}"
        if proto == "UDP" and record["src_port"]:
            line += f" sport={record['src_port']} dport={record['dst_port']}"
        if proto == "ICMP":
            line += f" type={record['icmp_type']} code={record['icmp_code']}"
        if proto == "DNS" and record["dns_query"]:
            line += f" query={record['dns_query']}"
        if proto == "HTTP":
            if record["http_method"]:
                line += f" {record['http_method']} {record.get('http_host','')}{record.get('http_path','')}"

        print(line)

    # ------------------------------------------------------------------
    # Behavioral alert logic
    # ------------------------------------------------------------------

    def _check_alerts(self, record: dict):
        """Run all behavioral checks against the current record."""
        self._check_syn_flood(record)
        self._check_icmp_flood(record)
        self._check_http_cleartext(record)
        self._check_dns_anomaly(record)

    def _check_syn_flood(self, record: dict):
        """Alert if a single source sends repeated SYN-only packets."""
        if record["protocol"] != "TCP":
            return
        if record["tcp_flags"] != "SYN":
            return
        src = record["src_ip"]
        self._syn_counts[src] += 1
        if (self._syn_counts[src] >= self.syn_threshold
                and src not in self._syn_alerted):
            self._syn_alerted.add(src)
            print(
                f"\n{RED}{BOLD}[ALERT] Possible port scan detected!{RESET}"
                f"\n        Source : {src}"
                f"\n        SYN packets without completed handshake : "
                f"{self._syn_counts[src]}\n"
            )

    def _check_icmp_flood(self, record: dict):
        """Alert if a single source sends many ICMP echo requests."""
        if record["protocol"] != "ICMP":
            return
        if record["icmp_type"] != 8:  # 8 = echo request
            return
        src = record["src_ip"]
        self._icmp_echo_counts[src] += 1
        if (self._icmp_echo_counts[src] >= self.ICMP_FLOOD_THRESHOLD
                and src not in self._icmp_alerted):
            self._icmp_alerted.add(src)
            print(
                f"\n{YELLOW}{BOLD}[ALERT] Possible host discovery / ICMP flood!{RESET}"
                f"\n        Source : {src}"
                f"\n        ICMP echo requests : {self._icmp_echo_counts[src]}\n"
            )

    def _check_http_cleartext(self, record: dict):
        """Alert when HTTP request data is visible in cleartext."""
        if record["protocol"] != "HTTP":
            return
        if record["http_method"]:
            self._http_cleartext_count += 1
            print(
                f"\n{YELLOW}{BOLD}[ALERT] Cleartext HTTP session detected!{RESET}"
                f"\n        Source  : {record['src_ip']}"
                f"\n        Method  : {record['http_method']}"
                f"\n        Host    : {record.get('http_host', 'N/A')}"
                f"\n        Path    : {record.get('http_path', 'N/A')}"
                f"\n        Warning : Request data is visible to any observer"
                f" on this network segment.\n"
            )

    def _check_dns_anomaly(self, record: dict):
        """
        Alert on DNS queries with characteristics associated with
        domain generation algorithms: unusually long names or
        high Shannon entropy in the subdomain portion.
        """
        if record["protocol"] != "DNS":
            return
        query = record.get("dns_query")
        if not query:
            return

        # Extract the leftmost label (subdomain) for entropy analysis
        parts = query.split(".")
        subdomain = parts[0] if parts else query

        alerted = False
        reason = []

        if len(query) > self.DGA_LENGTH_THRESHOLD:
            reason.append(f"name length={len(query)} (threshold={self.DGA_LENGTH_THRESHOLD})")
            alerted = True

        ent = _entropy(subdomain)
        if ent > self.DGA_ENTROPY_THRESHOLD:
            reason.append(f"subdomain entropy={ent:.2f} (threshold={self.DGA_ENTROPY_THRESHOLD})")
            alerted = True

        if alerted:
            self._dns_alert_count += 1
            print(
                f"\n{CYAN}{BOLD}[ALERT] Suspicious DNS query detected!{RESET}"
                f"\n        Source : {record['src_ip']}"
                f"\n        Query  : {query}"
                f"\n        Reason : {'; '.join(reason)}\n"
            )
