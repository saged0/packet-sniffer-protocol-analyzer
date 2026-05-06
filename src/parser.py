"""
parser.py - Parser Module
--------------------------
Extracts structured field-level information from filtered packets.
Transforms raw packet data into a dictionary record that can be
consumed by the reporting module.

Fields extracted per protocol:
  All packets : timestamp, src_ip, dst_ip, src_mac, dst_mac, length, protocol
  TCP         : src_port, dst_port, tcp_flags
  UDP         : src_port, dst_port
  ICMP        : icmp_type, icmp_code, icmp_payload_size
  DNS         : dns_query
  HTTP        : http_method, http_host, http_path
"""

from datetime import datetime
from scapy.all import IP, TCP, UDP, ICMP, Ether
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.http import HTTPRequest


# Map integer TCP flag values to human-readable strings
TCP_FLAG_MAP = {
    0x002: "SYN",
    0x010: "ACK",
    0x001: "FIN",
    0x004: "RST",
    0x008: "PSH",
    0x020: "URG",
    0x012: "SYN-ACK",
    0x011: "FIN-ACK",
    0x018: "PSH-ACK",
}


def decode_tcp_flags(flags_int) -> str:
    """Convert a TCP flags integer to a readable string."""
    if flags_int in TCP_FLAG_MAP:
        return TCP_FLAG_MAP[flags_int]
    # Build a custom string for uncommon combinations
    result = []
    if flags_int & 0x002:
        result.append("SYN")
    if flags_int & 0x010:
        result.append("ACK")
    if flags_int & 0x001:
        result.append("FIN")
    if flags_int & 0x004:
        result.append("RST")
    if flags_int & 0x008:
        result.append("PSH")
    if flags_int & 0x020:
        result.append("URG")
    return "-".join(result) if result else str(flags_int)


class ParserModule:
    """
    Parses a filtered packet into a structured dictionary record.
    Returns None if the packet cannot be meaningfully parsed.
    """

    def parse(self, packet) -> dict | None:
        """
        Extract fields from a packet and return a record dictionary.

        Parameters
        ----------
        packet : scapy Packet

        Returns
        -------
        dict or None
        """
        if not packet.haslayer(IP):
            return None

        ip = packet[IP]
        record = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"),
            "src_ip": ip.src,
            "dst_ip": ip.dst,
            "src_mac": packet[Ether].src if packet.haslayer(Ether) else "N/A",
            "dst_mac": packet[Ether].dst if packet.haslayer(Ether) else "N/A",
            "length": len(packet),
            "protocol": self._detect_protocol(packet),
            "src_port": None,
            "dst_port": None,
            "tcp_flags": None,
            "icmp_type": None,
            "icmp_code": None,
            "icmp_payload_size": None,
            "dns_query": None,
            "http_method": None,
            "http_host": None,
            "http_path": None,
        }

        # TCP
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            record["src_port"] = tcp.sport
            record["dst_port"] = tcp.dport
            record["tcp_flags"] = decode_tcp_flags(int(tcp.flags))

        # UDP
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            record["src_port"] = udp.sport
            record["dst_port"] = udp.dport

        # ICMP
        if packet.haslayer(ICMP):
            icmp = packet[ICMP]
            record["icmp_type"] = icmp.type
            record["icmp_code"] = icmp.code
            # Payload size helps identify covert channel anomalies
            record["icmp_payload_size"] = len(icmp.payload)

        # DNS - extract query name when present
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            try:
                record["dns_query"] = packet[DNSQR].qname.decode("utf-8").rstrip(".")
            except Exception:
                record["dns_query"] = "undecodable"

        # HTTP - extract request fields from cleartext traffic
        if packet.haslayer(HTTPRequest):
            http = packet[HTTPRequest]
            try:
                record["http_method"] = http.Method.decode("utf-8") if http.Method else None
                record["http_host"] = http.Host.decode("utf-8") if http.Host else None
                record["http_path"] = http.Path.decode("utf-8") if http.Path else None
            except Exception:
                pass

        return record

    def _detect_protocol(self, packet) -> str:
        """Return a human-readable label for the highest-level protocol detected."""
        if packet.haslayer(HTTPRequest):
            return "HTTP"
        if packet.haslayer(DNS):
            return "DNS"
        if packet.haslayer(TCP):
            return "TCP"
        if packet.haslayer(UDP):
            return "UDP"
        if packet.haslayer(ICMP):
            return "ICMP"
        return "OTHER"
