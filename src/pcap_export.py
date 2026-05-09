"""
pcap_export.py - PCAP Export Module
Saves captured packets as a .pcap file openable in Wireshark.
"""
import os
from scapy.all import wrpcap

class PCAPExporter:
    def __init__(self, output_path: str):
        self.output_path = output_path
        self._packets = []

    def add(self, packet):
        """Store a raw Scapy packet for later export."""
        self._packets.append(packet)

    def write(self):
        """Write all buffered packets to the .pcap file."""
        if not self._packets:
            print("[!] No packets to export.")
            return
        
        # Create directory if it doesn't exist
        output_dir = os.path.dirname(self.output_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        wrpcap(self.output_path, self._packets)
        print(f"[*] PCAP saved to {self.output_path}")
        print(f"    {len(self._packets)} packets written.")
        print(f"    Open in Wireshark: wireshark {self.output_path}")

    def packet_count(self) -> int:
        return len(self._packets)
