"""
filter.py - Filter Module
--------------------------
Determines whether a captured packet is relevant to the analyzer's scope.
Supports filtering by protocol: TCP, UDP, ICMP, DNS, HTTP, or all.

The filter module does NOT extract fields. It only classifies packets
as in-scope or out-of-scope for the current session.
"""

from scapy.all import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS
from scapy.layers.http import HTTPRequest


class FilterModule:
    """
    Checks each packet against the configured protocol filter.
    Returns True if the packet matches, False otherwise.
    """

    SUPPORTED = {"all", "tcp", "udp", "icmp", "dns", "http"}

    def __init__(self, protocol="all"):
        """
        Parameters
        ----------
        protocol : str
            One of: all, tcp, udp, icmp, dns, http.
        """
        protocol = protocol.lower()
        if protocol not in self.SUPPORTED:
            raise ValueError(f"Unsupported protocol filter: {protocol}")
        self.protocol = protocol

    def matches(self, packet) -> bool:
        """
        Returns True if the packet matches the configured protocol filter.

        Parameters
        ----------
        packet : scapy Packet
            Raw packet from the capture engine.
        """
        # Must have an IP layer to be useful
        if not packet.haslayer(IP):
            return False

        if self.protocol == "all":
            return self._is_supported_protocol(packet)
        elif self.protocol == "tcp":
            return packet.haslayer(TCP)
        elif self.protocol == "udp":
            return packet.haslayer(UDP)
        elif self.protocol == "icmp":
            return packet.haslayer(ICMP)
        elif self.protocol == "dns":
            return packet.haslayer(DNS)
        elif self.protocol == "http":
            return packet.haslayer(HTTPRequest)
        return False

    def _is_supported_protocol(self, packet) -> bool:
        """Returns True if the packet contains at least one supported protocol."""
        return (
            packet.haslayer(TCP) or
            packet.haslayer(UDP) or
            packet.haslayer(ICMP) or
            packet.haslayer(DNS) or
            packet.haslayer(HTTPRequest)
        )
