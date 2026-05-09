"""
capture.py - Capture Engine
----------------------------
Responsible for binding to a network interface and collecting
packets in real time using Scapy's sniff() function.

The capture engine does NOT make detection or parsing decisions.
Its only job is to collect packets and forward them to the callback.
"""

from scapy.all import sniff, conf, IP, TCP, UDP, ICMP


class CaptureEngine:
    """
    Binds to a network interface and captures packets.
    Each packet is forwarded to the provided callback function.
    """

    def __init__(self, interface=None, count=0, callback=None):
        """
        Parameters
        ----------
        interface : str or None
            Network interface name (e.g. 'eth0'). None uses Scapy default.
        count : int
            Number of packets to capture. 0 = unlimited.
        callback : callable
            Function to call for each captured packet.
        """
        self.interface = interface
        self.count = count
        self.callback = callback

        if self.interface:
            conf.iface = self.interface

    def start(self):
        """
        Begin packet capture. Blocks until count is reached
        or the user interrupts with Ctrl+C.
        """
        sniff(
            iface=self.interface,
            prn=self.callback,
            count=self.count,
            store=False  # Do not store packets in memory; process on the fly
        )
