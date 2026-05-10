# Testing Guide

Step-by-step instructions for testing the packet sniffer on Kali Linux.

---

## Setup

```bash
git clone https://github.com/saged0/packet-sniffer-protocol-analyzer
cd packet-sniffer-protocol-analyzer

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

Verify Scapy is working:

```bash
sudo python3 -c "from scapy.all import sniff; print('Scapy working')"
```

---

## Running the Tool

You need two terminals open at the same time. The analyzer runs in one, traffic generators run in the other.

**Terminal 1 — Start the analyzer:**

```bash
sudo python3 main.py -i eth0
```

Replace `eth0` with your interface name. Check yours with `ip a`.

To also save output:

```bash
sudo python3 main.py -i eth0 -o results/capture.csv --pcap results/capture.pcap
```

---

## Generating Test Traffic

Wait a few seconds for the analyzer to start, then run any of these in Terminal 2.

**DNS queries (no sudo needed, good starting point):**

```bash
python3 scripts/generate_dns.py --normal -c 8
```

**Suspicious DNS queries that trigger anomaly alerts:**

```bash
python3 scripts/generate_dns.py --dga -c 10
python3 scripts/generate_dns.py --tunnel -c 5
```

**Cleartext HTTP sessions:**

```bash
python3 scripts/generate_http.py --demo
```

**ICMP host discovery (requires sudo and a target IP):**

```bash
sudo python3 scripts/generate_icmp.py -t 192.168.1.5 -c 15
```

**TCP SYN port scan (requires sudo and a target IP):**

```bash
sudo python3 scripts/generate_tcp_syn.py -t 192.168.1.5 --scan
```

**Run everything at once:**

```bash
sudo python3 scripts/run_all_scenarios.py -t 192.168.1.5
```

---

## What to Look For

While traffic is being generated, watch Terminal 1 for:

- Packets printing in real time with protocol, source, destination, and port info
- Color-coded alerts when suspicious patterns are detected
- A session summary when you stop the capture with Ctrl+C

---

## Analyzing Output

**Open the CSV in a spreadsheet:**

```bash
head -20 results/capture.csv
```

**Open the PCAP in Wireshark for side-by-side comparison:**

```bash
wireshark results/capture.pcap
```

---

## Troubleshooting

**Permission denied:** Make sure you are using `sudo` for the analyzer and for any TCP or ICMP scripts.

**No packets showing up:** Make sure the traffic generator is actually running in Terminal 2 and that you specified the correct interface with `-i`.

**Module not found:** Make sure you are running from the project root directory, not from inside a subfolder.
