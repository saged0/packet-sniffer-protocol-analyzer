# packet-sniffer-protocol-analyzer

A Python-based network protocol analyzer and packet sniffer for capturing, filtering, parsing, and reporting TCP, UDP, ICMP, DNS, and HTTP traffic in a controlled Kali Linux lab.

Built as part of the COSC 489 final project at Bowie State University, Spring 2026.

---

## Features

- Live packet capture from any network interface using Scapy
- Protocol-based filtering: TCP, UDP, ICMP, DNS, HTTP, or all
- Field-level parsing: IP/MAC addresses, ports, timestamps, TCP flags, DNS query names, HTTP request data
- Real-time console output with color-coded alerts
- Behavioral detection:
  - TCP SYN flood / port scan detection
  - ICMP echo request flood / host discovery detection
  - Cleartext HTTP session detection
  - DNS anomaly detection (DGA indicators: long names, high entropy)
- Optional CSV export for post-capture analysis
- Designed for controlled lab use only

---

## Requirements

- Kali Linux (or any Debian-based Linux with root access)
- Python 3.7+
- Scapy 2.5.0+

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Usage

Must be run with `sudo` because raw packet capture requires root privileges.

```bash
# Capture all protocols on default interface
sudo python3 main.py

# Capture on a specific interface
sudo python3 main.py -i eth0

# Filter to TCP only
sudo python3 main.py -i eth0 -p tcp

# Capture 100 packets then stop
sudo python3 main.py -i eth0 -c 100

# Save results to CSV
sudo python3 main.py -i eth0 -o results/capture.csv

# Set custom SYN alert threshold
sudo python3 main.py -i eth0 --syn-threshold 3
```

### All options

| Flag | Description | Default |
|------|-------------|---------|
| `-i` | Network interface | Scapy default |
| `-p` | Protocol filter: all, tcp, udp, icmp, dns, http | all |
| `-c` | Packet count (0 = unlimited) | 0 |
| `-o` | CSV output file path | None |
| `--syn-threshold` | SYN packets before alert | 5 |

---

## Lab Traffic Generation

Use the provided scripts in `scripts/` to generate test traffic for analyzer evaluation:

```bash
# Generate normal DNS baseline traffic
python3 scripts/generate_dns.py --normal -c 8

# Generate DGA-style (high-entropy) DNS queries
python3 scripts/generate_dns.py --dga -c 10

# Generate DNS tunnel-style queries (long subdomains)
python3 scripts/generate_dns.py --tunnel -c 5

# Generate ICMP host discovery (ping sweep)
sudo python3 scripts/generate_icmp.py -t 192.168.1.5 -c 15

# Generate TCP SYN port scan
sudo python3 scripts/generate_tcp_syn.py -t 192.168.1.5 --scan

# Generate TCP SYN flood
sudo python3 scripts/generate_tcp_syn.py -t 192.168.1.5 --flood -p 80 -c 20

# Generate cleartext HTTP traffic
python3 scripts/generate_http.py --demo

# Run all scenarios in sequence (recommended for full testing)
python3 scripts/run_all_scenarios.py -t 192.168.1.5
```

**Note:** Run the analyzer in one terminal while traffic generators run in another to capture and alert on suspicious activity.

---

## Project Structure

```
packet-sniffer-protocol-analyzer/
├── src/                          # Core source modules
│   ├── __init__.py
│   ├── capture.py               # Capture engine (Scapy sniff wrapper)
│   ├── filter.py                # Protocol-based packet filtering
│   ├── parser.py                # Field extraction and record building
│   └── report.py                # Console output, alerts, CSV export
├── scripts/                      # Utility and traffic generation scripts
│   ├── generate_dns.py          # DNS traffic generator (normal, DGA, tunnel)
│   ├── generate_http.py         # Cleartext HTTP traffic generator
│   ├── generate_icmp.py         # ICMP host discovery traffic generator
│   ├── generate_tcp_syn.py      # TCP SYN scan/flood traffic generator
│   └── run_all_scenarios.py     # Master scenario runner for full lab tests
├── tests/                        # Unit tests and integration tests
├── docs/                         # Documentation, papers, and guides
├── main.py                       # Entry point and argument parsing
├── requirements.txt              # Python dependencies
├── pyproject.toml               # Project metadata and configuration
├── .gitignore                   # Git ignore rules
├── README.md                    # This file
├── CHANGELOG.md                 # Version history
├── CONTRIBUTING.md              # Contribution guidelines
├── LICENSE.md                   # License and ethical guidelines
├── STRUCTURE.md                 # Detailed architecture documentation
└── results/                     # CSV output files (gitignored)
```

### Architecture Overview

- **src/**: Core functionality organized as a Python package
  - Modular design with separation of concerns (capture → filter → parse → report)
  - Each module handles one responsibility
  - Importable as `from src.capture import CaptureEngine`

- **scripts/**: Lab testing and traffic generation utilities
  - Standalone scripts for generating test traffic
  - No sudo required for DNS and HTTP generators
  - Run together with `run_all_scenarios.py` for comprehensive testing

- **tests/**: Placeholder for unit and integration tests
  
- **docs/**: Project documentation, research papers, and guides

---

## Ethical Considerations

This tool is intended strictly for use in authorized, controlled lab environments. All testing was performed on isolated virtual machines using traffic generated by the research team. No external networks, third-party systems, or real user data were involved at any stage.

Unauthorized use of packet capture tools is illegal under the Electronic Communications Privacy Act (18 U.S.C. §§ 2510–2523) and similar laws in other jurisdictions. Do not use this tool on any network you do not own or have explicit written authorization to monitor.

---

## Development

### Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/packet-sniffer-protocol-analyzer.git
cd packet-sniffer-protocol-analyzer

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Running Tests

```bash
# Add tests to tests/ directory
python3 -m pytest tests/
```

### Code Style

- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) guidelines
- Use type hints where practical
- Add docstrings to functions and classes
- Include comments for complex logic

See [CONTRIBUTING.md](./CONTRIBUTING.md) for detailed guidelines.

---

## Authors

Bowie State University — Department of Computer Science  
COSC 489: Ethical Hacking / COSC 442: Cybersecurity and Society  
Spring 2026  
Instructor: Devharsh Trivedi, Ph.D., CISSP
