# Testing Guide

Complete step-by-step instructions for testing the packet sniffer and protocol analyzer on Kali Linux.

## Features Summary

This project includes the following capabilities:

- **Live Packet Capture** - Real-time capture from any network interface
- **Protocol Filtering** - TCP, UDP, ICMP, DNS, HTTP, or all
- **Field-Level Parsing** - IP/MAC, ports, timestamps, TCP flags, DNS queries, HTTP requests
- **Real-Time Alerts** - Color-coded alerts for suspicious activity
- **Behavioral Detection**:
  - TCP SYN flood / port scan detection
  - ICMP echo request flood / host discovery detection
  - Cleartext HTTP session detection
  - DNS anomaly detection (DGA: high entropy, long names)
- **CSV Export** - Save analyzed data for spreadsheet analysis
- **PCAP Export** - Save raw packets for Wireshark inspection
- **Traffic Generators** - Scripts to create test scenarios

---

## Step 1: Clone & Setup the Project

```bash
# Clone the repository
git clone https://github.com/saged0/packet-sniffer-protocol-analyzer
cd packet-sniffer-protocol-analyzer

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## Step 2: Verify Scapy Installation

Test that Scapy is properly installed and working:

```bash
sudo python3 -c "from scapy.all import sniff; print('✓ Scapy working')"
```

You should see: `✓ Scapy working`

---

## Step 3: Open Two Terminals

The analyzer and traffic generators must run **simultaneously** in separate terminals.

---

### Terminal A: Run the Analyzer

Start the packet capture analyzer:

```bash
# Basic capture on eth0, stop after 100 packets
sudo python3 main.py -i eth0 -c 100
```

**Advanced usage with export options:**

```bash
# Capture and export to CSV
sudo python3 main.py -i eth0 -c 100 -o results/capture.csv

# Capture and export to PCAP (Wireshark format)
sudo python3 main.py -i eth0 -c 100 --pcap results/capture.pcap

# Capture to BOTH CSV and PCAP simultaneously
sudo python3 main.py -i eth0 -c 100 -o results/capture.csv --pcap results/capture.pcap

# Filter to TCP only and export
sudo python3 main.py -i eth0 -p tcp -c 100 -o results/tcp.csv --pcap results/tcp.pcap
```

**Expected output:**
```
[*] Starting packet capture...
[*] Packets received: 0
```

The analyzer will wait for incoming packets and display them in real-time.

**All available flags:**
| Flag | Description |
|------|-------------|
| `-i eth0` | Network interface |
| `-p tcp` | Protocol filter (tcp, udp, icmp, dns, http, all) |
| `-c 100` | Packet count (0 = unlimited) |
| `-o path.csv` | Save parsed results to CSV |
| `--pcap path.pcap` | Save raw packets to PCAP (Wireshark compatible) |
| `--syn-threshold 5` | Sensitivity for SYN flood detection |

---

### Terminal B: Generate Test Traffic

Wait a few seconds for the analyzer to start, then generate test traffic in a second terminal.

#### **Option 1: Start Simple (No sudo required)**

Best for first-time testing:

```bash
python3 scripts/generate_dns.py --normal -c 8
```

Watch Terminal A for DNS packet output.

---

#### **Option 2: Run Full Test Suite (Recommended)**

Requires a target IP address (e.g., `192.168.1.5`):

```bash
python3 scripts/run_all_scenarios.py -t 192.168.1.5
```

This generates:
- Normal DNS traffic
- DGA-style DNS (anomalies)
- HTTP cleartext sessions
- TCP SYN patterns
- ICMP ping sweeps

---

#### **Option 3: Test Individual Attack Scenarios**

Test specific detections one at a time:

**DGA-style DNS queries (high entropy anomaly detection):**
```bash
python3 scripts/generate_dns.py --dga -c 10
```

**DNS tunnel-style queries (long subdomain anomaly detection):**
```bash
python3 scripts/generate_dns.py --tunnel -c 5
```

**HTTP cleartext traffic:**
```bash
python3 scripts/generate_http.py --demo
```

**TCP SYN port scan (requires sudo and target IP):**
```bash
sudo python3 scripts/generate_tcp_syn.py -t 192.168.1.5 --scan
```

**TCP SYN flood attack (requires sudo and target IP):**
```bash
sudo python3 scripts/generate_tcp_syn.py -t 192.168.1.5 --flood -p 80 -c 20
```

**ICMP ping sweep / host discovery (requires sudo and target IP):**
```bash
sudo python3 scripts/generate_icmp.py -t 192.168.1.5 -c 15
```

---

## Step 4: Verify Detection Works

In Terminal A, look for:

✓ **Packets displayed** with formatted output  
✓ **Color-coded alerts** for suspicious activity  
✓ **DNS anomalies** flagged (DGA detection)  
✓ **TCP patterns** detected (SYN flood/port scan)  
✓ **ICMP patterns** detected (ping sweep)  
✓ **HTTP sessions** identified (cleartext detection)

---

## Step 5: Export Results (Optional)

Save captured packets to CSV for post-analysis and detailed review.

### Basic CSV Export

```bash
sudo python3 main.py -i eth0 -c 100 -o results/capture.csv
```

Results will be saved to `results/capture.csv` for spreadsheet analysis.

### CSV Export with Filtering

Export only specific protocols to CSV:

**TCP traffic only:**
```bash
sudo python3 main.py -i eth0 -p tcp -c 100 -o results/tcp_capture.csv
```

**DNS traffic only:**
```bash
sudo python3 main.py -i eth0 -p dns -c 100 -o results/dns_capture.csv
```

**HTTP traffic only:**
```bash
sudo python3 main.py -i eth0 -p http -c 100 -o results/http_capture.csv
```

### View the CSV File

**On Kali (using command line):**
```bash
# View first few rows
head -20 results/capture.csv

# View full file with paging
less results/capture.csv

# Count total packets
wc -l results/capture.csv
```

**Transfer to Windows for Excel:**
```bash
# From Windows PowerShell (using SCP or Git)
# Or download via SFTP/file sharing
```

Then open in Excel or Google Sheets for analysis.

### CSV Export During Full Test Scenario

Run all scenarios and capture to CSV:

**Terminal A - Analyzer with CSV output:**
```bash
sudo python3 main.py -i eth0 -c 500 -o results/full_test.csv
```

**Terminal B - Run all scenarios (requires sudo for TCP/ICMP):**
```bash
sudo python3 scripts/run_all_scenarios.py -t 192.168.1.5
```

This will generate a comprehensive `full_test.csv` with all detected traffic and alerts.

---

## Step 6: PCAP Export & Wireshark Analysis

Export raw packets to `.pcap` format for deep inspection in Wireshark.

### Basic PCAP Export

```bash
sudo python3 main.py -i eth0 -c 100 --pcap results/capture.pcap
```

Results will be saved to `results/capture.pcap` for Wireshark inspection.

### PCAP Export with Filtering

**TCP traffic only:**
```bash
sudo python3 main.py -i eth0 -p tcp -c 100 --pcap results/tcp.pcap
```

**DNS traffic only:**
```bash
sudo python3 main.py -i eth0 -p dns -c 100 --pcap results/dns.pcap
```

**HTTP traffic only:**
```bash
sudo python3 main.py -i eth0 -p http -c 100 --pcap results/http.pcap
```

### Open PCAP File in Wireshark

**On Kali (with GUI):**
```bash
wireshark results/capture.pcap &
```

**Or open through Wireshark GUI:**
- File → Open
- Navigate to `results/capture.pcap`
- Click Open

**What you'll see in Wireshark:**
- Full packet details (headers, payloads, checksums)
- Drill down into individual packets
- Packet dissection by protocol layer
- Apply display filters for deeper analysis

### Combined Export (CSV + PCAP)

**Capture everything to both formats:**
```bash
sudo python3 main.py -i eth0 -c 500 -o results/full_test.csv --pcap results/full_test.pcap
```

Then:
- **Excel/Sheets** (CSV) - Summarized alerts and statistics
- **Wireshark** (PCAP) - Raw packet inspection

### PCAP During Full Test Scenario

**Terminal A - Analyzer capturing to PCAP:**
```bash
sudo python3 main.py -i eth0 -c 500 -o results/full_test.csv --pcap results/full_test.pcap
```

**Terminal B - Run all scenarios:**
```bash
sudo python3 scripts/run_all_scenarios.py -t 192.168.1.5
```

**Then analyze:**
```bash
# View in Wireshark
wireshark results/full_test.pcap &

# View CSV summary
cat results/full_test.csv | head -20
```

---

## Complete Workflow Examples

### Scenario 1: Quick DNS Analysis

**Goal:** Capture and analyze DNS traffic only.

**Terminal A:**
```bash
sudo python3 main.py -i eth0 -p dns -c 50 -o results/dns_analysis.csv --pcap results/dns_analysis.pcap
```

**Terminal B:**
```bash
python3 scripts/generate_dns.py --dga -c 10
python3 scripts/generate_dns.py --normal -c 8
python3 scripts/generate_dns.py --tunnel -c 5
```

**Then analyze:**
- `results/dns_analysis.csv` - Anomaly flags and alerts
- Open `results/dns_analysis.pcap` in Wireshark for detailed packet inspection

---

### Scenario 2: Full Attack Simulation

**Goal:** Simulate real attacks and capture comprehensive evidence.

**Terminal A - Analyzer with all exports:**
```bash
sudo python3 main.py -i eth0 -c 500 -o results/attack_lab.csv --pcap results/attack_lab.pcap --syn-threshold 3
```

**Terminal B - Generate all attack scenarios:**
```bash
sudo python3 scripts/run_all_scenarios.py -t 192.168.1.5
```

**Then analyze:**
```bash
# Check alerts in CSV
cat results/attack_lab.csv | grep "ALERT"

# Open PCAP in Wireshark for deep inspection
wireshark results/attack_lab.pcap &
```

---

### Scenario 3: Protocol-Specific Deep Dive

**TCP Analysis:**
```bash
# Terminal A
sudo python3 main.py -i eth0 -p tcp -c 200 -o results/tcp_deep.csv --pcap results/tcp_deep.pcap

# Terminal B
sudo python3 scripts/generate_tcp_syn.py -t 192.168.1.5 --scan
sudo python3 scripts/generate_tcp_syn.py -t 192.168.1.5 --flood -p 80 -c 20
```

**HTTP Analysis:**
```bash
# Terminal A
sudo python3 main.py -i eth0 -p http -c 100 -o results/http_traffic.csv --pcap results/http_traffic.pcap

# Terminal B
python3 scripts/generate_http.py --demo
```

**ICMP Analysis:**
```bash
# Terminal A
sudo python3 main.py -i eth0 -p icmp -c 100 -o results/icmp_sweep.csv --pcap results/icmp_sweep.pcap

# Terminal B
sudo python3 scripts/generate_icmp.py -t 192.168.1.5 -c 15
```

---

### Scenario 4: Export for Report Generation

**Collect comprehensive data:**
```bash
# Run capture with both outputs for 5 minutes (300 packets max)
sudo python3 main.py -i eth0 -c 300 -o results/report_data.csv --pcap results/report_data.pcap
```

**Generate traffic:**
```bash
sudo python3 scripts/run_all_scenarios.py -t 192.168.1.5
```

**Then create report:**
```bash
# CSV for statistics and spreadsheet
cat results/report_data.csv

# PCAP for forensic analysis
wireshark results/report_data.pcap &

# Count packets by protocol
grep "UDP" results/report_data.csv | wc -l
grep "DNS" results/report_data.csv | wc -l
grep "ALERT" results/report_data.csv | wc -l
```

---

## Troubleshooting

**Solution:** Make sure you're using `sudo`:
```bash
sudo python3 main.py -i eth0 -c 100
```

### Issue: No packets captured

**Checklist:**
1. Is the traffic generator running in Terminal B?
2. Is the correct interface specified? (Check with `ip a`)
3. Are you on the same network/VM as the traffic?

### Issue: Scapy import error

**Solution:** Reinstall in venv:
```bash
source venv/bin/activate
pip install --upgrade scapy
```

### Issue: "No module named 'src'"

**Solution:** Run from the project root directory:
```bash
pwd  # Should output: /path/to/packet-sniffer-protocol-analyzer
python3 main.py -i eth0
```

---

## Testing Workflow Summary

### Quick Start (DNS Testing)

1. **Terminal A:** `sudo python3 main.py -i eth0 -c 100`
2. **Wait 2-3 seconds for analyzer to start**
3. **Terminal B:** `python3 scripts/generate_dns.py --normal -c 8`
4. **Observe** packets and alerts in Terminal A
5. **View results** in console

### Full Test Suite (All Protocols)

1. **Terminal A:** `sudo python3 main.py -i eth0 -c 500 -o results/test.csv --pcap results/test.pcap`
2. **Wait 2-3 seconds**
3. **Terminal B:** `sudo python3 scripts/run_all_scenarios.py -t 192.168.1.5`
4. **Monitor** real-time alerts in Terminal A
5. **Analyze results:**
   - CSV: `cat results/test.csv | head -20`
   - PCAP: `wireshark results/test.pcap &`

### Protocol-Specific Testing

```bash
# TCP Analysis
sudo python3 main.py -i eth0 -p tcp --pcap results/tcp.pcap &
sudo python3 scripts/generate_tcp_syn.py -t 192.168.1.5 --flood -p 80 -c 20

# DNS Analysis
sudo python3 main.py -i eth0 -p dns -o results/dns.csv --pcap results/dns.pcap &
python3 scripts/generate_dns.py --dga -c 10

# HTTP Analysis
sudo python3 main.py -i eth0 -p http -o results/http.csv --pcap results/http.pcap &
python3 scripts/generate_http.py --demo

# ICMP Analysis
sudo python3 main.py -i eth0 -p icmp --pcap results/icmp.pcap &
sudo python3 scripts/generate_icmp.py -t 192.168.1.5 -c 15
```

---

## Success Criteria & Validation

### Console Output

- ✓ Analyzer starts: `"Starting capture..."` displayed
- ✓ Packets received: `"Packets received: X"` updates in real-time
- ✓ Alerts shown: Color-coded alerts for suspicious traffic
- ✓ Normal termination: `"Capture stopped by user"` message

### CSV Export

- ✓ File created: `results/test.csv` exists
- ✓ Contains data: `wc -l results/test.csv` shows packet count
- ✓ Headers present: `head -1 results/test.csv` shows column names
- ✓ Alerts logged: `grep "ALERT" results/test.csv` returns flagged packets

### PCAP Export

- ✓ File created: `results/test.pcap` exists
- ✓ Opens in Wireshark: `wireshark results/test.pcap` displays packets
- ✓ Packet count matches: Wireshark shows same count as analyzer
- ✓ All protocols visible: Can filter by TCP, UDP, DNS, ICMP, HTTP

### Feature Detection

✓ **DNS Anomalies** - DGA/tunnel queries flagged with high entropy/long names  
✓ **TCP Patterns** - SYN flood and port scans detected  
✓ **ICMP Patterns** - Host discovery sweeps detected  
✓ **HTTP Sessions** - Cleartext HTTP requests identified  
✓ **Real-Time Alerts** - Suspicious activity flagged immediately  
✓ **Data Exports** - Both CSV (analysis) and PCAP (forensics) functional

---

## Project Features Checklist

- [x] Live packet capture from network interface
- [x] Protocol-based filtering (TCP, UDP, ICMP, DNS, HTTP, All)
- [x] Field-level parsing (IP, MAC, ports, timestamps, flags, etc.)
- [x] Real-time console output with color-coded alerts
- [x] TCP SYN flood / port scan detection
- [x] ICMP echo request flood / host discovery detection
- [x] Cleartext HTTP session detection
- [x] DNS anomaly detection (DGA/high entropy)
- [x] CSV export for post-capture analysis
- [x] PCAP export for Wireshark inspection
- [x] Traffic generation scripts for testing
- [x] Documentation and testing guide
