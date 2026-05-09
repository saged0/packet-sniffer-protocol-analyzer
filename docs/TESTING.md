# Testing Guide

Complete step-by-step instructions for testing the packet sniffer and protocol analyzer on Kali Linux.

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
# Capture packets on eth0, stop after 100 packets
sudo python3 main.py -i eth0 -c 100
```

**Expected output:**
```
[*] Starting packet capture...
[*] Packets received: 0
```

The analyzer will wait for incoming packets and display them in real-time.

**Common flags:**
- `-i eth0` - Specify network interface
- `-c 100` - Stop after 100 packets
- `-p tcp` - Filter to TCP only (optional)
- `-o results/capture.csv` - Save to CSV (optional)

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

Save captured packets to CSV for post-analysis:

```bash
sudo python3 main.py -i eth0 -c 100 -o results/capture.csv
```

Results will be saved to `results/capture.csv` for spreadsheet analysis.

---

## Troubleshooting

### Issue: "Permission denied" on packet capture

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

1. **Terminal A:** `sudo python3 main.py -i eth0 -c 100`
2. **Wait 2-3 seconds**
3. **Terminal B:** `python3 scripts/generate_dns.py --normal -c 8`
4. **Observe** packets and alerts in Terminal A
5. **Repeat** with different generators to test all features

---

## Success Criteria

- ✓ Analyzer starts and awaits packets
- ✓ DNS traffic captured and displayed
- ✓ DGA anomalies detected and alerted
- ✓ TCP patterns recognized
- ✓ Results exportable to CSV
