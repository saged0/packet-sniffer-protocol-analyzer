# Testing Guide

Step-by-step instructions for testing the packet sniffer on Kali Linux.

---

## Step 1: Clone and Install

```bash
git clone https://github.com/saged0/packet-sniffer-protocol-analyzer
cd packet-sniffer-protocol-analyzer
```

### Choose one of these installation methods:

**Option A: Virtual Environment (Recommended)**

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

When using a virtual environment, replace `sudo python3` with `sudo venv/bin/python` in every command below. This is important because sudo does not inherit the virtual environment by default.

**Option B: System install (if venv gives you issues)**

```bash
pip install -r requirements.txt --break-system-packages
```

Then use `sudo python3` as normal in every command below.

**Option C: Install via apt (simplest fix if pip fails)**

```bash
sudo apt install python3-scapy -y
```

Then use `sudo python3` as normal in every command below.

---

> **Note on Virtual Environments:**
> 
> You only need to activate the virtual environment to install the dependencies. You do not need to be inside the virtual environment to run the project commands. However, if you installed Scapy inside the virtual environment (Option A), you must use `sudo venv/bin/python` instead of `sudo python3` when running the analyzer, because sudo does not inherit the virtual environment and will use the system Python instead.
>
> If you installed Scapy using apt (Option C) or the `--break-system-packages` flag (Option B), you do not need a virtual environment at all and can use `sudo python3` for all commands.

---

## Step 2: Verify Scapy is Working

Run whichever matches your installation method:

**If you used Option A (venv):**
```bash
venv/bin/python -c "from scapy.all import sniff; print('Scapy working')"
```

**If you used Option B or C (system install):**
```bash
sudo python3 -c "from scapy.all import sniff; print('Scapy working')"
```

You should see: `Scapy working`

If you see an error, go back to Step 1 and try a different installation option.

---

## Step 3: Open Two Terminals

The analyzer and traffic generators must run at the same time in separate terminals.

---

## Terminal 1 — Start the Analyzer

Replace `eth0` with your actual interface name. Check yours with:
```bash
ip a
```

**If you used Option A (venv):**
```bash
sudo venv/bin/python main.py -i eth0
```

**If you used Option B or C (system install):**
```bash
sudo python3 main.py -i eth0
```


To save output to CSV and PCAP at the same time:

**Option A:**
```bash
sudo venv/bin/python main.py -i eth0 -o results/capture.csv --pcap results/capture.pcap
```

**Option B or C:**
```bash
sudo python3 main.py -i eth0 -o results/capture.csv --pcap results/capture.pcap
```

---

## Terminal 2 — Generate Test Traffic

Wait a few seconds for the analyzer to start, then run any of these.

**DNS queries (no sudo needed, best place to start):**
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

**Run all scenarios at once:**
```bash
sudo python3 scripts/run_all_scenarios.py -t 192.168.1.5
```

---

## Step 4: What to Look For

While traffic is being generated, watch Terminal 1 for:

- Packets printing in real time with protocol, source, destination, and port info
- Color-coded alerts when suspicious patterns are detected
- A session summary when you stop the capture with Ctrl+C

---

## Step 5: Analyze Output

**View the CSV:**
```bash
head -20 results/capture.csv
```

**Open the PCAP in Wireshark for side-by-side comparison:**
```bash
wireshark results/capture.pcap
```

---

## Troubleshooting

**Scapy not found after installing in venv**

Make sure you are using `venv/bin/python` instead of `python3` when running with sudo:
```bash
sudo venv/bin/python main.py -i eth0
```

**pip install fails with "externally-managed-environment"**

Use one of these:
```bash
pip install -r requirements.txt --break-system-packages
# or
sudo apt install python3-scapy -y
```

**Permission denied**

Always use sudo for the analyzer and for any TCP or ICMP scripts.

**No packets showing up**

- Make sure the traffic generator is running in Terminal 2
- Check your interface name with `ip a` and pass it with `-i`
- Make sure your VM network adapter is set to Bridged mode, not NAT

**Module not found**

Make sure you are running from the project root directory:
```bash
cd packet-sniffer-protocol-analyzer
sudo python3 main.py -i eth0
```
