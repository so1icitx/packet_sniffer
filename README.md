# so1dump: Packet Sniffer

## Overview
so1dump is a Python-based tool for capturing and analyzing network packets (TCP, UDP, ICMP) on a specified interface. It parses packet details, supports hex dumps, and offers AbuseIPDB lookups for IP reputation, with output in CSV, JSON, or text formats. It’s a work in progress, and i could add more stuff in future

## Purpose
so1dump monitors network traffic to reveal source/destination IPs, ports, and protocol data, useful for security testing, network debugging, or CTF challenges.

## Features
- Captures TCP, UDP, and ICMP packets with details like IPs, ports, and flags.
- Filters by protocol (`tcp`, `udp`, `icmp`) or captures all (`all`).
- Outputs to CSV, JSON (clean format), or text files.
- Quiet mode to save results without terminal output.
- Optional hex dump of packet data using the `hexdump` library.
- AbuseIPDB lookup for destination IP reputation (requires API key).
- Supports specific network interface binding.

## Installation
1. Clone the repo:
   ```bash
   git clone https://github.com/so1icitx/so1dump.git
   cd so1dump
   ```
2. Install dependencies (Python 3.6+ required):
   ```bash
   pip install requests hexdump
   ```
3. Run with root privileges (required for raw sockets):
   ```bash
   sudo python3 so1dump.v.1.0.9.py
   ```

## Usage
Run so1dump with command-line arguments to capture packets and customize output.

### Command-Line Options
| Option | Description | Example |
|--------|-------------|---------|
| `-p`, `--protocol` | Protocol to capture: `all`, `tcp`, `udp`, `icmp` (default: `all`). | `-p tcp` |
| `-i`, `--interface` | Network interface (default: `all`). | `-i eth0` |
| `-f`, `--file` | Output format: `csv`, `json`, `txt` (default: none). | `-f json` |
| `-n`, `--name` | Output file path (required with `-f`). | `-n capture.json` |
| `-X`, `--hex-dump` | Display raw packet hex dump. | `-X` |
| `--quiet` | Suppress terminal output, save to file. | `--quiet` |
| `-a`, `--abuse-check` | Enable AbuseIPDB lookup for destination IPs. | `-a` |

### Examples
1. Capture all packets on default interface:
   ```bash
   python3 so1dump.v.1.0.0.py
   ```
   **Output**:
   ```
   13:00:00.123456 IP 192.168.1.1:80 -> 192.168.1.100:12345 TCP Flags[SYN, ACK], ack 123456, win 65535, length 0
   13:00:00.124000 IP 192.168.1.2:53 -> 192.168.1.100:54321 UDP, length 32
   ```

2. Capture TCP packets with hex dump and JSON output:
   ```bash
   python3 so1dump.v.1.0.0.py -p tcp -f json -n capture.json -X
   ```
   **Output**:
   ```
   13:00:00.123456 IP 192.168.1.1:80 -> 192.168.1.100:12345 TCP Flags[SYN, ACK], ack 123456, win 65535, length 20
   00000000:  47 45 54 20 2F 20 48 54  54 50 2F 31 2E 31 0D 0A  GET / HTTP/1.1..
   00000010:  48 6F 73 74 3A 20 65 78  61 6D 70 6C 65 2E 63 6F  Host: example.co
   ```
   **Output File (capture.json)**:
   ```
   {
     "time": "13:00:00.123456",
     "src_ip": "192.168.1.1",
     "src_port": 80,
     "dest_ip": "192.168.1.100",
     "dest_port": 12345,
     "flags": "SYN, ACK",
     "ack_number": 123456,
     "window_size": 65535,
     "length": 20,
     "hex": "00000000:  47 45 54 20 2F 20 48 54  54 50 2F 31 2E 31 0D 0A\n00000010:  48 6F 73 74 3A 20 65 78  61 6D 70 6C 65 2E 63 6F"
   }
   {
     "time": "13:00:00.124000",
     "src_ip": "192.168.1.1",
     "src_port": 80,
     "dest_ip": "192.168.1.100",
     "dest_port": 54321,
     "flags": "ACK",
     "ack_number": 123457,
     "window_size": 65535,
     "length": 0
   }
   ```

3. Capture UDP packets with AbuseIPDB lookup and CSV output, quiet mode:
   ```bash
   python3 so1dump.v.1.0.0.py -p udp -f csv -n capture.csv -a --quiet
   ```
   **Output File (capture.csv)**:
   ```
   time,src_ip,src_port,dest_ip,dest_port,length
   13:00:00.124000,192.168.1.2,53,192.168.1.100,54321,32
   ```

## Disclaimer
Use so1dump responsibly and only on networks you have permission to monitor. Unauthorized use may violate laws or terms of service.
