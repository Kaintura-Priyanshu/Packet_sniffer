# Packet Sniffer 

**Professional packet sniffer tool for network analysis and monitoring.**

---

## Description

| Module | Description |
|--------|-------------|
| **sniffer.py** | Captures, parses, and displays network packets with detailed protocol analysis |
| **analyzer.py** | Parses raw packet data into structured, human-readable protocol information |
| **config.py** | Centralized configuration settings for packet sniffer customization and tuning |
| **monitor.py** | Real-time network traffic monitor with curses-based visual interface display |

---

## Features

-  Real-time packet capture on any network interface
-  Protocol analysis for TCP, UDP, ICMP, and more
-  Human-readable output with detailed packet inspection
-  Statistics collection with protocol distribution
-  File output for packet logging and analysis
-  Verbose mode for detailed packet information
-  Configurable capture with packet count limits
-  Well-documented code for educational purposes
-  Interactive curses-based monitoring interface

---

## Requirements

- Python 3.6 or higher
- Kali Linux or other Linux distribution
- Root/Administrator privileges for packet capture
- Standard library only (no external dependencies)

---

## Installation

# Clone the repository
git clone https://github.com/Kaintura_Priyanshu/Packet_sniffer.git
cd Packet_sniffer

# Make scripts executable
chmod +x sniffer.py monitor.py

# Verify installation
python3 sniffer.py --help

# Usage
Basic Commands

# Run with default settings (requires sudo)
sudo python3 sniffer.py

# Specify interface
sudo python3 sniffer.py -i eth0

# Verbose mode (show packet details)
sudo python3 sniffer.py -v

# Limit number of packets
sudo python3 sniffer.py -c 100

# Save output to file
sudo python3 sniffer.py -o capture.log

# Combine options
sudo python3 sniffer.py -i wlan0 -v -c 50 -o wifi_capture.log

# Launch interactive monitor
sudo python3 monitor.py -i eth0

# Command Line Options
Option	Description
-i, --interface	Network interface to sniff on
-c, --count	Number of packets to capture
-o, --output	Output file for captured packets
-v, --verbose	Enable verbose output
-h, --help	Show help message

# Output Example

[*] Starting packet capture on interface: eth0
[*] Press Ctrl+C to stop capture

================================================================================

[14:32:15.123] Protocol: TCP | Length: 1514 bytes
  ├─ Ethernet: aa:bb:cc:dd:ee:ff -> 11:22:33:44:55:66
  ├─ IP: 192.168.1.100 -> 192.168.1.1 (TTL: 64)
  ├─ TCP: Port 54321 -> 80 (SYN,ACK)
  └─ Payload: 485454502f312e3120323030204f4b0d0a...

[14:32:15.125] Protocol: UDP | Length: 78 bytes
  ├─ Ethernet: aa:bb:cc:dd:ee:ff -> 11:22:33:44:55:66
  ├─ IP: 192.168.1.100 -> 8.8.8.8 (TTL: 64)
  ├─ UDP: Port 54321 -> 53
# Statistics Summary
After stopping the capture:

================================================================================
CAPTURE SUMMARY
================================================================================
Total Packets: 500
Duration: 10.23 seconds
Average: 48.87 packets/sec

Protocol Distribution:
  TCP: 350 packets (70.0%)
  UDP: 120 packets (24.0%)
  ICMP: 30 packets (6.0%)

Top Source IP Addresses:
  192.168.1.100: 250 packets
  192.168.1.101: 150 packets
  8.8.8.8: 100 packets

Top Destination IP Addresses:
  192.168.1.1: 200 packets
  192.168.1.102: 180 packets
  8.8.4.4: 120 packets
================================================================================
# Project Structure

packet_sniffer/
├── sniffer.py          # Main packet sniffer
├── analyzer.py         # Packet analysis module
├── config.py           # Configuration settings
├── monitor.py          # Real-time monitoring interface
├── requirements.txt    # Dependencies
└── README.md          # Documentation
# Configuration
Edit config.py to customize:

class SnifferConfig:
    DEFAULT_INTERFACE = None        # Use default interface
    BUFFER_SIZE = 65535             # Maximum packet size
    SOCKET_TIMEOUT = 1.0            # Socket timeout in seconds
    MAX_PAYLOAD_DISPLAY = 50        # Maximum payload bytes to display
    FILTER_PROTOCOLS = None         # e.g., ['TCP', 'UDP', 'ICMP']
    LOG_LEVEL = 'INFO'              # DEBUG, INFO, WARNING, ERROR

# Security & Legal Notice
# IMPORTANT: This tool is for educational and authorized network analysis purposes only. Unauthorized packet sniffing may violate laws and network policies in your jurisdiction. Always ensure you have proper authorization before using this tool.

# Troubleshooting
Issue	Solution
Permission denied	Run with sudo
No such device	Check interface name with ip link show
No packets captured	Ensure interface is active and has traffic
ImportError	Use Python 3.6+ or install missing modules
License
This project is licensed under the MIT License - see the LICENSE file for details.

## Quick Start

# One-liner to start capturing
sudo python3 sniffer.py -v -c 10

# Monitor live traffic
sudo python3 monitor.py

# Save to file for later analysis
sudo python3 sniffer.py -o capture.log -c 1000
Made with for the security community

Remember: With great power comes great responsibility.


