# 🛡️ Basic Network Sniffer | Python & Scapy

### A Python-Based Network Traffic Capture and Packet Analysis Tool

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python)](https://www.python.org/)
[![Scapy](https://img.shields.io/badge/Library-Scapy-orange)](https://scapy.net/)
[![Platform](https://img.shields.io/badge/Platform-Kali%20Linux%20%7C%20Linux-black)](https://www.kali.org/)
[![Status](https://img.shields.io/badge/Project-Completed-success)](https://github.com/KUMAWAT2005/NETWORK-SNIFFER)

**Developed by:** Ritesh Kumawat  
**GitHub:** [KUMAWAT2005](https://github.com/KUMAWAT2005)  
**Repository:** [Basic Network Sniffer](https://github.com/KUMAWAT2005/NETWORK-SNIFFER)  
**Internship:** Code Alpha – Cybersecurity Internship  
**Task:** Basic Network Sniffer

---

## 📌 1. About the Project

The **Basic Network Sniffer** is a Python-based cybersecurity project developed using the Scapy library.

It captures and analyzes network packets from a selected network interface. It helps users understand how data travels across networks and how different network protocols communicate with each other.

The program displays important packet information, including source and destination IP addresses, protocols, port numbers, TCP flags, packet sizes, and limited payload previews.

It also provides packet statistics and saves captured packet metadata into a CSV file for further analysis.

This project is designed for beginners who want to understand network communication, packet structures, and basic network analysis.

## 🎯 2. Project Objectives

The main objectives of this project are:

- Capture network traffic using Python and Scapy.
- Understand the structure and content of network packets.
- Identify common network protocols.
- Display source and destination IP addresses.
- Analyze TCP and UDP port information.
- Inspect limited packet payload data.
- Understand how information travels between network devices.
- Store packet information in CSV format.
- Generate traffic statistics for basic network analysis.

## ✨ 3. Key Features

| Feature | Description |
|---|---|
| Packet Capturing | Captures authorized network traffic using Scapy. |
| Protocol Identification | Identifies TCP, UDP, ICMP, ICMPv6, ARP, IPv4 and IPv6. |
| IP Address Analysis | Displays source and destination addresses. |
| Port Analysis | Displays TCP/UDP source and destination ports. |
| TCP Flags | Displays flags such as SYN, ACK, FIN and PSH. |
| DNS Analysis | Displays decoded DNS query names when available. |
| Payload Inspection | Provides limited printable-text and hexadecimal previews. |
| Protocol Filtering | Allows users to focus on selected protocols. |
| CSV Logging | Saves packet metadata for later analysis. |
| Traffic Statistics | Displays packet counts, packet sizes, protocols and top addresses. |

## 🛠️ 4. Technologies Used

- **Programming Language:** Python
- **Packet Capture Library:** Scapy
- **Network Interface:** Wireless or Ethernet interface
- **Operating System:** Kali Linux / Linux
- **Data Storage:** CSV
- **Testing:** Python Unit Testing
- **Version Control:** Git and GitHub

## 📂 5. Project Structure

```text
NETWORK-SNIFFER/
│
├── basic_network_sniffer.py
│
├── requirements.txt
│
├── README.md
│
├── tests/
│   └── test_packet_summary.py
│
└── logs/
    └── packets.csv
```

**Note:** The `logs/` directory and CSV file are generated during execution. They should not be committed with private packet-capture data.

## 💻 6. Installation and Setup

### Step 1: Requirements

Before starting, make sure you have:

- Kali Linux or another supported Linux distribution.
- Python 3.9 or newer.
- Internet connection for installing dependencies.
- A supported network interface.
- Appropriate permissions to capture network traffic.

### Step 2: Clone the GitHub Repository

Open your terminal and execute:

```bash
git clone https://github.com/KUMAWAT2005/NETWORK-SNIFFER.git
```

### Step 3: Open the Project Directory

```bash
cd NETWORK-SNIFFER
```

### Step 4: Identify Your Network Interface

```bash
ip -br link
```

Example interfaces:

```text
lo
eth0
wlan0
```

Your interface name may be different. Use the interface connected to the network you are authorized to monitor.

### Step 5: Install Dependencies

**Recommended method for Kali Linux:**

```bash
sudo apt update
sudo apt install python3-scapy tcpdump
```

Alternatively, install the Python dependencies inside a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## 🚀 7. How to Run the Project

### Basic Packet Capture

Capture 20 packets:

```bash
sudo python3 basic_network_sniffer.py \
  --iface wlan0 \
  --count 20
```

### TCP Packet Filtering

Capture only TCP packets:

```bash
sudo python3 basic_network_sniffer.py \
  --iface wlan0 \
  --protocol tcp \
  --count 20
```

### UDP Packet Filtering

```bash
sudo python3 basic_network_sniffer.py \
  --iface wlan0 \
  --protocol udp \
  --count 20
```

### DNS Packet Analysis

```bash
sudo python3 basic_network_sniffer.py \
  --iface wlan0 \
  --protocol dns \
  --count 10
```

Generate DNS traffic from another terminal:

```bash
nslookup example.com
```

### Payload Inspection

Display both text and hexadecimal payload previews:

```bash
sudo python3 basic_network_sniffer.py \
  --iface wlan0 \
  --protocol tcp \
  --payload-format both \
  --payload-bytes 32 \
  --count 20
```

### Custom Network Filter

Capture traffic involving a particular authorized host:

```bash
sudo python3 basic_network_sniffer.py \
  --iface wlan0 \
  --filter 'host 192.168.1.1' \
  --count 20
```

### Continuous Packet Capture

```bash
sudo python3 basic_network_sniffer.py \
  --iface wlan0
```

Press `CTRL + C` to stop the capture.

**Important:** Replace `wlan0` with your actual network interface name.

If Scapy is installed inside a virtual environment, use its interpreter:

```bash
sudo ./.venv/bin/python basic_network_sniffer.py \
  --iface wlan0 \
  --count 20
```

## 📊 8. Understanding the Output

The program displays useful information about captured network packets.

| Output Field | Meaning |
|---|---|
| Timestamp | Time when the packet was captured. |
| Source | IP address from which the packet originated. |
| Destination | IP address receiving the packet. |
| Protocol | Protocol identified in the packet. |
| Ports | Source and destination TCP/UDP ports, when available. |
| TCP Flags | TCP communication control flags. |
| Payload | Limited preview of available raw packet data. |
| Packet Size | Total size of the captured Scapy packet. |
| Service Hint | Common service associated with a port number. |

### Example

```text
BASIC NETWORK SNIFFER | RITESH KUMAWAT

Interface:      wlan0
Protocol focus: TCP

Packet #1 TCP / IPv4

Source:       192.168.1.7
Destination:  192.168.1.5

Ports:        58224 -> 8009
TCP flags:    PA

Service hint: Common port information
Payload:      Limited text/hex preview
Size:         176 bytes
```

*Illustrative example. Actual results depend on your network traffic.*

## 📈 9. Packet Statistics

After packet capture, the program generates a statistics summary.

It includes:

- Total packets captured.
- Capture duration.
- Average packet rate.
- Total packet size.
- Decoded raw payload bytes.
- Packets grouped by protocol.
- Packets grouped by network layer.
- Top source IP addresses.
- Top destination IP addresses.
- Observed DNS query names, when available.

These statistics help users understand the amount and type of traffic observed during a capture session.

## 📁 10. CSV Packet Logging

The program automatically stores packet metadata in:

```text
logs/packets.csv
```

The CSV file contains information such as:

- Timestamp
- Network interface
- Protocol
- IP version
- Source IP
- Destination IP
- Source port
- Destination port
- TCP flags
- DNS query
- Packet size
- Raw payload byte count

View the latest captured records:

```bash
tail -n 10 logs/packets.csv
```

To view the CSV file:

```bash
cat logs/packets.csv
```

To include limited payload previews in the CSV, use:

```bash
sudo python3 basic_network_sniffer.py \
  --iface wlan0 \
  --count 20 \
  --log-payload
```

To disable CSV logging:

```bash
sudo python3 basic_network_sniffer.py \
  --iface wlan0 \
  --count 20 \
  --no-csv
```

**Privacy note:** Payloads can contain sensitive information. The project stores metadata by default and does not save payload previews unless explicitly enabled.

## 🧪 11. Testing and Verification

The project includes automated unit tests to verify important packet-analysis functions.

### Check Python Syntax

```bash
python3 -m py_compile basic_network_sniffer.py
```

### Run Unit Tests

```bash
python3 -m unittest discover -s tests -v
```

The tests cover:

- ARP address and protocol identification.
- Capture-filter construction.
- DNS query decoding.
- IPv4 and TCP packet information.
- IPv6 and UDP packet information.
- Payload-preview extraction.

**Verified test result from development:**

```text
Ran 5 tests

OK
```

## 🔐 12. Security and Privacy Considerations

Network packet capture must always be performed responsibly.

Follow these practices:

- Capture only traffic on networks you own or have explicit permission to monitor.
- Do not inspect private communications without authorization.
- Avoid saving unnecessary payload information.
- Keep packet logs private.
- Do not upload sensitive packet captures to public GitHub repositories.
- Use appropriate permissions when running the program.

## ⚠️ 13. Project Limitations

- Packet capture requires appropriate permissions.
- The program depends on the selected interface and capture backend.
- Protocol filters restrict which packets are captured.
- Some packet content may already be decoded by Scapy instead of appearing in the Raw layer.
- Encrypted HTTPS/TLS content normally cannot be displayed as readable application data.
- Port-based service hints do not guarantee the actual application running on a port.
- The default capture filter focuses on IPv4, IPv6 and ARP traffic, not every possible link-layer frame.

## 📚 14. Learning Outcomes

Through this project, I gained practical experience in:

1. Understanding network packet structures.
2. Working with the Scapy Python library.
3. Identifying common networking protocols.
4. Understanding TCP and UDP communication.
5. Inspecting IP addresses and port numbers.
6. Understanding DNS traffic.
7. Capturing and analyzing network traffic.
8. Working with CSV files for packet logging.
9. Using Linux terminal commands.
10. Performing basic Python unit testing.

## 🎓 15. Code Alpha Internship Task

**Task: Basic Network Sniffer**

This project was developed as part of the Code Alpha Cybersecurity Internship.

The implementation addresses the assigned requirements:

- Build a Python program to capture network packets.
- Analyze captured packets to understand their structure and content.
- Learn how data flows through networks.
- Use Scapy for packet capturing.
- Display source and destination IP addresses, protocols and payload previews.

## 👨‍💻 16. Author

**Ritesh Kumawat**

Cybersecurity Enthusiast | Network Security Learner | Python Developer

GitHub Profile: [https://github.com/KUMAWAT2005](https://github.com/KUMAWAT2005)

Project Repository: [https://github.com/KUMAWAT2005/NETWORK-SNIFFER](https://github.com/KUMAWAT2005/NETWORK-SNIFFER)

---

### ⭐ Support

If you find this project useful for learning Python, networking or cybersecurity, consider giving the repository a star on GitHub.

**Thank you for visiting my project!**

*Built with Python and Scapy | Code Alpha Cybersecurity Internship*
