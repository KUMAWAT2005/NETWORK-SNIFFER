# Project Report: Basic Network Sniffer

## 1. Objective

Build a Python program that captures network packets, analyzes selected packet fields, introduces common network protocols, and displays source/destination addresses and payload information when available.

## 2. Tools and technologies

- **Python:** Main programming language.
- **Scapy:** Packet capture and packet-field decoding.
- **CSV module:** Saves packet metadata in a structured table.
- **argparse:** Provides command-line options for interface, protocol, payload preview, and capture count.

## 3. Main workflow

1. The user selects a network interface and optional protocol/BPF filter.
2. Scapy captures matching packets.
3. For each packet, the program identifies the network layer and common transport protocol.
4. It displays source and destination addresses, available ports, TCP flags or ICMP details, decoded DNS query names, packet size, and a bounded raw-payload preview.
5. Packet metadata is appended to a CSV file by default; payload previews are omitted from CSV unless explicitly enabled.
6. When capture stops, the program prints summary statistics.

## 4. Key fields demonstrated

- Source and destination IP addresses
- IPv4 and IPv6
- TCP, UDP, ICMP/ICMPv6, and ARP
- TCP/UDP port numbers and TCP flags
- DNS query names when decoded by Scapy
- Packet size and available undecoded raw-layer bytes
- Limited text/hex payload preview

## 5. How to run

```bash
sudo python3 basic_network_sniffer.py --iface wlan0 --count 20
```

Confirm the correct interface with `ip -br link`. Use the appropriate dependency installation commands in the README if Scapy or the packet-capture backend is missing.

## 6. Validation

- Run `python3 -m py_compile basic_network_sniffer.py` to check for Python syntax errors.
- Run `python3 -m unittest discover -s tests -v` to test packet-field extraction and filter construction.
- Run a limited capture on an authorized interface and confirm the output and `logs/packets.csv`.

## 7. Limitations and privacy

The program only analyzes packets visible at the selected interface and matching the selected filter. Payload previews show only Scapy's undecoded `Raw` layer, not necessarily all application data. Encryption commonly makes payload data unreadable. Logs can contain sensitive network metadata, so runtime logs should not be committed to a public GitHub repository.

## 8. Conclusion

The project gives practical experience with packet capture, network-layer addresses, transport protocols, ports, flags, DNS, payload representation, CSV logging, and basic traffic statistics.
