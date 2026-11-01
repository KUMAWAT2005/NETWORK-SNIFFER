# Basic Network Sniffer (Python + Scapy)

**Code Alpha Internship Task — Basic Network Sniffer**

A beginner-friendly command-line program that captures authorized network traffic, explains selected packet fields, shows a limited payload preview, writes packet metadata to CSV, and summarizes the captured traffic.

## Features mapped to the internship task

- **Capture packets:** Uses Python and Scapy to listen on a selected network interface.
- **Analyze packet structure:** Identifies IPv4/IPv6/ARP and common transport protocols (TCP, UDP, ICMP/ICMPv6).
- **Display useful information:** Shows timestamp, source and destination addresses, ports when available, TCP flags, ICMP type/code, decoded DNS query names, packet size, and common port hints.
- **Payload preview:** Displays a limited, sanitized printable-text and/or hexadecimal preview of Scapy's undecoded `Raw` layer.
- **Understand traffic flow:** Optional protocol filters let you focus on TCP, UDP, ICMP, ARP, or DNS packets.
- **Save results:** Appends packet metadata to `logs/packets.csv`; payload previews are not written to CSV unless explicitly enabled.
- **Statistics:** Prints packet totals, capture duration, average packet rate, byte totals, protocol/network-layer counts, top addresses, and observed DNS query names when available.

## Requirements

- Kali Linux or another Linux system with a supported network interface.
- Python 3.9 or newer recommended.
- Scapy and a packet-capture backend such as libpcap/tcpdump.
- Permission to capture traffic on the selected interface.

## Install on Kali Linux

Recommended system-package installation:

```bash
sudo apt update
sudo apt install python3-scapy tcpdump
```

Alternatively, use a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

If Scapy is installed inside `.venv`, run the program with that interpreter so `sudo` uses the same environment:

```bash
sudo ./.venv/bin/python basic_network_sniffer.py --iface wlan0 --count 20
```

## Find your network interface

```bash
ip -br link
```

Use the interface name shown on your system, such as `wlan0` or `eth0`. It may be different on your computer.

## Run examples

Capture 20 packets from common IPv4, IPv6, and ARP traffic:

```bash
sudo python3 basic_network_sniffer.py --iface wlan0 --count 20
```

Focus on TCP packets and display both text and hexadecimal payload previews (up to 32 bytes):

```bash
sudo python3 basic_network_sniffer.py \
  --iface wlan0 \
  --protocol tcp \
  --payload-format both \
  --payload-bytes 32 \
  --count 20
```

Focus on DNS packets while generating a DNS lookup in another terminal:

```bash
sudo python3 basic_network_sniffer.py --iface wlan0 --protocol dns --count 10
```

In another terminal, run:

```bash
nslookup example.com
```

Capture only traffic matching an additional BPF filter, such as a particular host:

```bash
sudo python3 basic_network_sniffer.py --iface wlan0 --filter 'host 192.168.1.1' --count 20
```

Run continuously until stopped with `Ctrl+C`:

```bash
sudo python3 basic_network_sniffer.py --iface wlan0
```

## Output files

- `logs/packets.csv` — timestamp, interface, protocol, source/destination, ports, flags, DNS query when decoded, sizes, and an empty payload-preview field by default.
- CSV logging appends new capture records. Use `tail -n 10 logs/packets.csv` to view the latest records; `head` displays the oldest records.

To include the limited preview in the CSV, add `--log-payload`. Only do this if authorized and appropriate, since packet payloads may include sensitive information:

```bash
sudo python3 basic_network_sniffer.py --iface wlan0 --count 20 --log-payload
```

To disable CSV logging, add `--no-csv`.

## How to read the output

- **Source / Destination:** The addresses at the network layer that Scapy decodes.
- **Ports:** TCP/UDP source and destination ports, when present.
- **TCP flags:** For example, `S` is SYN, `A` is ACK, and `P` is PSH. Multiple flags can appear together.
- **Packet size:** `len(packet)` for the captured Scapy packet.
- **Raw-layer bytes:** Bytes in Scapy's undecoded `Raw` layer. A value of zero does **not** necessarily mean the packet has no payload; Scapy may have decoded the data into protocol-specific layers.
- **Payload preview:** Only a bounded view of the `Raw` layer. Binary or encrypted traffic may look unreadable; HTTPS/TLS application content is normally encrypted.
- **Service hint:** A port-based hint only, not proof that a specific application/service is running.

## Testing

Check syntax:

```bash
python3 -m py_compile basic_network_sniffer.py
```

Run the packet-summary unit tests (Scapy must be installed):

```bash
python3 -m unittest discover -s tests -v
```

## Limitations

- Packet capture depends on interface permissions, the chosen interface, and the installed capture backend.
- The default `all` capture filter focuses on IPv4, IPv6, and ARP traffic; it is not intended to capture every possible link-layer frame.
- A protocol filter or BPF filter will exclude packets that do not match it.
- Some protocol content may already be decoded by Scapy instead of appearing in the `Raw` layer.
- HTTPS/TLS and other encrypted content cannot normally be read as plain text without authorized decryption material.
- Port-based service labels are indicative only.

## Responsible use and privacy

Capture only traffic on systems and networks you own or have explicit permission to monitor. Packet metadata can reveal browsing, device, and network activity. Payload previews are restricted in size, and the CSV is metadata-only by default. Avoid uploading live packet logs to a public repository.

## Project objective

This project demonstrates the basics of packet capture and protocol inspection with Scapy, helping learners observe how packets flow between network endpoints and how common protocols appear in captured traffic.
