#!/usr/bin/env python3
"""Basic Network Sniffer for an internship learning project.

Captures authorized network traffic with Scapy, prints useful packet fields,
provides a bounded payload preview, writes packet metadata to CSV, and prints
summary statistics when capture ends.

Capture only on devices/networks you own or are authorized to monitor.
"""

import argparse
import csv
import sys
import time
from collections import Counter
from datetime import datetime
from pathlib import Path

try:
    from scapy.all import ARP, DNS, DNSQR, ICMP, IP, IPv6, Raw, TCP, UDP, sniff
    from scapy.error import Scapy_Exception
except ImportError as exc:  # Give a friendly message if dependencies are missing.
    print(
        "Scapy is not installed. Install it with 'python3 -m pip install -r requirements.txt' "
        "or your operating system package manager.",
        file=sys.stderr,
    )
    raise SystemExit(1) from exc


CSV_FIELDS = [
    "timestamp",
    "interface",
    "protocol",
    "network",
    "source",
    "destination",
    "source_port",
    "destination_port",
    "tcp_flags",
    "dns_query",
    "application_hint",
    "packet_size_bytes",
    "raw_layer_bytes",
    "payload_preview",
]

PROTOCOL_FILTERS = {
    "all": "ip or ip6 or arp",
    "tcp": "tcp",
    "udp": "udp",
    "icmp": "icmp or icmp6",
    "arp": "arp",
    "dns": "port 53",
}

COMMON_PORT_HINTS = {
    22: "SSH (common port 22)",
    53: "DNS (common port 53)",
    80: "HTTP (common port 80)",
    123: "NTP (common port 123)",
    443: "HTTPS/TLS or QUIC (common port 443)",
    5353: "mDNS (common port 5353)",
    1900: "SSDP (common port 1900)",
}


def get_timestamp():
    """Return local time with its UTC offset included."""
    return datetime.now().astimezone().isoformat(timespec="seconds")


def get_addresses(packet):
    """Return source address, destination address, and network-layer label."""
    if packet.haslayer(IP):
        return packet[IP].src, packet[IP].dst, "IPv4"
    if packet.haslayer(IPv6):
        return packet[IPv6].src, packet[IPv6].dst, "IPv6"
    if packet.haslayer(ARP):
        source = packet[ARP].psrc or packet[ARP].hwsrc or "Unknown"
        destination = packet[ARP].pdst or packet[ARP].hwdst or "Unknown"
        return source, destination, "ARP"
    return "Unknown", "Unknown", "Other"


def get_dns_query(packet):
    """Return a decoded DNS query name when available, otherwise an empty string."""
    if not packet.haslayer(DNS) or not packet.haslayer(DNSQR):
        return ""
    try:
        name = packet[DNSQR].qname
        if isinstance(name, bytes):
            name = name.decode("utf-8", errors="replace")
        return str(name).rstrip(".")
    except (AttributeError, IndexError, TypeError):
        return ""


def get_payload_preview(packet, payload_limit, payload_format):
    """Return a safe, size-limited preview of Scapy's undecoded Raw layer.

    This intentionally does not try to decode encrypted or binary data as text.
    The byte count describes the Raw layer only; Scapy may decode other packet
    content into protocol-specific layers instead.
    """
    if not packet.haslayer(Raw):
        return "", 0

    raw_payload = bytes(packet[Raw].load)
    if payload_format == "none" or payload_limit == 0:
        return "", len(raw_payload)

    sample = raw_payload[:payload_limit]
    parts = []

    if payload_format in ("text", "both"):
        # Non-printable bytes become dots to avoid terminal control characters.
        readable = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in sample)
        parts.append(f"text='{readable}'")

    if payload_format in ("hex", "both"):
        parts.append("hex=" + sample.hex(" "))

    preview = " | ".join(parts)
    if len(raw_payload) > len(sample):
        preview += f" ... (showing {len(sample)} of {len(raw_payload)} bytes)"
    return preview, len(raw_payload)


def describe_packet(packet, payload_limit=48, payload_format="text"):
    """Extract useful fields from one Scapy packet into a dictionary."""
    source, destination, network = get_addresses(packet)
    source_port = ""
    destination_port = ""
    tcp_flags = ""
    details = []
    application_hint = ""

    if packet.haslayer(TCP):
        protocol = "TCP"
        source_port = int(packet[TCP].sport)
        destination_port = int(packet[TCP].dport)
        tcp_flags = str(packet[TCP].flags)
        details.append(f"Ports: {source_port} -> {destination_port}")
        details.append(f"TCP flags: {tcp_flags or 'None'}")
    elif packet.haslayer(UDP):
        protocol = "UDP"
        source_port = int(packet[UDP].sport)
        destination_port = int(packet[UDP].dport)
        details.append(f"Ports: {source_port} -> {destination_port}")
    elif packet.haslayer(ICMP):
        protocol = "ICMP"
        details.append(f"Type: {packet[ICMP].type}, code: {packet[ICMP].code}")
    elif packet.haslayer(IPv6) and any(
        getattr(layer, "__name__", "").startswith("ICMPv6")
        for layer in packet.layers()
    ):
        protocol = "ICMPv6"
    elif packet.haslayer(ARP):
        protocol = "ARP"
        details.append(f"Operation: {packet[ARP].op}")
    else:
        protocol = network

    dns_query = get_dns_query(packet)
    if dns_query:
        details.append(f"DNS query: {dns_query}")

    if source_port != "" or destination_port != "":
        for port in (source_port, destination_port):
            if port in COMMON_PORT_HINTS:
                application_hint = COMMON_PORT_HINTS[port]
                break
        if application_hint:
            details.append(f"Service hint: {application_hint}")

    payload_preview, raw_layer_bytes = get_payload_preview(
        packet, payload_limit=payload_limit, payload_format=payload_format
    )

    return {
        "timestamp": get_timestamp(),
        "protocol": protocol,
        "network": network,
        "source": source,
        "destination": destination,
        "source_port": source_port,
        "destination_port": destination_port,
        "tcp_flags": tcp_flags,
        "dns_query": dns_query,
        "application_hint": application_hint,
        "packet_size_bytes": len(packet),
        "raw_layer_bytes": raw_layer_bytes,
        "payload_preview": payload_preview,
        "details": details,
    }


def print_packet(summary, packet_number, payload_format):
    """Print an easy-to-read packet summary."""
    print(
        f"[{summary['timestamp']}] Packet #{packet_number}  "
        f"{summary['protocol']} / {summary['network']}"
    )
    print(f"  Source:      {summary['source']}")
    print(f"  Destination: {summary['destination']}")

    for detail in summary["details"]:
        print(f"  {detail}")

    if summary["raw_layer_bytes"] == 0:
        print("  Payload:     No undecoded Raw layer found")
    elif payload_format == "none" or not summary["payload_preview"]:
        print(f"  Payload:     Preview disabled ({summary['raw_layer_bytes']} raw-layer bytes)")
    else:
        print(f"  Payload:     {summary['payload_preview']}")

    print(
        f"  Packet size: {summary['packet_size_bytes']} bytes"
        f" | Raw-layer bytes: {summary['raw_layer_bytes']} bytes"
    )
    print("-" * 78, flush=True)


def create_csv_logger(csv_path):
    """Open an append-only metadata CSV file and create a header if needed."""
    path = Path(csv_path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    needs_header = not path.exists() or path.stat().st_size == 0
    handle = path.open("a", newline="", encoding="utf-8")
    writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS, extrasaction="ignore")
    if needs_header:
        writer.writeheader()
        handle.flush()
    return handle, writer, str(path)


def build_capture_filter(protocol, custom_filter):
    """Build a BPF filter for the selected protocol and optional extra filter."""
    base_filter = PROTOCOL_FILTERS[protocol]
    if custom_filter is None:
        return base_filter

    custom_filter = custom_filter.strip()
    if not custom_filter:
        return base_filter
    if protocol == "all":
        return custom_filter
    return f"({base_filter}) and ({custom_filter})"


def print_statistics(
    packet_count,
    started_at,
    protocol_counts,
    network_counts,
    total_packet_bytes,
    total_raw_layer_bytes,
    source_counts,
    destination_counts,
    dns_queries,
):
    """Print packet counts, sizes, observed addresses and decoded DNS names."""
    duration = max(time.monotonic() - started_at, 0.0)
    rate = packet_count / duration if duration > 0 else 0.0

    print("\n" + "=" * 78)
    print("CAPTURE STATISTICS SUMMARY")
    print("=" * 78)
    print(f"Packets captured:       {packet_count}")
    print(f"Capture duration:       {duration:.2f} seconds")
    print(f"Average packet rate:    {rate:.2f} packets/second")
    print(f"Total packet size:      {total_packet_bytes:,} bytes")
    print(f"Raw-layer bytes found:  {total_raw_layer_bytes:,} bytes")

    print("Packets by protocol:")
    for name, count in protocol_counts.most_common():
        print(f"  {name:<12} {count:>6}")
    if not protocol_counts:
        print("  No packets captured.")

    print("Packets by network layer:")
    for name, count in network_counts.most_common():
        print(f"  {name:<12} {count:>6}")
    if not network_counts:
        print("  No packets captured.")

    print("Top source addresses:")
    for address, count in source_counts.most_common(5):
        print(f"  {address:<40} {count:>6} packets")
    if not source_counts:
        print("  None")

    print("Top destination addresses:")
    for address, count in destination_counts.most_common(5):
        print(f"  {address:<40} {count:>6} packets")
    if not destination_counts:
        print("  None")

    if dns_queries:
        print("DNS query names observed (when decoded):")
        for query, count in dns_queries.most_common(10):
            print(f"  {query:<45} {count:>6}")

    print("=" * 78, flush=True)


def parse_args(argv=None):
    """Parse command-line options; separated to make validation testable."""
    parser = argparse.ArgumentParser(
        description=(
            "Capture and inspect network packets with Scapy. "
            "Only monitor networks you own or are authorized to inspect."
        )
    )
    parser.add_argument("--iface", help="Network interface, for example wlan0 or eth0.")
    parser.add_argument(
        "--count",
        type=int,
        default=0,
        help="Stop after this many matching packets; 0 means continue until Ctrl+C (default: 0).",
    )
    parser.add_argument(
        "--protocol",
        choices=tuple(PROTOCOL_FILTERS),
        default="all",
        help="Protocol focus: all, tcp, udp, icmp, arp, or dns (default: all).",
    )
    parser.add_argument(
        "--filter",
        dest="bpf_filter",
        default=None,
        help="Optional additional BPF filter, for example 'host 192.168.1.1' or 'port 443'.",
    )
    parser.add_argument(
        "--payload-bytes",
        type=int,
        default=48,
        help="Maximum Raw-layer bytes to preview per packet (0-1024; default: 48).",
    )
    parser.add_argument(
        "--payload-format",
        choices=("text", "hex", "both", "none"),
        default="text",
        help="Payload preview style (default: text). Use 'none' to disable previews.",
    )
    parser.add_argument(
        "--csv",
        default="logs/packets.csv",
        help="CSV log path (default: logs/packets.csv).",
    )
    parser.add_argument("--no-csv", action="store_true", help="Disable CSV logging.")
    parser.add_argument(
        "--log-payload",
        action="store_true",
        help="Save the limited payload preview to CSV too; off by default for privacy.",
    )
    args = parser.parse_args(argv)

    if args.count < 0:
        parser.error("--count must be 0 or greater")
    if not 0 <= args.payload_bytes <= 1024:
        parser.error("--payload-bytes must be between 0 and 1024")
    if args.no_csv and args.log_payload:
        parser.error("--log-payload requires CSV logging; do not combine it with --no-csv")
    return args


def main(argv=None):
    args = parse_args(argv)
    capture_filter = build_capture_filter(args.protocol, args.bpf_filter)
    csv_handle = None
    csv_writer = None

    print("=" * 78)
    print("BASIC NETWORK SNIFFER | RITESH KUMAWAT ")
    print(f"Interface:      {args.iface or 'Scapy default'}")
    print(f"Protocol focus: {args.protocol.upper()}")
    print(f"BPF filter:     {capture_filter or '(none)'}")
    print(f"Payload view:   {args.payload_format} (up to {args.payload_bytes} bytes)")
    print("CSV payloads:   " + ("enabled (limited preview only)" if args.log_payload else "disabled (metadata only)"))
    print("Press Ctrl+C to stop. Only monitor traffic you are authorized to inspect.")
    print("=" * 78)

    if not args.no_csv:
        try:
            csv_handle, csv_writer, csv_path = create_csv_logger(args.csv)
            print(f"CSV log:        {csv_path}\n")
        except OSError as exc:
            print(f"Could not open CSV log {args.csv!r}: {exc}", file=sys.stderr)
            return 1
    else:
        print("CSV log:        disabled\n")

    packet_count = 0
    started_at = time.monotonic()
    protocol_counts = Counter()
    network_counts = Counter()
    source_counts = Counter()
    destination_counts = Counter()
    dns_queries = Counter()
    total_packet_bytes = 0
    total_raw_layer_bytes = 0

    def on_packet(packet):
        nonlocal packet_count, total_packet_bytes, total_raw_layer_bytes
        packet_count += 1
        summary = describe_packet(
            packet,
            payload_limit=args.payload_bytes,
            payload_format=args.payload_format,
        )
        print_packet(summary, packet_count, args.payload_format)

        protocol_counts[summary["protocol"]] += 1
        network_counts[summary["network"]] += 1
        total_packet_bytes += summary["packet_size_bytes"]
        total_raw_layer_bytes += summary["raw_layer_bytes"]
        if summary["source"] != "Unknown":
            source_counts[summary["source"]] += 1
        if summary["destination"] != "Unknown":
            destination_counts[summary["destination"]] += 1
        if summary["dns_query"]:
            dns_queries[summary["dns_query"]] += 1

        if csv_writer is not None:
            row = {key: summary.get(key, "") for key in CSV_FIELDS}
            row["interface"] = args.iface or "Scapy default"
            if not args.log_payload:
                row["payload_preview"] = ""
            csv_writer.writerow(row)
            csv_handle.flush()

    capture_error = None
    try:
        sniff(
            iface=args.iface,
            filter=capture_filter,
            prn=on_packet,
            store=False,
            count=args.count,
        )
        print(f"\nCapture complete. Packets displayed: {packet_count}")
    except KeyboardInterrupt:
        print(f"\nCapture stopped by user. Packets displayed: {packet_count}")
    except PermissionError as exc:
        capture_error = exc
        print("Permission denied. On Linux, try running with sudo.", file=sys.stderr)
    except (OSError, Scapy_Exception) as exc:
        capture_error = exc
        print(f"Capture error: {exc}", file=sys.stderr)
        print("Check the interface name, permissions, and libpcap/tcpdump installation.", file=sys.stderr)
    finally:
        if csv_handle is not None:
            csv_handle.close()

    print_statistics(
        packet_count=packet_count,
        started_at=started_at,
        protocol_counts=protocol_counts,
        network_counts=network_counts,
        total_packet_bytes=total_packet_bytes,
        total_raw_layer_bytes=total_raw_layer_bytes,
        source_counts=source_counts,
        destination_counts=destination_counts,
        dns_queries=dns_queries,
    )
    return 1 if capture_error else 0


if __name__ == "__main__":
    raise SystemExit(main())
