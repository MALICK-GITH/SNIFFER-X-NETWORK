#!/usr/bin/env python3
"""SNIFFER-X-NETWORK: safe offline PCAP/network diagnostics CLI."""

import argparse
import csv
import json
import socket
import struct
import sys
from collections import Counter
from pathlib import Path

ETHERNET = 1
IPV4 = 0x0800
IPV6 = 0x86DD
TCP = 6
UDP = 17
ICMP = 1


def ipv4(addr):
    return socket.inet_ntoa(addr)


def parse_ipv4_packet(data):
    if len(data) < 20:
        return None
    version_ihl = data[0]
    if version_ihl >> 4 != 4:
        return None
    ihl = (version_ihl & 0x0F) * 4
    if len(data) < ihl:
        return None
    proto = data[9]
    src = ipv4(data[12:16])
    dst = ipv4(data[16:20])
    sport = dport = None
    if proto in (TCP, UDP) and len(data) >= ihl + 4:
        sport, dport = struct.unpack("!HH", data[ihl:ihl + 4])
    names = {TCP: "TCP", UDP: "UDP", ICMP: "ICMP"}
    return {
        "src": src, "dst": dst, "protocol": names.get(proto, str(proto)),
        "src_port": sport, "dst_port": dport, "length": len(data),
    }


def read_pcap(path):
    raw = Path(path).read_bytes()
    if len(raw) < 24:
        raise ValueError("PCAP file is too small")
    magic = raw[:4]
    if magic not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
        raise ValueError("Unsupported PCAP format or byte order")
    endian = "<" if magic == b"\xd4\xc3\xb2\xa1" else ">"
    network = struct.unpack_from(endian + "I", raw, 20)[0]
    if network != ETHERNET:
        raise ValueError("Only Ethernet PCAP link type is supported in V1")
    pos = 24
    packets = []
    while pos + 16 <= len(raw):
        _sec, _usec, incl, _orig = struct.unpack_from(endian + "IIII", raw, pos)
        pos += 16
        frame = raw[pos:pos + incl]
        pos += incl
        if len(frame) < 14:
            continue
        ethertype = struct.unpack("!H", frame[12:14])[0]
        if ethertype == IPV4:
            packet = parse_ipv4_packet(frame[14:])
            if packet:
                packets.append(packet)
        elif ethertype == IPV6:
            packets.append({"src": None, "dst": None, "protocol": "IPv6", "src_port": None, "dst_port": None, "length": len(frame)})
    return packets


def print_stats(packets):
    protocols = Counter(p["protocol"] for p in packets)
    total = sum(p["length"] for p in packets)
    print("SNIFFER-X-NETWORK")
    print("=" * 48)
    print(f"Packets : {len(packets)}")
    print(f"Bytes   : {total}")
    print("Protocols:")
    for proto, count in protocols.most_common():
        print(f"  {proto:<8} {count}")


def export_json(packets, path):
    Path(path).write_text(json.dumps(packets, indent=2), encoding="utf-8")


def export_csv(packets, path):
    fields = ["src", "dst", "protocol", "src_port", "dst_port", "length"]
    with Path(path).open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(packets)


def main():
    parser = argparse.ArgumentParser(prog="sxn", description="SNIFFER-X-NETWORK packet analysis")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("pcap", help="Analyze a PCAP file")
    p.add_argument("file")
    p.add_argument("--json", dest="json_out")
    p.add_argument("--csv", dest="csv_out")
    args = parser.parse_args()
    if args.command == "pcap":
        try:
            packets = read_pcap(args.file)
        except (OSError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print_stats(packets)
        if args.json_out:
            export_json(packets, args.json_out)
        if args.csv_out:
            export_csv(packets, args.csv_out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
