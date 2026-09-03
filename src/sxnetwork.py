#!/usr/bin/env python3
"""SNIFFER-X-NETWORK: interactive Termux-friendly network diagnostics.

The tool can still be used with command-line arguments, but launching it
without arguments opens an interactive terminal menu so users do not need to
remember commands.

Live capture remains a capability check because Android capture permissions
and mechanisms differ between devices.
"""

import argparse
import csv
import ipaddress
import json
import socket
import struct
import sys
from collections import Counter
from pathlib import Path

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
    b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">",
}
ETHERNET = 1
IPV4, IPV6 = 0x0800, 0x86DD
TCP, UDP, ICMP = 6, 17, 1
PROTOCOLS = {TCP: "TCP", UDP: "UDP", ICMP: "ICMP"}


def ip4(raw):
    return socket.inet_ntoa(raw)


def parse_ipv4(data):
    if len(data) < 20 or data[0] >> 4 != 4:
        return None
    ihl = (data[0] & 0x0F) * 4
    if ihl < 20 or len(data) < ihl:
        return None
    proto = data[9]
    result = {"src": ip4(data[12:16]), "dst": ip4(data[16:20]),
              "protocol": PROTOCOLS.get(proto, f"IP/{proto}"),
              "src_port": None, "dst_port": None, "length": len(data)}
    if proto in (TCP, UDP) and len(data) >= ihl + 4:
        result["src_port"], result["dst_port"] = struct.unpack("!HH", data[ihl:ihl + 4])
    return result


def parse_ipv6(data):
    if len(data) < 40 or data[0] >> 4 != 6:
        return None
    src = str(ipaddress.IPv6Address(data[8:24]))
    dst = str(ipaddress.IPv6Address(data[24:40]))
    return {"src": src, "dst": dst, "protocol": "IPv6",
            "src_port": None, "dst_port": None, "length": len(data)}


def read_pcap(path):
    raw = Path(path).read_bytes()
    if len(raw) < 24:
        raise ValueError("PCAP file is too small")
    magic = raw[:4]
    if magic not in PCAP_MAGICS:
        raise ValueError("Unsupported PCAP/byte order")
    endian = PCAP_MAGICS[magic]
    network = struct.unpack_from(endian + "I", raw, 20)[0]
    if network != ETHERNET:
        raise ValueError(f"Unsupported link type {network}; Ethernet PCAP required")
    pos, packets = 24, []
    while pos + 16 <= len(raw):
        _sec, _usec, incl, _orig = struct.unpack_from(endian + "IIII", raw, pos)
        pos += 16
        if incl > len(raw) - pos:
            break
        frame = raw[pos:pos + incl]
        pos += incl
        if len(frame) < 14:
            continue
        ethertype = struct.unpack("!H", frame[12:14])[0]
        payload = frame[14:]
        packet = parse_ipv4(payload) if ethertype == IPV4 else parse_ipv6(payload) if ethertype == IPV6 else None
        if packet:
            packets.append(packet)
    return packets


def filter_packets(packets, protocol=None, host=None, port=None):
    protocol = protocol.upper() if protocol else None
    return [p for p in packets if
            (not protocol or p["protocol"].upper() == protocol) and
            (not host or p["src"] == host or p["dst"] == host) and
            (not port or p["src_port"] == port or p["dst_port"] == port)]


def stats(packets):
    return {"packets": len(packets), "bytes": sum(p["length"] for p in packets),
            "protocols": dict(Counter(p["protocol"] for p in packets)),
            "top_hosts": Counter(x for p in packets for x in (p["src"], p["dst"])).most_common(10)}


def print_packets(packets, limit=30):
    for i, p in enumerate(packets[:limit], 1):
        ports = ""
        if p["src_port"] is not None:
            ports = f":{p['src_port']} -> :{p['dst_port']}"
        print(f"{i:>4}  {p['protocol']:<7} {p['src']}{ports} -> {p['dst']}  {p['length']} B")
    if len(packets) > limit:
        print(f"... {len(packets) - limit} more packets")


def print_stats(packets):
    s = stats(packets)
    print("\nSNIFFER-X-NETWORK")
    print("=" * 56)
    print(f"Packets : {s['packets']}")
    print(f"Bytes   : {s['bytes']}")
    print("Protocols:")
    for proto, count in sorted(s["protocols"].items(), key=lambda x: (-x[1], x[0])):
        print(f"  {proto:<10} {count}")
    if s["top_hosts"]:
        print("Top hosts:")
        for host, count in s["top_hosts"]:
            print(f"  {host:<39} {count}")


def export_json(packets, path):
    Path(path).write_text(json.dumps(packets, indent=2), encoding="utf-8")


def export_csv(packets, path):
    fields = ["src", "dst", "protocol", "src_port", "dst_port", "length"]
    with Path(path).open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(packets)


def resolve_target(target):
    """Resolve a hostname without performing traffic interception."""
    try:
        infos = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
        addresses = sorted({item[4][0] for item in infos})
    except socket.gaierror as exc:
        print(f"\nImpossible de résoudre {target}: {exc}")
        return
    print(f"\nCible : {target}")
    print("DNS / adresses résolues")
    print("-" * 40)
    for address in addresses:
        print(f"  {address}")
    print("\nCette fonction affiche uniquement la résolution DNS.")


def interactive_pcap():
    print("\n📦 ANALYSE PCAP")
    path = input("Chemin du fichier PCAP : ").strip()
    if not path:
        print("Annulé.")
        return
    try:
        packets = read_pcap(path)
    except (OSError, ValueError) as exc:
        print(f"Erreur : {exc}")
        return

    protocol = input("Protocole (TCP/UDP/ICMP/IPv6 ou Entrée=tous) : ").strip().upper() or None
    host = input("IP à filtrer (ou Entrée=toutes) : ").strip() or None
    port_text = input("Port à filtrer (ou Entrée=tous) : ").strip()
    port = int(port_text) if port_text.isdigit() else None
    limit_text = input("Nombre de paquets à afficher [30] : ").strip()
    limit = int(limit_text) if limit_text.isdigit() else 30

    packets = filter_packets(packets, protocol, host, port)
    print_stats(packets)
    print("\nPaquets:")
    print_packets(packets, max(0, limit))

    export = input("Exporter en JSON/CSV ? (json/csv/non) : ").strip().lower()
    if export in ("json", "csv"):
        output = input(f"Nom du fichier [{Path(path).stem}.{export}] : ").strip()
        output = output or f"{Path(path).stem}.{export}"
        try:
            export_json(packets, output) if export == "json" else export_csv(packets, output)
            print(f"✓ Export terminé : {output}")
        except OSError as exc:
            print(f"Erreur export : {exc}")


def interactive_target():
    print("\n🎯 CIBLE / DNS")
    target = input("Domaine ou IP [mtn.ci] : ").strip() or "mtn.ci"
    resolve_target(target)


def interactive_live():
    print("\n📡 MODE LIVE")
    print("Backend de capture : dépendant de l'appareil")
    print("Termux/Android peut nécessiter root ou un mécanisme de capture autorisé.")
    print("SNIFFER-X-NETWORK ne contourne aucune protection ni permission.")
    input("Appuie sur Entrée pour revenir au menu...")


def interactive_menu():
    while True:
        print("\n" + "=" * 56)
        print("        SNIFFER-X-NETWORK  v0.1")
        print("      NETWORK DIAGNOSTICS • TERMUX")
        print("=" * 56)
        print("[1] 📦 Analyser un fichier PCAP")
        print("[2] 🎯 Résoudre une cible (DNS/IP)")
        print("[3] 📡 Vérifier le mode Live")
        print("[4] ℹ️  Aide")
        print("[0] 🚪 Quitter")
        choice = input("\nChoix > ").strip()
        if choice == "1":
            interactive_pcap()
        elif choice == "2":
            interactive_target()
        elif choice == "3":
            interactive_live()
        elif choice == "4":
            print("\nConseil : utilise le menu pour éviter de mémoriser les commandes.")
            print("Les analyses concernent uniquement des captures et réseaux que tu es autorisé à diagnostiquer.")
            input("\nAppuie sur Entrée...")
        elif choice == "0":
            print("\nSNIFFER-X-NETWORK fermé. 👋")
            return 0
        else:
            print("Choix invalide.")
    return 0


def build_parser():
    parser = argparse.ArgumentParser(prog="sxn", description="SNIFFER-X-NETWORK diagnostics")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("pcap", help="Analyze an authorized PCAP file")
    p.add_argument("file")
    p.add_argument("--protocol", choices=["TCP", "UDP", "ICMP", "IPv6"])
    p.add_argument("--host")
    p.add_argument("--port", type=int)
    p.add_argument("--limit", type=int, default=30)
    p.add_argument("--json", dest="json_out")
    p.add_argument("--csv", dest="csv_out")
    s = sub.add_parser("live", help="Check live-capture requirements")
    s.add_argument("--interface", default="auto")
    return parser


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        return interactive_menu()
    args = build_parser().parse_args(argv)
    if args.command == "live":
        print("Live capture backend: device-dependent")
        print("Termux/Android may require root or an authorized capture mechanism.")
        print("No security controls are bypassed by SNIFFER-X-NETWORK.")
        return 0
    try:
        packets = read_pcap(args.file)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    packets = filter_packets(packets, args.protocol, args.host, args.port)
    print_stats(packets)
    print("\nPackets:")
    print_packets(packets, max(0, args.limit))
    if args.json_out:
        export_json(packets, args.json_out)
    if args.csv_out:
        export_csv(packets, args.csv_out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
