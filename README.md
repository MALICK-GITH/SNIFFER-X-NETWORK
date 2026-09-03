# SNIFFER-X-NETWORK

> Advanced network diagnostics and packet analysis toolkit for Termux/Android.

SNIFFER-X-NETWORK is designed for analyzing traffic on devices and networks you are authorized to inspect.

## V1

- Live traffic statistics
- TCP / UDP / ICMP visibility when capture data is available
- Source/destination IP and ports
- Packet and byte counters
- Protocol filters
- JSON / CSV export
- Offline PCAP analysis
- DNS visibility from captured traffic
- Terminal-friendly output

## Important

Android/Termux permissions vary by device. Raw live packet capture may require root or another permitted capture mechanism. The tool never attempts to bypass Android security controls.

## Roadmap

- [ ] Core CLI
- [ ] PCAP/PCAPNG parser
- [ ] Live capture backend
- [ ] Filters
- [ ] Statistics engine
- [ ] DNS analyzer
- [ ] Export engine
- [ ] Tests
- [ ] Termux installer

## Ethics

Use only on devices, interfaces, and traffic you own or are explicitly authorized to analyze. SNIFFER-X-NETWORK is for network diagnostics, troubleshooting, learning, and defensive security.

## License

MIT
