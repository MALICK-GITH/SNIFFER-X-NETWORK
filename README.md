# SNIFFER-X-NETWORK

> Interactive network, web diagnostics and PCAP intelligence toolkit for Termux/Android.

## 🚀 V0.3

Launch the interactive console with:

```bash
python src/sxnetwork.py
```

After installation:

```bash
./install.sh
sxn
```

### Modules

- 🎯 Full authorized target diagnostics
- 🌐 DNS / IP resolution
- 🔄 Reverse DNS
- 📡 HTTP/HTTPS headers and status
- 🔐 TLS version, cipher and certificate metadata
- 🔗 Public-page link extraction
- 🧩 Passive technology/signature hints from public HTTP responses
- 🔌 Small TCP connectivity check for common service ports
- 🛣️ Traceroute when available, otherwise ping fallback
- 📦 Ethernet PCAP analysis with IPv4/IPv6, TCP/UDP/ICMP visibility
- 📊 Packet, byte, protocol, host and port statistics
- 💾 JSON/CSV export and JSON reports
- 🧰 CLI mode for automation
- 📱 Termux installer

## CLI examples

```bash
sxn dns mtn.ci
sxn headers https://mtn.ci
sxn tls mtn.ci
sxn links https://mtn.ci
sxn tech https://mtn.ci
sxn ports mtn.ci
sxn trace mtn.ci
sxn full https://mtn.ci
sxn pcap capture.pcap --port 443 --json report.json
```

## ⚠️ Scope and safety

SNIFFER-X-NETWORK is a diagnostics and defensive-analysis tool. Use it only against systems, domains, devices and traffic you own or have explicit permission to test.

The port module intentionally performs only simple TCP connectivity checks against a short list of common ports. It does not exploit services, brute-force credentials, intercept private communications, bypass authentication, or evade security controls.

Public web requests are limited in size/time and are not an aggressive crawler. Live packet capture on Android is device-dependent and may require root or an authorized VPN/capture mechanism.

## Roadmap

- PCAPNG parsing
- Optional pluggable capture backends
- Better report formatting
- More protocol parsers
- Automated tests for network modules

## License

MIT
