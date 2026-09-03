#!/usr/bin/env python3
"""SNIFFER-X-NETWORK v0.4 interactive console."""
import json, sys
from pathlib import Path
from sxcore import common_ports, dns_lookup, extract_links, http_probe, pretty, reverse_dns, target_host, tls_probe

BANNER = r'''\n╔════════════════════════════════════════════════════╗\n║             SNIFFER-X-NETWORK v0.4                ║\n║        NETWORK • URL • PCAP INTELLIGENCE           ║\n╚════════════════════════════════════════════════════╝'''

def pause():
    input("\nEntrée pour revenir au menu...")

def complete(target):
    print("\n[+] Analyse autorisée de", target)
    d = dns_lookup(target); print("\n🌐 DNS / IP\n", pretty(d))
    h = http_probe(target)
    print("\n📡 HTTP")
    if "error" in h: print(h["error"])
    else:
        print("Status:", h["status"], "URL:", h["final_url"])
        links = extract_links(h.get("body", ""), h["final_url"])
        print("Liens publics trouvés:", len(links))
        for x in links[:50]: print("  ", x)
    print("\n🔐 TLS\n", pretty(tls_probe(target)))
    host = target_host(target)
    print("\n🔌 Ports courants (connexion TCP simple)\n", pretty(common_ports(host)))

def menu():
    while True:
        print(BANNER)
        print("\n[1] 🎯 Analyse complète")
        print("[2] 🌐 DNS / IP")
        print("[3] 🔄 Reverse DNS")
        print("[4] 📡 HTTP / HTTPS")
        print("[5] 🔐 TLS / certificat")
        print("[6] 🔗 Extraire les liens")
        print("[7] 🔌 Ports courants")
        print("[8] 📦 Analyse PCAP (ancien module)")
        print("[9] 💾 Sauvegarder un rapport JSON")
        print("[0] 🚪 Quitter")
        try: c=input("\nChoix > ").strip()
        except (EOFError, KeyboardInterrupt): print(); return
        if c == "0": return
        if c in {"1","2","4","5","6","7","9"}:
            t=input("Domaine ou URL > ").strip()
            if not t: continue
            if c == "1": complete(t)
            elif c == "2": print(pretty(dns_lookup(t)))
            elif c == "4": print(pretty({k:v for k,v in http_probe(t).items() if k != "body"}))
            elif c == "5": print(pretty(tls_probe(t)))
            elif c == "6":
                h=http_probe(t)
                if "error" in h: print(h["error"])
                else:
                    links=extract_links(h.get("body",""),h["final_url"])
                    print(f"{len(links)} liens trouvés")
                    for i,x in enumerate(links[:200],1): print(f"{i:>3}. {x}")
            elif c == "7": print(pretty(common_ports(target_host(t))))
            else:
                data={"target":t,"dns":dns_lookup(t),"tls":tls_probe(t),"http":{k:v for k,v in http_probe(t).items() if k != "body"}}
                out=Path("sxn-report.json");out.write_text(json.dumps(data,indent=2,ensure_ascii=False,default=str),encoding="utf-8");print("Rapport:",out)
            pause()
        elif c == "3":
            x=input("Adresse IP > ").strip(); print(pretty(reverse_dns(x))); pause()
        elif c == "8":
            print("Utilise: python src/sxnetwork.py pcap fichier.pcap"); pause()
        else: print("Choix invalide")

def main(): menu()
if __name__ == "__main__": main()
