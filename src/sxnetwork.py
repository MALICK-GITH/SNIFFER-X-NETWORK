#!/usr/bin/env python3
"""SNIFFER-X-NETWORK: interactive network and URL diagnostics for Termux.
Use only on systems, domains and traffic you own or are authorized to test.
"""
import argparse,csv,ipaddress,json,re,socket,ssl,struct,sys,urllib.parse,urllib.request
from collections import Counter
from pathlib import Path

PCAP_MAGICS={b"\xd4\xc3\xb2\xa1":"<",b"\xa1\xb2\xc3\xd4":">",b"\x4d\x3c\xb2\xa1":"<",b"\xa1\xb2\x3c\x4d":">"}
ETHERNET=1; IPV4=0x0800; IPV6=0x86DD; TCP=6; UDP=17; ICMP=1
PROTOCOLS={TCP:"TCP",UDP:"UDP",ICMP:"ICMP"}


def parse_ipv4(d):
    if len(d)<20 or d[0]>>4!=4:return None
    ihl=(d[0]&15)*4
    if ihl<20 or len(d)<ihl:return None
    proto=d[9]; p={"src":socket.inet_ntoa(d[12:16]),"dst":socket.inet_ntoa(d[16:20]),"protocol":PROTOCOLS.get(proto,f"IP/{proto}"),"src_port":None,"dst_port":None,"length":len(d)}
    if proto in (TCP,UDP) and len(d)>=ihl+4:p["src_port"],p["dst_port"]=struct.unpack("!HH",d[ihl:ihl+4])
    return p


def parse_ipv6(d):
    if len(d)<40 or d[0]>>4!=6:return None
    return {"src":str(ipaddress.IPv6Address(d[8:24])),"dst":str(ipaddress.IPv6Address(d[24:40])),"protocol":"IPv6","src_port":None,"dst_port":None,"length":len(d)}


def read_pcap(path):
    raw=Path(path).read_bytes()
    if len(raw)<24 or raw[:4] not in PCAP_MAGICS:raise ValueError("Unsupported or invalid PCAP")
    endian=PCAP_MAGICS[raw[:4]]
    if struct.unpack_from(endian+"I",raw,20)[0]!=ETHERNET:raise ValueError("Only Ethernet PCAP is supported")
    pos=24; out=[]
    while pos+16<=len(raw):
        _,_,incl,_=struct.unpack_from(endian+"IIII",raw,pos);pos+=16
        if incl>len(raw)-pos:break
        f=raw[pos:pos+incl];pos+=incl
        if len(f)<14:continue
        et=struct.unpack("!H",f[12:14])[0];d=f[14:]
        p=parse_ipv4(d) if et==IPV4 else parse_ipv6(d) if et==IPV6 else None
        if p:out.append(p)
    return out


def filter_packets(ps,protocol=None,host=None,port=None):
    protocol=protocol.upper() if protocol else None
    return [p for p in ps if (not protocol or p["protocol"].upper()==protocol) and (not host or host in (p["src"],p["dst"])) and (not port or port in (p["src_port"],p["dst_port"]))]


def stats(ps):return {"packets":len(ps),"bytes":sum(p["length"] for p in ps),"protocols":dict(Counter(p["protocol"] for p in ps)),"top_hosts":Counter(x for p in ps for x in (p["src"],p["dst"])).most_common(10)}

def print_stats(ps):
    s=stats(ps);print("\nPackets:",s["packets"],"  Bytes:",s["bytes"]);print("Protocols:")
    for k,v in sorted(s["protocols"].items(),key=lambda x:-x[1]):print(f"  {k:<10}{v}")
    print("Top hosts:")
    for h,n in s["top_hosts"]:print(f"  {h:<40}{n}")

def print_packets(ps,limit=30):
    for i,p in enumerate(ps[:limit],1):
        ports=f":{p['src_port']} -> :{p['dst_port']}" if p["src_port"] is not None else ""
        print(f"{i:>4} {p['protocol']:<7} {p['src']}{ports} -> {p['dst']} {p['length']} B")

def normalize_url(t):return t if "://" in t else "https://"+t

def resolve_target(target):
    host=urllib.parse.urlparse(normalize_url(target)).hostname or target
    print(f"\n🎯 TARGET: {host}")
    try:
        infos=socket.getaddrinfo(host,None);ips=sorted({x[4][0] for x in infos})
        print("\nDNS / IP:");[print("  "+x) for x in ips]
    except socket.gaierror as e:print("DNS error:",e)
    return host

def http_headers(target):
    url=normalize_url(target);print("\n🌐 HTTP HEADERS:",url)
    req=urllib.request.Request(url,headers={"User-Agent":"SNIFFER-X-NETWORK/0.2"},method="HEAD")
    try:
        with urllib.request.urlopen(req,timeout=8) as r:
            print("Status:",r.status,r.reason)
            for k,v in r.headers.items():print(f"  {k}: {v}")
    except Exception as e:print("HTTP error:",e)

def tls_info(target):
    u=urllib.parse.urlparse(normalize_url(target));host=u.hostname
    if not host:return
    port=u.port or 443
    print(f"\n🔐 TLS: {host}:{port}")
    try:
        ctx=ssl.create_default_context()
        with socket.create_connection((host,port),timeout=8) as s:
            with ctx.wrap_socket(s,server_hostname=host) as t:
                print("Version:",t.version());print("Cipher:",t.cipher()[0] if t.cipher() else "unknown")
    except Exception as e:print("TLS error:",e)

def extract_links(target):
    url=normalize_url(target);print("\n🔗 LINK EXTRACTOR:",url)
    req=urllib.request.Request(url,headers={"User-Agent":"SNIFFER-X-NETWORK/0.2"})
    try:
        with urllib.request.urlopen(req,timeout=10) as r:
            html=r.read(2*1024*1024).decode("utf-8","ignore");base=r.geturl()
        links=[];seen=set()
        for raw in re.findall(r'''(?:href|src)\s*=\s*[\"']([^\"']+)[\"']''',html,re.I):
            x=urllib.parse.urljoin(base,raw)
            if x.startswith(("http://","https://")) and x not in seen:seen.add(x);links.append(x)
        print(f"Found: {len(links)} links")
        for i,x in enumerate(links[:200],1):print(f"{i:>3}. {x}")
    except Exception as e:print("Fetch error:",e)

def interactive():
    while True:
        print("\n"+"="*64);print("          SNIFFER-X-NETWORK v0.2");print("       NETWORK • URL • LINK INTELLIGENCE");print("="*64)
        print("[1] 🔎 Fouiller une cible (DNS/IP)")
        print("[2] 🌐 Lire les HTTP headers")
        print("[3] 🔐 Inspecter TLS/HTTPS")
        print("[4] 🔗 Fouiller les liens d'une page")
        print("[5] 📦 Analyser un PCAP")
        print("[6] 📡 Mode Live / capture")
        print("[0] 🚪 Quitter")
        try:c=input("\nChoix > ").strip()
        except (EOFError,KeyboardInterrupt):print();return 0
        if c=="0":return 0
        if c in ("1","2","3","4"):
            t=input("Domaine ou URL > ").strip()
            if not t:continue
            if c=="1":resolve_target(t)
            elif c=="2":http_headers(t)
            elif c=="3":tls_info(t)
            else:extract_links(t)
        elif c=="5":
            f=input("Fichier PCAP > ").strip()
            if f:
                try:
                    ps=read_pcap(f);print_stats(ps);print("\nPackets:");print_packets(ps)
                except Exception as e:print("PCAP error:",e)
        elif c=="6":
            print("\n📡 Live capture backend: dépendant de l'appareil.")
            print("Termux/Android peut nécessiter root ou un mécanisme de capture autorisé.")
        else:print("Choix invalide")
        input("\nEntrée pour revenir au menu...")

def build_parser():
    p=argparse.ArgumentParser(prog="sxn",description="SNIFFER-X-NETWORK diagnostics");sub=p.add_subparsers(dest="command",required=True)
    q=sub.add_parser("pcap");q.add_argument("file");q.add_argument("--protocol",choices=["TCP","UDP","ICMP","IPv6"]);q.add_argument("--host");q.add_argument("--port",type=int);q.add_argument("--limit",type=int,default=30);q.add_argument("--json",dest="json_out");q.add_argument("--csv",dest="csv_out")
    sub.add_parser("live");return p

def main(argv=None):
    if argv is None:argv=sys.argv[1:]
    if not argv:return interactive()
    a=build_parser().parse_args(argv)
    if a.command=="live":print("Live capture backend: device-dependent");return 0
    try:ps=filter_packets(read_pcap(a.file),a.protocol,a.host,a.port)
    except (OSError,ValueError) as e:print("error:",e,file=sys.stderr);return 2
    print_stats(ps);print("\nPackets:");print_packets(ps,max(0,a.limit))
    if a.json_out:Path(a.json_out).write_text(json.dumps(ps,indent=2),encoding="utf-8")
    if a.csv_out:
        with Path(a.csv_out).open("w",newline="",encoding="utf-8") as f:
            w=csv.DictWriter(f,fieldnames=["src","dst","protocol","src_port","dst_port","length"]);w.writeheader();w.writerows(ps)
    return 0

if __name__=="__main__":raise SystemExit(main())
