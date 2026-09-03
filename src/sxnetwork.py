#!/usr/bin/env python3
"""SNIFFER-X-NETWORK v0.3 - interactive network diagnostics for Termux.
Use only on systems, domains and traffic you own or are authorized to test.
Standard-library only; no exploitation, credential capture, or security bypass.
"""
import argparse,csv,html,json,re,socket,ssl,struct,subprocess,sys,urllib.parse,urllib.request
from collections import Counter
from datetime import datetime
from pathlib import Path

VERSION="0.3.0"
UA=f"SNIFFER-X-NETWORK/{VERSION}"
PCAP_MAGICS={b"\xd4\xc3\xb2\xa1":"<",b"\xa1\xb2\xc3\xd4":">",b"\x4d\x3c\xb2\xa1":"<",b"\xa1\xb2\x3c\x4d":">"}
ETHERNET=1; IPV4=0x0800; IPV6=0x86DD; TCP=6; UDP=17; ICMP=1
PROTOCOLS={TCP:"TCP",UDP:"UDP",ICMP:"ICMP"}
COMMON_PORTS=(21,22,25,53,80,110,143,443,465,587,993,995,8080,8443)


def normalize_url(t): return t if "://" in t else "https://"+t

def target_host(t): return urllib.parse.urlparse(normalize_url(t)).hostname or t

def resolve_target(target):
    host=target_host(target); out={"target":host,"addresses":[]}
    print(f"\n🎯 TARGET: {host}")
    try:
        infos=socket.getaddrinfo(host,None)
        ips=sorted({x[4][0] for x in infos}); out["addresses"]=ips
        print("\nDNS / IP:"); [print("  "+x) for x in ips]
        try:
            name,aliases,addrs=socket.gethostbyaddr(ips[0]); out["reverse"]=name
            print("Reverse DNS:",name)
        except Exception: pass
    except socket.gaierror as e: print("DNS error:",e); out["error"]=str(e)
    return out

def reverse_dns(target):
    host=target_host(target); print(f"\n🔄 REVERSE DNS: {host}")
    try:
        ip=socket.gethostbyname(host) if not re.match(r"^[0-9a-fA-F:.]+$",host) else host
        name,aliases,addrs=socket.gethostbyaddr(ip)
        print("IP:",ip); print("Hostname:",name)
        if aliases: print("Aliases:",", ".join(aliases))
        return {"ip":ip,"hostname":name,"aliases":aliases}
    except Exception as e: print("Reverse DNS error:",e); return {"error":str(e)}

def http_fetch(target, method="GET", max_bytes=2*1024*1024):
    url=normalize_url(target)
    req=urllib.request.Request(url,headers={"User-Agent":UA},method=method)
    try:
        with urllib.request.urlopen(req,timeout=10) as r:
            body=r.read(max_bytes) if method=="GET" else b""
            return {"url":url,"final_url":r.geturl(),"status":r.status,"reason":r.reason,"headers":dict(r.headers.items()),"body":body}
    except urllib.error.HTTPError as e:
        body=e.read(max_bytes) if method=="GET" else b""
        return {"url":url,"final_url":e.geturl(),"status":e.code,"reason":str(e.reason),"headers":dict(e.headers.items()),"body":body}
    except Exception as e: return {"url":url,"error":str(e),"body":b""}

def http_headers(target):
    print("\n🌐 HTTP / HTTPS HEADERS")
    r=http_fetch(target,"HEAD")
    if "error" in r: print("HTTP error:",r["error"]); return r
    print("URL:",r["final_url"]); print("Status:",r["status"],r["reason"])
    for k,v in r["headers"].items(): print(f"  {k}: {v}")
    return r

def tls_info(target):
    u=urllib.parse.urlparse(normalize_url(target)); host=u.hostname; port=u.port or 443
    print(f"\n🔐 TLS: {host}:{port}"); out={"host":host,"port":port}
    try:
        ctx=ssl.create_default_context()
        with socket.create_connection((host,port),timeout=8) as s:
            with ctx.wrap_socket(s,server_hostname=host) as t:
                cert=t.getpeercert(); out.update({"version":t.version(),"cipher":t.cipher()[0] if t.cipher() else None,"certificate":cert})
                print("Version:",t.version()); print("Cipher:",out["cipher"])
                subj=dict(x[0] for x in cert.get("subject",[])); issuer=dict(x[0] for x in cert.get("issuer",[]))
                print("Subject CN:",subj.get("commonName","?")); print("Issuer CN:",issuer.get("commonName","?")); print("Valid from:",cert.get("notBefore","?")); print("Valid until:",cert.get("notAfter","?"))
                sans=[x[1] for x in cert.get("subjectAltName",[]) if x[0]=="DNS"]
                if sans: print("SAN:",", ".join(sans[:20]))
    except Exception as e: print("TLS error:",e); out["error"]=str(e)
    return out

def extract_links(target):
    print("\n🔗 LINK EXTRACTOR")
    r=http_fetch(target,"GET")
    if "error" in r: print("Fetch error:",r["error"]); return {"links":[]}
    text=r["body"].decode("utf-8","ignore"); base=r["final_url"]
    links=[]; seen=set()
    for raw in re.findall(r'''(?:href|src|action)\s*=\s*["']([^"']+)["']''',text,re.I):
        x=urllib.parse.urljoin(base,html.unescape(raw)).split("#",1)[0]
        if x.startswith(("http://","https://")) and x not in seen: seen.add(x); links.append(x)
    print("Page:",base); print("Found:",len(links)); [print(f"{i:>3}. {x}") for i,x in enumerate(links[:300],1)]
    return {"page":base,"links":links}

def tech_detect(target):
    print("\n🧩 TECHNOLOGY HINTS")
    r=http_fetch(target,"GET",1024*1024)
    if "error" in r: print("Fetch error:",r["error"]); return {}
    h={k.lower():v for k,v in r["headers"].items()}; body=r["body"].decode("utf-8","ignore").lower(); found=[]
    tests={"Cloudflare":["cf-ray","cloudflare"],"WordPress":["wp-content","wp-includes"],"Next.js":["__next_data__","/_next/"],"React":["react"],"Vue":["vue.js","vue.min.js"],"Nginx":["nginx"],"Apache":["apache"]}
    blob=" ".join(h.values())+" "+body[:300000]
    for name,needles in tests.items():
        if any(x in blob for x in needles): found.append(name)
    print("Hints:",", ".join(found) if found else "Aucune signature évidente")
    return {"technologies":found,"headers":r["headers"]}

def safe_port_check(target):
    host=target_host(target); print(f"\n🔌 CONNECTIVITY CHECK (ports courants): {host}")
    print("⚠️ À utiliser uniquement sur une cible autorisée.")
    results=[]
    for port in COMMON_PORTS:
        s=socket.socket(); s.settimeout(0.8)
        try: s.connect((host,port)); state="open"; print(f"  {port:<5} OPEN")
        except (ConnectionRefusedError,TimeoutError,OSError): state="closed/unreachable"
        finally: s.close()
        results.append({"port":port,"state":state})
    return results

def traceroute(target):
    host=target_host(target); print(f"\n🛣️ TRACE: {host}")
    cmd=["traceroute","-m","8",host] if subprocess.call(["sh","-c","command -v traceroute >/dev/null"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)==0 else ["ping","-c","1",host]
    try:
        p=subprocess.run(cmd,capture_output=True,text=True,timeout=25); print(p.stdout or p.stderr); return {"command":cmd,"output":p.stdout or p.stderr}
    except Exception as e: print("Trace error:",e); return {"error":str(e)}

def parse_ipv4(d):
    if len(d)<20 or d[0]>>4!=4:return None
    ihl=(d[0]&15)*4
    if ihl<20 or len(d)<ihl:return None
    proto=d[9]; p={"src":socket.inet_ntoa(d[12:16]),"dst":socket.inet_ntoa(d[16:20]),"protocol":PROTOCOLS.get(proto,f"IP/{proto}"),"src_port":None,"dst_port":None,"length":len(d)}
    if proto in (TCP,UDP) and len(d)>=ihl+4:p["src_port"],p["dst_port"]=struct.unpack("!HH",d[ihl:ihl+4])
    return p

def parse_ipv6(d):
    if len(d)<40 or d[0]>>4!=6:return None
    nxt=d[6]; p={"src":str(__import__('ipaddress').IPv6Address(d[8:24])),"dst":str(__import__('ipaddress').IPv6Address(d[24:40])),"protocol":PROTOCOLS.get(nxt,f"IPv6/{nxt}"),"src_port":None,"dst_port":None,"length":len(d)}
    if nxt in (TCP,UDP) and len(d)>=44:p["src_port"],p["dst_port"]=struct.unpack("!HH",d[40:44])
    return p

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

def stats(ps): return {"packets":len(ps),"bytes":sum(p["length"] for p in ps),"protocols":dict(Counter(p["protocol"] for p in ps)),"top_hosts":Counter(x for p in ps for x in (p["src"],p["dst"])).most_common(10),"top_ports":Counter(x for p in ps for x in (p["src_port"],p["dst_port"]) if x).most_common(15)}

def print_stats(ps):
    s=stats(ps); print(f"\nPackets: {s['packets']}  Bytes: {s['bytes']}"); print("Protocols:"); [print(f"  {k:<12}{v}") for k,v in sorted(s["protocols"].items(),key=lambda x:-x[1])]; print("Top hosts:"); [print(f"  {h:<40}{n}") for h,n in s["top_hosts"]]; print("Top ports:"); [print(f"  {p:<8}{n}") for p,n in s["top_ports"]]

def print_packets(ps,limit=30):
    for i,p in enumerate(ps[:limit],1):
        ports=f":{p['src_port']} -> :{p['dst_port']}" if p["src_port"] is not None else ""
        print(f"{i:>4} {p['protocol']:<8} {p['src']}{ports} -> {p['dst']} {p['length']} B")

def export_report(data,path): Path(path).write_text(json.dumps(data,indent=2,default=str,ensure_ascii=False),encoding="utf-8"); print("💾 Rapport:",path)

def full_scan(target):
    print("\n🚀 ANALYSE COMPLÈTE — diagnostic non intrusif")
    data={"tool":"SNIFFER-X-NETWORK","version":VERSION,"timestamp":datetime.utcnow().isoformat()+"Z"}
    data["dns"]=resolve_target(target); data["http"]=http_headers(target); data["tls"]=tls_info(target); data["links"]=extract_links(target); data["technology"]=tech_detect(target)
    return data

def interactive():
    last={}
    while True:
        print("\n"+"═"*64); print(f"        SNIFFER-X-NETWORK v{VERSION}"); print("      NETWORK • WEB • PCAP INTELLIGENCE"); print("═"*64)
        print("[1] 🎯 Analyse complète d'une cible")
        print("[2] 🌐 DNS / IP")
        print("[3] 🔄 Reverse DNS")
        print("[4] 📡 HTTP / HTTPS Headers")
        print("[5] 🔐 TLS / Certificat")
        print("[6] 🔗 Extraire les liens")
        print("[7] 🧩 Indices de technologies")
        print("[8] 🔌 Connectivité ports courants")
        print("[9] 🛣️ Traceroute / ping")
        print("[10] 📦 Analyser un PCAP")
        print("[11] 💾 Exporter le dernier rapport")
        print("[12] ℹ️ Aide / limites")
        print("[0] 🚪 Quitter")
        try:c=input("\nChoix > ").strip()
        except (EOFError,KeyboardInterrupt):print();return 0
        if c=="0": return 0
        try:
            if c in {"1","2","3","4","5","6","7","8","9"}:
                t=input("Domaine, IP ou URL > ").strip()
                if not t: continue
                funcs={"1":lambda:full_scan(t),"2":lambda:resolve_target(t),"3":lambda:reverse_dns(t),"4":lambda:http_headers(t),"5":lambda:tls_info(t),"6":lambda:extract_links(t),"7":lambda:tech_detect(t),"8":lambda:safe_port_check(t),"9":lambda:traceroute(t)}
                last={"target":t,"result":funcs[c]()}
            elif c=="10":
                f=input("Fichier PCAP > ").strip()
                ps=read_pcap(f); print_stats(ps); print("\nPackets:"); print_packets(ps); last={"pcap":f,"stats":stats(ps),"packets":ps}
            elif c=="11":
                if not last: print("Aucun rapport en mémoire.")
                else: export_report(last,input("Nom du fichier [report.json] > ").strip() or "report.json")
            elif c=="12":
                print("\nSNIFFER-X-NETWORK est un outil de diagnostic et d'analyse autorisée.")
                print("Modules: DNS, reverse DNS, HTTP, TLS, liens, détection de signatures, PCAP, connectivité et trace.")
                print("Le module ports utilise uniquement une petite liste de ports courants et des connexions TCP simples.")
                print("Pas d'exploitation, pas de vol de données, pas de contournement d'authentification.")
                print("Android: la capture live réelle dépend des permissions/root ou d'un mécanisme VPN/capture autorisé.")
            else: print("Choix invalide")
        except Exception as e: print("\n❌ Erreur:",e)
        input("\nEntrée pour revenir au menu...")

def build_parser():
    p=argparse.ArgumentParser(prog="sxn",description="SNIFFER-X-NETWORK diagnostics"); sub=p.add_subparsers(dest="command",required=True)
    q=sub.add_parser("pcap"); q.add_argument("file"); q.add_argument("--protocol",choices=["TCP","UDP","ICMP","IPv6"]); q.add_argument("--host"); q.add_argument("--port",type=int); q.add_argument("--limit",type=int,default=30); q.add_argument("--json",dest="json_out"); q.add_argument("--csv",dest="csv_out")
    for n in ("dns","reverse","headers","tls","links","tech","ports","trace","full"): x=sub.add_parser(n); x.add_argument("target")
    sub.add_parser("live"); return p

def main(argv=None):
    if argv is None: argv=sys.argv[1:]
    if not argv:return interactive()
    a=build_parser().parse_args(argv)
    if a.command=="live": print("Live capture: device-dependent; use an authorized capture mechanism."); return 0
    if a.command=="pcap":
        try: ps=filter_packets(read_pcap(a.file),a.protocol,a.host,a.port)
        except (OSError,ValueError) as e: print("error:",e,file=sys.stderr); return 2
        print_stats(ps); print("\nPackets:"); print_packets(ps,max(0,a.limit))
        if a.json_out: export_report(ps,a.json_out)
        if a.csv_out:
            with Path(a.csv_out).open("w",newline="",encoding="utf-8") as f: w=csv.DictWriter(f,fieldnames=["src","dst","protocol","src_port","dst_port","length"]); w.writeheader(); w.writerows(ps)
        return 0
    funcs={"dns":resolve_target,"reverse":reverse_dns,"headers":http_headers,"tls":tls_info,"links":extract_links,"tech":tech_detect,"ports":safe_port_check,"trace":traceroute,"full":full_scan}; result=funcs[a.command](a.target)
    if a.command=="full": print(json.dumps(result,indent=2,default=str,ensure_ascii=False))
    return 0

if __name__=="__main__": raise SystemExit(main())
