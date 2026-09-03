#!/usr/bin/env python3
"""Core, safe network intelligence helpers for SNIFFER-X-NETWORK."""
import ipaddress, json, re, socket, ssl, urllib.parse, urllib.request
from collections import Counter

UA = "SNIFFER-X-NETWORK/0.4"

def target_host(target):
    u = urllib.parse.urlparse(target if "://" in target else "https://" + target)
    return u.hostname or target

def dns_lookup(target):
    host = target_host(target)
    result = {"target": host, "addresses": [], "aliases": []}
    try:
        for family, _, _, canon, sockaddr in socket.getaddrinfo(host, None):
            result["addresses"].append(sockaddr[0])
            if canon and canon != host: result["aliases"].append(canon)
    except socket.gaierror as e:
        result["error"] = str(e)
    result["addresses"] = sorted(set(result["addresses"]))
    result["aliases"] = sorted(set(result["aliases"]))
    return result

def reverse_dns(value):
    try: return {"input": value, "hostname": socket.gethostbyaddr(value)[0]}
    except Exception as e: return {"input": value, "hostname": None, "error": str(e)}

def http_probe(target, timeout=8):
    url = target if "://" in target else "https://" + target
    req = urllib.request.Request(url, headers={"User-Agent": UA}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(2 * 1024 * 1024)
            return {"url": url, "final_url": r.geturl(), "status": r.status, "headers": dict(r.headers.items()), "body": body.decode("utf-8", "ignore")}
    except Exception as e: return {"url": url, "error": str(e)}

def extract_links(html, base):
    seen, links = set(), []
    for raw in re.findall(r'''(?:href|src)\s*=\s*["']([^"']+)["']''', html, re.I):
        x = urllib.parse.urljoin(base, raw)
        if x.startswith(("http://", "https://")) and x not in seen:
            seen.add(x); links.append(x)
    return links

def tls_probe(target, timeout=8):
    u = urllib.parse.urlparse(target if "://" in target else "https://" + target)
    host, port = u.hostname, u.port or 443
    out = {"host": host, "port": port}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                out["version"] = s.version(); out["cipher"] = s.cipher()[0] if s.cipher() else None
                cert = s.getpeercert(); out["subject"] = cert.get("subject"); out["issuer"] = cert.get("issuer"); out["expires"] = cert.get("notAfter")
    except Exception as e: out["error"] = str(e)
    return out

def common_ports(host, ports=(21,22,25,53,80,110,143,443,465,587,993,995,8080,8443), timeout=.7):
    """Small, opt-in connect check for an authorized target."""
    results = []
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=timeout): state = "open"
        except (ConnectionRefusedError, TimeoutError, OSError): state = "closed/filtered"
        results.append({"port": port, "state": state})
    return results

def pretty(obj): return json.dumps(obj, indent=2, ensure_ascii=False, default=str)
