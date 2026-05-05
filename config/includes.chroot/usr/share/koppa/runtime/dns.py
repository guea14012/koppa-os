"""KOPPA stdlib: dns — DNS query helpers."""
import socket, subprocess, re


def resolve(domain):
    try:    return socket.gethostbyname(domain)
    except: return ""

def resolve_all(domain):
    try:
        infos = socket.getaddrinfo(domain, None)
        return list(set(i[4][0] for i in infos))
    except: return []

def reverse(ip):
    try:    return socket.gethostbyaddr(ip)[0]
    except: return ""

def query(domain, rtype="A"):
    out = subprocess.getoutput(f"dig +short {domain} {rtype} 2>/dev/null")
    return [l.strip() for l in out.splitlines() if l.strip()]

def mx(domain):    return query(domain, "MX")
def txt(domain):   return query(domain, "TXT")
def ns(domain):    return query(domain, "NS")
def cname(domain): return query(domain, "CNAME")

def zone_transfer(domain, nameserver=None):
    server = nameserver or ns(domain)[0].rstrip(".") if ns(domain) else ""
    if not server:
        return ""
    return subprocess.getoutput(f"dig @{server} {domain} AXFR 2>/dev/null")

def ptr_scan(cidr):
    """Reverse-lookup all IPs in a /24."""
    results = {}
    m = re.match(r"(\d+\.\d+\.\d+)\.", cidr)
    prefix = m.group(1) if m else cidr.rsplit(".", 1)[0]
    for i in range(1, 255):
        ip   = f"{prefix}.{i}"
        host = reverse(ip)
        if host:
            results[ip] = host
    return results

def cache_snoop(domain, server="8.8.8.8"):
    """DNS cache snooping — check if server has cached a domain."""
    out = subprocess.getoutput(
        f"dig +norecurse @{server} {domain} A 2>/dev/null"
    )
    return "ANSWER: 0" not in out and "ANSWER SECTION" in out

def dnssec(domain):
    out = subprocess.getoutput(f"dig {domain} DNSKEY +dnssec 2>/dev/null")
    return "RRSIG" in out
