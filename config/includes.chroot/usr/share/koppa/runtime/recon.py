"""KOPPA stdlib: recon — passive & active reconnaissance."""
import socket, subprocess, re, urllib.request, urllib.parse, json, ssl, threading

_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode    = ssl.CERT_NONE


def dns_resolve(domain):
    try:    return socket.gethostbyname(domain)
    except: return ""

def dns_resolve_all(domain):
    try:    return list(set(r[4][0] for r in socket.getaddrinfo(domain, None)))
    except: return []

def dns_reverse(ip):
    try:    return socket.gethostbyaddr(ip)[0]
    except: return ""

def dns_query(domain, rtype="A"):
    out = subprocess.getoutput(f"dig +short {domain} {rtype} 2>/dev/null")
    return [l.strip() for l in out.splitlines() if l.strip()]

def mx(domain):      return dns_query(domain, "MX")
def txt(domain):     return dns_query(domain, "TXT")
def ns(domain):      return dns_query(domain, "NS")
def cname(domain):   return dns_query(domain, "CNAME")
def aaaa(domain):    return dns_query(domain, "AAAA")

def zone_transfer(domain):
    """Attempt DNS zone transfer."""
    ns_servers = ns(domain)
    for server in ns_servers:
        out = subprocess.getoutput(f"dig @{server.rstrip('.')} {domain} AXFR 2>/dev/null")
        if "Transfer failed" not in out and len(out.splitlines()) > 5:
            return out
    return ""

def subdomain_enum(domain, wordlist=None, threads=50):
    """Enumerate subdomains via DNS brute-force."""
    if wordlist is None:
        wordlist = [
            "www", "mail", "ftp", "admin", "api", "dev", "test", "staging",
            "portal", "vpn", "ssh", "cdn", "static", "media", "app", "web",
            "mx", "smtp", "pop", "imap", "ns1", "ns2", "dns", "git", "gitlab",
            "jenkins", "jira", "confluence", "wiki", "intranet", "internal",
            "beta", "alpha", "demo", "old", "new", "backup", "db", "mysql",
            "redis", "elastic", "kibana", "grafana", "monitor", "prometheus",
        ]
    found = []
    lock  = threading.Lock()

    def check(sub):
        fqdn = f"{sub}.{domain}"
        ip   = dns_resolve(fqdn)
        if ip:
            with lock:
                found.append({"subdomain": fqdn, "ip": ip})

    pool = []
    for sub in wordlist:
        while len([t for t in pool if t.is_alive()]) >= threads:
            import time; time.sleep(0.01)
        t = threading.Thread(target=check, args=(sub,), daemon=True)
        t.start(); pool.append(t)
    for t in pool: t.join(timeout=10)
    return found

def whois(target):
    return subprocess.getoutput(f"whois {target} 2>/dev/null")

def asn(ip):
    return subprocess.getoutput(f"whois -h whois.radb.net {ip} 2>/dev/null")

def cert_transparency(domain):
    """Enumerate subdomains via crt.sh certificate transparency."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": "KOPPA-OS/3.1"})
    try:
        with urllib.request.urlopen(req, timeout=15, context=_ctx) as r:
            data = json.loads(r.read())
            names = set()
            for entry in data:
                for name in re.split(r"[\n,]", entry.get("name_value", "")):
                    name = name.strip().lstrip("*.")
                    if name.endswith(domain):
                        names.add(name)
            return sorted(names)
    except Exception:
        return []

def email_harvest(domain):
    """Harvest email addresses using theHarvester."""
    out = subprocess.getoutput(
        f"theHarvester -d {domain} -l 100 -b all 2>/dev/null"
    )
    return list(set(re.findall(r"[\w.+-]+@[\w.-]+\.\w+", out)))

def shodan(query, api_key=""):
    """Query Shodan API."""
    if not api_key:
        return []
    url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query={urllib.parse.quote(query)}"
    req = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(req, timeout=15, context=_ctx) as r:
            return json.loads(r.read()).get("matches", [])
    except Exception:
        return []

def censys(query, api_id="", api_secret=""):
    """Query Censys hosts API."""
    if not api_id:
        return []
    import base64
    creds = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
    url   = "https://search.censys.io/api/v2/hosts/search"
    data  = json.dumps({"q": query, "per_page": 50}).encode()
    req   = urllib.request.Request(url, data=data, headers={
        "Authorization": f"Basic {creds}",
        "Content-Type": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=15, context=_ctx) as r:
            return json.loads(r.read()).get("result", {}).get("hits", [])
    except Exception:
        return []

def github_dorks(org, token=""):
    """Search GitHub for secrets in org repos."""
    dorks = ["password", "api_key", "secret_key", "token", "private_key", "aws_access"]
    results = []
    for dork in dorks:
        url  = f"https://api.github.com/search/code?q={dork}+org:{org}"
        hdrs = {"User-Agent": "KOPPA-OS", "Accept": "application/vnd.github.v3+json"}
        if token:
            hdrs["Authorization"] = f"token {token}"
        req = urllib.request.Request(url, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=10, context=_ctx) as r:
                data  = json.loads(r.read())
                items = data.get("items", [])
                for item in items[:5]:
                    results.append({
                        "file":  item.get("html_url"),
                        "repo":  item.get("repository", {}).get("full_name"),
                        "dork":  dork,
                    })
        except Exception:
            pass
    return results

def wayback(domain):
    """Fetch historical URLs from Wayback Machine."""
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&limit=100"
    req = urllib.request.Request(url, headers={"User-Agent": "KOPPA-OS/3.1"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            data  = json.loads(r.read())
            return [row[2] for row in data[1:] if len(row) > 2]
    except Exception:
        return []
