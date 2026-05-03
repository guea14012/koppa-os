"""KOPPA stdlib: net — network operations"""
import subprocess, socket, json, urllib.request, urllib.parse, urllib.error
import ssl, threading, time, re, os

_ctx = ssl.create_default_context(); _ctx.check_hostname = False; _ctx.verify_mode = ssl.CERT_NONE

class _Resp:
    def __init__(self, status=0, body="", headers={}):
        self.status = status; self.body = body; self.headers = headers
    def __repr__(self): return f"<Response {self.status}>"

# ── HTTP ──────────────────────────────────────────────────────────────────────
def _req(method, url, data=None, headers={}):
    if not url.startswith("http"): url = "http://" + url
    hdrs = {"User-Agent": "Mozilla/5.0 (KOPPA-OS)", **headers}
    body = json.dumps(data).encode() if isinstance(data, dict) else \
           (data.encode() if isinstance(data, str) else data)
    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10, context=_ctx) as r:
            return _Resp(r.status, r.read().decode(errors="replace"), dict(r.headers))
    except urllib.error.HTTPError as e:
        return _Resp(e.code, e.read().decode(errors="replace"))
    except Exception:
        return _Resp(0, "")

def http_get(url, headers={}):           return _req("GET",  url, None, headers or {})
def http_post(url, data=None, headers={}): return _req("POST", url, data, headers or {})
def http_request(method, url, data=None, headers={}): return _req(method, url, data, headers or {})

def url_encode(s): return urllib.parse.quote(str(s), safe="")

# ── Port scanning ─────────────────────────────────────────────────────────────
class _Port:
    def __init__(self, id, proto="tcp", service="", banner=""):
        self.id = id; self.proto = proto; self.service = service; self.banner = banner
    def __repr__(self): return f"{self.id}/{self.proto}"

def scan_range(host, start, end):
    out = subprocess.getoutput(f"nmap -sV --open -p {start}-{end} {host} 2>/dev/null")
    results = []
    for line in out.splitlines():
        m = re.match(r"(\d+)/(tcp|udp)\s+open\s+(\S*)\s*(.*)", line)
        if m:
            results.append(_Port(int(m.group(1)), m.group(2), m.group(3), m.group(4).strip()))
    return results

def scan_ports(host, ports):
    port_str = ",".join(str(p) for p in ports)
    return scan_range(host, port_str, port_str)

def service_detect(host):
    return scan_range(host, 1, 65535)

# ── DNS ───────────────────────────────────────────────────────────────────────
def dns_resolve(host):
    try:    return socket.gethostbyname(host)
    except: return ""

def dns_query(domain, rtype="A"):
    out = subprocess.getoutput(f"dig +short {domain} {rtype} 2>/dev/null")
    return [l for l in out.splitlines() if l.strip()]

# ── HTTP fuzzing ──────────────────────────────────────────────────────────────
class _FuzzHit:
    def __init__(self, url, status, size): self.url=url; self.status=status; self.size=size

def http_fuzz(base_url, words, threads=10, status_codes=[200,301,302,403]):
    hits = []; lock = threading.Lock()
    def worker(word):
        url = base_url.rstrip("/") + "/" + word.strip("/")
        r = http_get(url)
        if r.status in status_codes:
            with lock: hits.append(_FuzzHit(url, r.status, len(r.body)))
    pool = []; q = list(words)
    while q:
        while len(pool) < threads and q:
            t = threading.Thread(target=worker, args=(q.pop(0),)); t.start(); pool.append(t)
        pool = [t for t in pool if t.is_alive()]
    for t in pool: t.join()
    return hits

def http_param_fuzz(url, param, words, status_codes=[200]):
    hits = []
    for word in words:
        r = http_get(f"{url}?{param}={url_encode(word)}")
        if r.status in status_codes:
            hits.append(type("H", (), {"value": word, "status": r.status, "url": url})())
    return hits

# ── Brute force ───────────────────────────────────────────────────────────────
def brute_force(proto, host, port, users, passwords, threads=10):
    found = []; lock = threading.Lock()
    proto_map = {
        "ssh":   f"hydra -L {{u}} -P {{p}} ssh://{host}:{port} -t {threads} 2>/dev/null",
        "ftp":   f"hydra -L {{u}} -P {{p}} ftp://{host}:{port} -t {threads} 2>/dev/null",
        "smb":   f"hydra -L {{u}} -P {{p}} smb://{host} -t {threads} 2>/dev/null",
        "rdp":   f"hydra -L {{u}} -P {{p}} rdp://{host}:{port} -t 4 2>/dev/null",
        "mysql": f"hydra -L {{u}} -P {{p}} mysql://{host}:{port} -t {threads} 2>/dev/null",
    }
    import tempfile
    uf = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    pf = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    uf.write("\n".join(users)); uf.close()
    pf.write("\n".join(passwords)); pf.close()
    cmd = proto_map.get(proto, "").format(u=uf.name, p=pf.name)
    if cmd:
        out = subprocess.getoutput(cmd)
        for line in out.splitlines():
            m = re.search(r"login:\s*(\S+)\s+password:\s*(\S+)", line)
            if m: found.append(type("C", (), {"user": m.group(1), "pass": m.group(2)})())
    os.unlink(uf.name); os.unlink(pf.name)
    return found

# ── Misc ──────────────────────────────────────────────────────────────────────
def whois(target):
    return subprocess.getoutput(f"whois {target} 2>/dev/null")

def ping_sweep(cidr):
    out = subprocess.getoutput(f"nmap -sn {cidr} 2>/dev/null")
    hosts = []
    for line in out.splitlines():
        m = re.search(r"Nmap scan report for (.+)", line)
        if m:
            ip = re.search(r"(\d+\.\d+\.\d+\.\d+)", m.group(1))
            hosts.append(type("H", (), {"ip": ip.group(1) if ip else m.group(1),
                                        "mac": "", "vendor": ""})())
    return hosts

def os_detect(host):
    out = subprocess.getoutput(f"nmap -O {host} 2>/dev/null")
    m = re.search(r"OS details: (.+)", out)
    os_str = m.group(1) if m else "Unknown"
    return type("R", (), {"os": os_str, "confidence": 90})()

def email_search(domain):
    out = subprocess.getoutput(f"theHarvester -d {domain} -l 100 -b all 2>/dev/null")
    return re.findall(r"[\w.+-]+@[\w.-]+\.\w+", out)

def vuln_lookup(service, version):
    return []

def vhost_fuzz(ip, words, base_domain):
    hits = []
    for word in words:
        vhost = f"{word}.{base_domain}"
        r = http_get(f"http://{ip}/", {"Host": vhost})
        if r.status == 200:
            hits.append(type("H", (), {"vhost": vhost, "size": len(r.body)})())
    return hits

def http_brute(url, user_field, pass_field, users, passwords, fail_str):
    found = []
    for user in users:
        for pw in passwords:
            r = http_post(url, {user_field: user, pass_field: pw})
            if fail_str not in r.body:
                found.append(type("C", (), {"user": user, "pass": pw})())
    return found
