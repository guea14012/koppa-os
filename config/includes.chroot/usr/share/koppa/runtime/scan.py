"""KOPPA stdlib: scan — port scanning, banner grabbing, service detection."""
import socket, subprocess, re, threading, time


_SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP",
    636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    1723: "PPTP", 2181: "ZooKeeper", 2375: "Docker", 2376: "Docker-TLS",
    3000: "Grafana/Node", 3306: "MySQL", 3389: "RDP", 4369: "RabbitMQ",
    5432: "PostgreSQL", 5601: "Kibana", 5900: "VNC", 5985: "WinRM",
    5986: "WinRM-HTTPS", 6379: "Redis", 6443: "K8s API", 7001: "WebLogic",
    8000: "HTTP-alt", 8080: "HTTP-proxy", 8443: "HTTPS-alt", 8888: "Jupyter",
    9000: "SonarQube/PHP-FPM", 9090: "Prometheus", 9200: "Elasticsearch",
    9300: "Elasticsearch", 9418: "Git", 11211: "Memcached",
    27017: "MongoDB", 27018: "MongoDB", 50070: "Hadoop NameNode",
}


class PortResult:
    def __init__(self, port, state, service="", banner="", proto="tcp"):
        self.port    = port
        self.state   = state
        self.open    = (state == "open")
        self.service = service
        self.banner  = banner
        self.proto   = proto

    def __repr__(self):
        return f"{self.port}/{self.proto}  {self.state:6}  {self.service}  {self.banner}"


def tcp(host, port, timeout=2):
    """Check if TCP port is open. Returns bool."""
    try:
        s = socket.create_connection((host, int(port)), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False


def tcp_scan(host, port, timeout=2):
    """Scan a single TCP port. Returns PortResult."""
    svc = service(port)
    if tcp(host, port, timeout):
        ban = banner(host, port, timeout)
        return PortResult(port, "open", svc, ban)
    return PortResult(port, "closed", svc, "")


def service(port):
    """Return service name for a port number."""
    return _SERVICE_MAP.get(int(port), "unknown")


def banner(host, port, timeout=3):
    """Grab service banner from an open port."""
    probes = {
        80:  b"GET / HTTP/1.0\r\n\r\n",
        443: b"GET / HTTP/1.0\r\n\r\n",
        21:  b"",
        22:  b"",
        25:  b"EHLO koppa\r\n",
    }
    try:
        s = socket.create_connection((host, int(port)), timeout=timeout)
        probe = probes.get(int(port), b"")
        if probe:
            s.sendall(probe)
        s.settimeout(timeout)
        data = s.recv(256)
        s.close()
        return data.decode(errors="replace").strip().split("\n")[0][:120]
    except Exception:
        return ""


def scan_ports(host, ports, threads=50, timeout=1.5):
    """Scan a list of ports with threading. Returns list of open PortResults."""
    results = []
    lock    = threading.Lock()

    def worker(port):
        if tcp(host, port, timeout):
            svc = service(port)
            ban = banner(host, port, timeout)
            with lock:
                results.append(PortResult(port, "open", svc, ban))

    pool = []
    for p in ports:
        while len([t for t in pool if t.is_alive()]) >= threads:
            time.sleep(0.01)
        t = threading.Thread(target=worker, args=(p,), daemon=True)
        t.start()
        pool.append(t)
    for t in pool:
        t.join(timeout=timeout + 2)
    return sorted(results, key=lambda r: r.port)


def scan_range(host, start=1, end=1024, threads=100, timeout=1):
    """Scan a port range. Returns list of open PortResults."""
    return scan_ports(host, range(int(start), int(end) + 1), threads, timeout)


def nmap(host, args="-sV --open -T4", ports=None):
    """Run nmap and return parsed results."""
    port_arg = f"-p {ports}" if ports else ""
    cmd = f"nmap {args} {port_arg} {host} 2>/dev/null"
    out = subprocess.getoutput(cmd)
    results = []
    for line in out.splitlines():
        m = re.match(r"(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)", line)
        if m:
            results.append(PortResult(
                int(m.group(1)), "open",
                m.group(3), m.group(4).strip(), m.group(2)
            ))
    return results


def nmap_vuln(host, ports=None):
    """Run nmap with vuln scripts."""
    port_arg = f"-p {ports}" if ports else "-p-"
    return subprocess.getoutput(
        f"nmap -sV --script vuln {port_arg} {host} 2>/dev/null"
    )


def masscan(cidr, ports="0-65535", rate=10000):
    """Run masscan on a CIDR. Returns list of (ip, port) tuples."""
    out = subprocess.getoutput(
        f"masscan {cidr} -p{ports} --rate={rate} 2>/dev/null"
    )
    results = []
    for line in out.splitlines():
        m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+port\s+(\d+)", line)
        if m:
            results.append((m.group(1), int(m.group(2))))
    return results


def ping(host):
    """Ping check. Returns True if host responds."""
    out = subprocess.getoutput(f"ping -c 1 -W 1 {host} 2>/dev/null")
    return "1 received" in out or "bytes from" in out


def host_discovery(cidr):
    """Discover live hosts in a CIDR block."""
    out = subprocess.getoutput(f"nmap -sn {cidr} 2>/dev/null")
    hosts = []
    for line in out.splitlines():
        m = re.search(r"Nmap scan report for (.+)", line)
        if m:
            h = m.group(1).strip()
            ip = re.search(r"(\d+\.\d+\.\d+\.\d+)", h)
            hosts.append(ip.group(1) if ip else h)
    return hosts


def udp(host, port, timeout=3):
    """UDP port check (best-effort). Returns bool."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(b"\x00", (host, int(port)))
        s.recv(128)
        s.close()
        return True
    except socket.timeout:
        return True
    except Exception:
        return False
