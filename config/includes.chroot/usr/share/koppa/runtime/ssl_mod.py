"""KOPPA stdlib: ssl — TLS/SSL certificate inspection and attacks."""
import ssl, socket, subprocess, datetime, re, hashlib, json


def _get_cert(host, port=443, timeout=10):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    try:
        conn = ctx.wrap_socket(
            socket.create_connection((host, int(port)), timeout=timeout),
            server_hostname=host
        )
        cert = conn.getpeercert(binary_form=True)
        conn.close()
        return cert, conn.getpeercert()
    except Exception:
        return None, None


def _der_cert(host, port=443):
    bin_cert, _ = _get_cert(host, port)
    return bin_cert

def expiry(host, port=443):
    """Return certificate expiry date string."""
    _, cert = _get_cert(host, int(port))
    if not cert:
        return "unknown"
    nb = cert.get("notAfter", "")
    return nb

def issuer(host, port=443):
    """Return certificate issuer string."""
    _, cert = _get_cert(host, int(port))
    if not cert:
        return "unknown"
    parts = dict(x[0] for x in cert.get("issuer", []))
    return parts.get("organizationName", str(cert.get("issuer", "")))

def subject(host, port=443):
    _, cert = _get_cert(host, int(port))
    if not cert:
        return ""
    parts = dict(x[0] for x in cert.get("subject", []))
    return parts.get("commonName", "")

def fingerprint(host, port=443, algo="sha256"):
    bin_cert, _ = _get_cert(host, int(port))
    if not bin_cert:
        return ""
    fn = getattr(hashlib, algo, hashlib.sha256)
    return fn(bin_cert).hexdigest()

def san(host, port=443):
    """Return Subject Alternative Names."""
    _, cert = _get_cert(host, int(port))
    if not cert:
        return []
    return [v for _type, v in cert.get("subjectAltName", [])]

def verify(host, port=443):
    """Return True if cert is valid and not expired."""
    try:
        ctx = ssl.create_default_context()
        s   = socket.create_connection((host, int(port)), timeout=10)
        ctx.wrap_socket(s, server_hostname=host).close()
        return True
    except Exception:
        return False

def protocols(host, port=443):
    """Test which TLS protocol versions the server supports."""
    supported = []
    for proto_name, proto_const in [
        ("TLSv1",   ssl.PROTOCOL_TLS_CLIENT),
        ("TLSv1.1", ssl.PROTOCOL_TLS_CLIENT),
        ("TLSv1.2", ssl.PROTOCOL_TLS_CLIENT),
        ("TLSv1.3", ssl.PROTOCOL_TLS_CLIENT),
    ]:
        try:
            ctx = ssl.SSLContext(proto_const)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            s = socket.create_connection((host, int(port)), timeout=5)
            ctx.wrap_socket(s).close()
            supported.append(proto_name)
        except Exception:
            pass
    return supported

def ciphers(host, port=443):
    """Return list of accepted cipher suites."""
    out = subprocess.getoutput(
        f"nmap --script ssl-enum-ciphers -p {port} {host} 2>/dev/null"
    )
    return re.findall(r"TLS_\w+", out)

def heartbleed(host, port=443):
    """Test for Heartbleed (CVE-2014-0160)."""
    out = subprocess.getoutput(
        f"nmap -p {port} --script ssl-heartbleed {host} 2>/dev/null"
    )
    return "VULNERABLE" in out.upper()

def poodle(host, port=443):
    out = subprocess.getoutput(
        f"nmap -p {port} --script ssl-poodle {host} 2>/dev/null"
    )
    return "VULNERABLE" in out.upper()

def full_scan(host, port=443):
    """Run full SSL/TLS audit with testssl.sh if available."""
    return subprocess.getoutput(
        f"testssl --quiet --color 0 {host}:{port} 2>/dev/null || "
        f"nmap -p {port} --script 'ssl-*' {host} 2>/dev/null"
    )

def cert_info(host, port=443):
    """Return dict with all cert metadata."""
    return {
        "subject":     subject(host, port),
        "issuer":      issuer(host, port),
        "expiry":      expiry(host, port),
        "fingerprint": fingerprint(host, port),
        "san":         san(host, port),
        "valid":       verify(host, port),
    }
