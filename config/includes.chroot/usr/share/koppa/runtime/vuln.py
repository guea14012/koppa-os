"""KOPPA stdlib: vuln — vulnerability scanning and CVE intelligence."""
import subprocess, re, json, urllib.request, urllib.error, ssl

_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode    = ssl.CERT_NONE


def _get(url, headers=None, timeout=15):
    hdrs = {"User-Agent": "KOPPA-OS/3.1"}
    if headers: hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ctx) as r:
            return r.read().decode(errors="replace"), r.status
    except Exception:
        return "", 0


def _sh(cmd, timeout=120):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, timeout=timeout)
        return r.stdout.decode(errors="replace")
    except Exception:
        return ""


# ── CVE Intelligence ──────────────────────────────────────────────────────────
def cve_info(cve_id):
    """Fetch CVE details from MITRE/NVD."""
    # Try NVD first
    body, code = _get(
        f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    )
    if code == 200:
        try:
            data  = json.loads(body)
            vuln  = data["vulnerabilities"][0]["cve"]
            desc  = vuln["descriptions"][0]["value"]
            score = ""
            metrics = vuln.get("metrics", {})
            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if key in metrics:
                    score = metrics[key][0].get("cvssData", {}).get("baseScore", "")
                    break
            return {
                "id":          cve_id,
                "description": desc,
                "cvss":        score,
                "url":         f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            }
        except Exception:
            pass
    # Fallback to MITRE
    body, code = _get(f"https://cveawg.mitre.org/api/cve/{cve_id}")
    if code == 200:
        try:
            data = json.loads(body)
            return {
                "id":          cve_id,
                "description": str(data.get("cveMetadata", {})),
                "cvss":        "N/A",
                "url":         f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}",
            }
        except Exception:
            pass
    return {"id": cve_id, "error": "not found"}


def cve_search(keyword, max_results=10):
    """Search NVD for CVEs matching a keyword."""
    import urllib.parse
    url   = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={urllib.parse.quote(keyword)}&resultsPerPage={max_results}"
    body, code = _get(url)
    if code != 200:
        return []
    try:
        data  = json.loads(body)
        results = []
        for item in data.get("vulnerabilities", []):
            cve   = item["cve"]
            desc  = cve["descriptions"][0]["value"][:200] if cve.get("descriptions") else ""
            results.append({
                "id":          cve["id"],
                "description": desc,
                "published":   cve.get("published", ""),
            })
        return results
    except Exception:
        return []


def exploit_db(cve_id):
    """Search Exploit-DB for a CVE."""
    return _sh(f"searchsploit {cve_id} 2>/dev/null || echo 'searchsploit not found'")


# ── Web Vulnerability Scanning ────────────────────────────────────────────────
def nikto(target, port=80):
    """Run Nikto web scanner."""
    return _sh(f"nikto -h {target} -p {port} -C all 2>/dev/null", timeout=300)


def nuclei(target, templates=None, severity=None):
    """Run Nuclei scanner with optional template/severity filters."""
    tmpl_flag = f"-t {templates}" if templates else ""
    sev_flag  = f"-severity {severity}" if severity else ""
    return _sh(
        f"nuclei -u {target} {tmpl_flag} {sev_flag} -silent 2>/dev/null",
        timeout=300
    )


def wapiti(target):
    """Run Wapiti web vulnerability scanner."""
    return _sh(f"wapiti -u {target} --scope url 2>/dev/null", timeout=300)


def whatweb(target):
    """Fingerprint web tech stack."""
    return _sh(f"whatweb -a 3 {target} 2>/dev/null")


def wpscan(target, api_token=""):
    """Run WPScan against a WordPress site."""
    token_flag = f"--api-token {api_token}" if api_token else ""
    return _sh(
        f"wpscan --url {target} {token_flag} --enumerate u,p,t --random-user-agent 2>/dev/null",
        timeout=300
    )


def droopescan(target, cms="drupal"):
    """Run droopescan for Drupal/Joomla/SilverStripe."""
    return _sh(f"droopescan scan {cms} -u {target} 2>/dev/null", timeout=300)


# ── Network Vuln Scanning ─────────────────────────────────────────────────────
def nmap_vuln(host, ports=None):
    """Run nmap with vulnerability scripts."""
    port_arg = f"-p {ports}" if ports else ""
    return _sh(
        f"nmap -sV --script vuln {port_arg} {host} 2>/dev/null",
        timeout=300
    )


def openvas_scan(target, user="admin", password="admin",
                 host="127.0.0.1", port=9390):
    """Trigger OpenVAS scan via GVM CLI (if installed)."""
    return _sh(
        f"gvm-cli --gmp-username {user} --gmp-password {password} "
        f"socket --xml '<create_task><name>KOPPA-{target}</name>"
        f"<config id=\"daba56c8-73ec-11df-a475-002264764cea\"/>"
        f"<target><hosts>{target}</hosts><ports>T:1-65535,U:1-65535</ports></target>"
        f"</create_task>' 2>/dev/null",
        timeout=30
    )


def msf_scan(target, module="auxiliary/scanner/portscan/tcp"):
    """Run a Metasploit auxiliary scanner module."""
    msfrc = f"/tmp/koppa_msf_{target.replace('.','_')}.rc"
    with open(msfrc, "w") as f:
        f.write(f"use {module}\nset RHOSTS {target}\nrun\nexit\n")
    out = _sh(f"msfconsole -q -r {msfrc} 2>/dev/null", timeout=120)
    import os; os.unlink(msfrc)
    return out


# ── Service-specific ──────────────────────────────────────────────────────────
def check_default_creds(host, port, service):
    """Check for default credentials on common services."""
    creds_map = {
        "redis":     [("", "")],
        "mongodb":   [("", ""), ("admin", "admin")],
        "elastic":   [("elastic", "changeme"), ("admin", "admin")],
        "grafana":   [("admin", "admin"), ("admin", "grafana")],
        "jenkins":   [("admin", "admin"), ("admin", "password")],
        "kibana":    [("elastic", "changeme")],
        "tomcat":    [("admin", "admin"), ("tomcat", "tomcat"), ("admin", "s3cret")],
    }
    results = []
    for user, pw in creds_map.get(service.lower(), []):
        results.append({"user": user, "password": pw, "service": service})
    return results


def ssl_scan(host, port=443):
    """Comprehensive SSL/TLS vulnerability test."""
    return _sh(
        f"testssl --quiet --color 0 {host}:{port} 2>/dev/null || "
        f"nmap -p {port} --script 'ssl-*' {host} 2>/dev/null",
        timeout=120
    )
