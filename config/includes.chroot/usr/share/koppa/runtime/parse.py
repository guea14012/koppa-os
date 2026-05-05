"""KOPPA stdlib: parse — HTML/text parsing utilities."""
import re, json, html as _html


def html_title(html):
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    return _html.unescape(m.group(1).strip()) if m else ""

def html_links(html, base=""):
    links = re.findall(r'href=["\']([^"\']+)["\']', html, re.I)
    result = []
    for l in links:
        if l.startswith("http"):
            result.append(l)
        elif base and l.startswith("/"):
            result.append(base.rstrip("/") + l)
    return result

def html_forms(html):
    forms = []
    for fm in re.finditer(r'<form([^>]*)>(.*?)</form>', html, re.S | re.I):
        attrs, body = fm.group(1), fm.group(2)
        action = re.search(r'action=["\']([^"\']*)["\']', attrs, re.I)
        method = re.search(r'method=["\']([^"\']*)["\']', attrs, re.I)
        inputs = re.findall(r'<input([^>]+)>', body, re.I)
        fields = []
        for inp in inputs:
            name  = re.search(r'name=["\']([^"\']+)["\']', inp, re.I)
            itype = re.search(r'type=["\']([^"\']+)["\']', inp, re.I)
            if name:
                fields.append({
                    "name":  name.group(1),
                    "type":  (itype.group(1) if itype else "text"),
                })
        forms.append({
            "action": action.group(1) if action else "",
            "method": (method.group(1) if method else "GET").upper(),
            "fields": fields,
        })
    return forms

def html_comments(html):
    return re.findall(r"<!--(.*?)-->", html, re.S)

def html_scripts(html):
    inline = re.findall(r"<script[^>]*>(.*?)</script>", html, re.S | re.I)
    srcs   = re.findall(r"<script[^>]+src=[\"']([^\"']+)[\"']", html, re.I)
    return {"inline": inline, "src": srcs}

def html_meta(html):
    metas = {}
    for m in re.finditer(r'<meta([^>]+)>', html, re.I):
        a = m.group(1)
        name    = re.search(r'name=["\']([^"\']+)["\']', a, re.I)
        content = re.search(r'content=["\']([^"\']+)["\']', a, re.I)
        if name and content:
            metas[name.group(1)] = content.group(1)
    return metas

def headers_parse(header_str):
    """Parse raw HTTP headers string into dict."""
    result = {}
    for line in header_str.splitlines():
        if ": " in line:
            k, v = line.split(": ", 1)
            result[k.strip()] = v.strip()
    return result

def json_parse(s):
    try:    return json.loads(s)
    except: return None

def csv_parse(s, sep=","):
    rows = []
    for line in s.splitlines():
        if line.strip():
            rows.append(line.split(sep))
    return rows

def extract_emails(text):
    return re.findall(r"[\w.+-]+@[\w.-]+\.\w+", text)

def extract_ips(text):
    return re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text)

def extract_urls(text):
    return re.findall(r"https?://[^\s\"'<>]+", text)

def extract_secrets(text):
    """Find potential secrets in text using regex patterns."""
    patterns = {
        "aws_key":      r"AKIA[0-9A-Z]{16}",
        "aws_secret":   r"(?i)aws.*secret.*['\"]([A-Za-z0-9/+=]{40})['\"]",
        "github_token": r"ghp_[A-Za-z0-9]{36}",
        "jwt":          r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        "private_key":  r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
        "password":     r"(?i)(password|passwd|pwd)\s*[:=]\s*[\'\"]?([^\s\'\",]+)",
        "api_key":      r"(?i)(api[_-]?key|apikey)\s*[:=]\s*[\'\"]?([A-Za-z0-9_-]{16,})",
        "bearer":       r"(?i)bearer\s+([A-Za-z0-9._-]{20,})",
    }
    found = {}
    for name, pat in patterns.items():
        matches = re.findall(pat, text)
        if matches:
            found[name] = matches
    return found
