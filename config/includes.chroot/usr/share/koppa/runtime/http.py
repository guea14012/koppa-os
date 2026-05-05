"""KOPPA stdlib: http — HTTP client with full security-testing helpers."""
import urllib.request, urllib.parse, urllib.error, ssl, json, socket, re

_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode    = ssl.CERT_NONE


class Response:
    def __init__(self, status=0, body="", headers=None):
        self.status  = status
        self.body    = body
        self.headers = headers or {}
        self.len     = len(body)

    def __repr__(self):
        return f"<Response {self.status} {self.len}b>"

    def json(self):
        try:    return json.loads(self.body)
        except: return None


def _request(method, url, data=None, headers=None, timeout=15, follow=True):
    if not url.startswith("http"):
        url = "http://" + url
    hdrs = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; KOPPA-OS/3.1)",
        "Accept":     "*/*",
    }
    if headers:
        hdrs.update(headers)
    body = None
    if isinstance(data, dict):
        body = json.dumps(data).encode()
        hdrs.setdefault("Content-Type", "application/json")
    elif isinstance(data, str):
        body = data.encode()
    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ctx) as r:
            raw = r.read()
            try:    text = raw.decode(errors="replace")
            except: text = ""
            return Response(r.status, text, dict(r.headers))
    except urllib.error.HTTPError as e:
        try:    text = e.read().decode(errors="replace")
        except: text = ""
        return Response(e.code, text, dict(e.headers) if e.headers else {})
    except Exception:
        return Response(0, "")


def get(url, headers=None):
    return _request("GET", url, headers=headers)

def post(url, data=None, headers=None):
    return _request("POST", url, data=data, headers=headers)

def put(url, data=None, headers=None):
    return _request("PUT", url, data=data, headers=headers)

def delete(url, headers=None):
    return _request("DELETE", url, headers=headers)

def patch(url, data=None, headers=None):
    return _request("PATCH", url, data=data, headers=headers)

def request(method, url, data=None, headers=None):
    return _request(method.upper(), url, data=data, headers=headers)

def head(url, headers=None):
    return _request("HEAD", url, headers=headers)

def options(url, headers=None):
    return _request("OPTIONS", url, headers=headers)


def get_raw(url, headers=None, timeout=15):
    """Raw HTTP GET returning bytes body."""
    if not url.startswith("http"):
        url = "http://" + url
    hdrs = {"User-Agent": "KOPPA-OS/3.1"}
    if headers: hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ctx) as r:
            return r.read()
    except Exception:
        return b""


def url_encode(s):
    return urllib.parse.quote(str(s), safe="")

def url_decode(s):
    return urllib.parse.unquote(str(s))

def build_url(base, path="", params=None):
    url = base.rstrip("/") + "/" + path.lstrip("/")
    if params:
        url += "?" + urllib.parse.urlencode(params)
    return url

def extract_links(html, base_url=""):
    links = re.findall(r'href=["\']([^"\']+)["\']', html, re.I)
    result = []
    for l in links:
        if l.startswith("http"):
            result.append(l)
        elif base_url and l.startswith("/"):
            result.append(base_url.rstrip("/") + l)
    return result

def extract_forms(html):
    forms = []
    for fm in re.finditer(r'<form([^>]*)>(.*?)</form>', html, re.S | re.I):
        attrs = fm.group(1)
        body  = fm.group(2)
        action = re.search(r'action=["\']([^"\']*)["\']', attrs, re.I)
        method = re.search(r'method=["\']([^"\']*)["\']', attrs, re.I)
        inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', body, re.I)
        forms.append({
            "action": action.group(1) if action else "",
            "method": (method.group(1) if method else "GET").upper(),
            "inputs": inputs,
        })
    return forms
