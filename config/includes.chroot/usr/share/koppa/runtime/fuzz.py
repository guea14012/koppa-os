"""KOPPA stdlib: fuzz — web fuzzing (directories, params, vhosts, headers)."""
import urllib.request, urllib.parse, urllib.error, ssl, threading, time, re

_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode    = ssl.CERT_NONE


class FuzzHit:
    def __init__(self, url, status, size, word=""):
        self.url    = url
        self.status = status
        self.size   = size
        self.word   = word
        self.found  = True

    def __repr__(self):
        return f"[{self.status}] {self.url}  ({self.size}b)"


def _get(url, headers=None, timeout=8):
    hdrs = {"User-Agent": "Mozilla/5.0 (KOPPA-OS/3.1)"}
    if headers: hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ctx) as r:
            body = r.read(4096).decode(errors="replace")
            return r.status, body
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return 0, ""


def dir_fuzz(base_url, words, threads=20, status_filter=None, timeout=8):
    """Directory/file brute force. Returns list of FuzzHit."""
    if status_filter is None:
        status_filter = lambda s: s not in (404, 0)
    hits = []
    lock = threading.Lock()
    base = base_url.rstrip("/")

    def worker(word):
        url = f"{base}/{word.strip('/')}"
        code, body = _get(url, timeout=timeout)
        if status_filter(code):
            with lock:
                hits.append(FuzzHit(url, code, len(body), word))

    _threaded(worker, words, threads)
    return hits


def param_fuzz(url, param, words, method="GET", threads=10, timeout=8):
    """Parameter value fuzzing. Returns list of FuzzHit."""
    hits = []
    lock = threading.Lock()

    def worker(word):
        target = f"{url}?{param}={urllib.parse.quote(str(word), safe='')}"
        code, body = _get(target, timeout=timeout)
        if code != 0:
            with lock:
                hits.append(FuzzHit(target, code, len(body), word))

    _threaded(worker, words, threads)
    return hits


def vhost_fuzz(ip, words, base_domain, threads=20, timeout=8):
    """Virtual host enumeration. Returns list of FuzzHit."""
    hits = []
    lock = threading.Lock()

    def worker(word):
        vhost = f"{word.strip()}.{base_domain}"
        code, body = _get(f"http://{ip}/", headers={"Host": vhost}, timeout=timeout)
        if code not in (0, 404):
            with lock:
                hits.append(FuzzHit(f"http://{vhost}/", code, len(body), vhost))

    _threaded(worker, words, threads)
    return hits


def header_fuzz(url, header_name, words, threads=10, timeout=8):
    """Fuzz a specific header. Returns list of FuzzHit."""
    hits = []
    lock = threading.Lock()

    def worker(word):
        code, body = _get(url, headers={header_name: word}, timeout=timeout)
        if code not in (0, 404):
            with lock:
                hits.append(FuzzHit(url, code, len(body), word))

    _threaded(worker, words, threads)
    return hits


def backup_fuzz(base_url, extensions=None, threads=20):
    """Find backup files for each discovered URL."""
    if extensions is None:
        extensions = [".bak", ".old", ".orig", ".backup", ".swp", "~",
                      ".tar.gz", ".zip", ".sql", ".log", ".conf"]
    return dir_fuzz(base_url, [f"{base_url}{ext}" for ext in extensions],
                    threads=threads)


def js_fuzz(url, threads=20):
    """Find JavaScript files and extract endpoints from them."""
    hits = dir_fuzz(url, ["js", "static/js", "assets/js", "app.js",
                           "main.js", "bundle.js", "vendor.js", "index.js"],
                    threads=threads)
    endpoints = set()
    for h in hits:
        code, body = _get(h.url)
        if code == 200:
            found = re.findall(r'["\']/([\w/-]+)["\']', body)
            endpoints.update(found)
    return list(endpoints)


def _threaded(worker, items, threads):
    pool = []
    for item in items:
        while len([t for t in pool if t.is_alive()]) >= threads:
            time.sleep(0.02)
        t = threading.Thread(target=worker, args=(item,), daemon=True)
        t.start()
        pool.append(t)
    for t in pool:
        t.join(timeout=30)
