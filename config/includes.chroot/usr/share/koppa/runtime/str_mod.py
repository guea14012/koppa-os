"""KOPPA stdlib: str — string utility functions."""
import re, json, unicodedata


def contains(s, sub):
    return sub.lower() in str(s).lower() if sub else False

def contains_exact(s, sub):
    return sub in str(s)

def lines(s):
    return [l.rstrip("\r") for l in str(s).splitlines()]

def strip(s):
    return str(s).strip()

def lstrip(s, chars=None):
    return str(s).lstrip(chars)

def rstrip(s, chars=None):
    return str(s).rstrip(chars)

def split(s, delim=None, maxsplit=-1):
    if maxsplit >= 0:
        return str(s).split(delim, maxsplit)
    return str(s).split(delim)

def join(parts, delim=""):
    return delim.join(str(p) for p in parts)

def replace(s, old, new, count=-1):
    if count >= 0:
        return str(s).replace(old, new, count)
    return str(s).replace(old, new)

def upper(s):  return str(s).upper()
def lower(s):  return str(s).lower()
def title(s):  return str(s).title()

def startswith(s, prefix):  return str(s).startswith(prefix)
def endswith(s, suffix):    return str(s).endswith(suffix)

def length(s):  return len(str(s))

def find(s, sub, start=0):
    return str(s).find(sub, start)

def count(s, sub):
    return str(s).count(sub)

def repeat(s, n):
    return str(s) * n

def reverse(s):
    return str(s)[::-1]

def pad_left(s, width, char=" "):
    return str(s).rjust(width, char)

def pad_right(s, width, char=" "):
    return str(s).ljust(width, char)

def truncate(s, n, suffix="..."):
    s = str(s)
    return s[:n] + suffix if len(s) > n else s

def extract(s, pattern, group=0):
    m = re.search(pattern, s)
    return m.group(group) if m else ""

def extract_all(s, pattern, group=0):
    return re.findall(pattern if group == 0 else f"({pattern})", s)

def match(s, pattern):
    return bool(re.search(pattern, s))

def grep(lines_list, pattern):
    return [l for l in lines_list if re.search(pattern, l)]

def between(s, start, end):
    """Extract text between two delimiters."""
    m = re.search(re.escape(start) + r"(.*?)" + re.escape(end), s, re.S)
    return m.group(1) if m else ""

def to_hex(s):
    return str(s).encode().hex()

def from_hex(h):
    try:    return bytes.fromhex(h).decode(errors="replace")
    except: return ""

def chunks(s, n):
    s = str(s)
    return [s[i:i+n] for i in range(0, len(s), n)]

def is_ip(s):
    import socket
    try:    socket.inet_aton(s); return True
    except: return False

def is_url(s):
    return bool(re.match(r"https?://[^\s]+", str(s)))

def is_email(s):
    return bool(re.match(r"[\w.+-]+@[\w.-]+\.\w+", str(s)))

def slug(s):
    s = unicodedata.normalize("NFKD", str(s)).encode("ascii", "ignore").decode()
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")

def wrap(s, width=80):
    import textwrap
    return textwrap.fill(str(s), width)

def parse_json(s):
    try:    return json.loads(s)
    except: return None

def to_json(obj, indent=None):
    return json.dumps(obj, indent=indent, default=str)
