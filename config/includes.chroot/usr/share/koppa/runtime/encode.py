"""KOPPA stdlib: encode — encoding and decoding utilities."""
import base64, urllib.parse, html, binascii, codecs, re, json


def b64_encode(s):
    if isinstance(s, str): s = s.encode()
    return base64.b64encode(s).decode()

def b64_decode(s):
    try:    return base64.b64decode(s + "==").decode(errors="replace")
    except: return ""

def b64url_encode(s):
    if isinstance(s, str): s = s.encode()
    return base64.urlsafe_b64encode(s).rstrip(b"=").decode()

def b64url_decode(s):
    try:    return base64.urlsafe_b64decode(s + "==").decode(errors="replace")
    except: return ""

def url_encode(s, safe=""):
    return urllib.parse.quote(str(s), safe=safe)

def url_decode(s):
    return urllib.parse.unquote(str(s))

def url_encode_all(s):
    return urllib.parse.quote(str(s), safe="")

def double_url_encode(s):
    return url_encode(url_encode(s))

def hex_encode(s):
    if isinstance(s, str): s = s.encode()
    return s.hex()

def hex_decode(s):
    try:    return bytes.fromhex(s.replace(" ", "").replace("\\x", "")).decode(errors="replace")
    except: return ""

def html_encode(s):
    return html.escape(str(s))

def html_decode(s):
    return html.unescape(str(s))

def rot13(s):
    return codecs.encode(str(s), "rot_13")

def rot_n(s, n):
    result = []
    for c in str(s):
        if c.isalpha():
            base = ord("A") if c.isupper() else ord("a")
            result.append(chr((ord(c) - base + n) % 26 + base))
        else:
            result.append(c)
    return "".join(result)

def xor_encode(s, key):
    if isinstance(s, str): s = s.encode()
    if isinstance(key, int):
        return bytes(b ^ key for b in s).hex()
    if isinstance(key, str): key = key.encode()
    return bytes(s[i] ^ key[i % len(key)] for i in range(len(s))).hex()

def xor_decode(hex_s, key):
    return xor_encode(bytes.fromhex(hex_s), key)

def unicode_encode(s):
    return "".join(f"\\u{ord(c):04x}" for c in str(s))

def char_encode(s):
    """JS-style String.fromCharCode encoding."""
    return "String.fromCharCode(" + ",".join(str(ord(c)) for c in str(s)) + ")"

def null_byte(s):
    return str(s) + "%00"

def mysql_hex(s):
    if isinstance(s, str): s = s.encode()
    return "0x" + s.hex()

def unicode_bypass(s):
    """Generate Unicode look-alike characters for WAF bypass."""
    subs = {"a": "а", "e": "е", "o": "о", "c": "с", "p": "р", "x": "х"}
    return "".join(subs.get(c, c) for c in str(s))

def case_vary(s):
    """Alternate upper/lower for case-insensitive filter bypass."""
    return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(str(s)))

def chunked_encode(s, n=3):
    s = str(s)
    return "".join(f"%{ord(c):02X}" if i % n == 0 else c for i, c in enumerate(s))
