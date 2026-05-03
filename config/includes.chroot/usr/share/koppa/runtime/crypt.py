"""KOPPA stdlib: crypt — cryptography and hash operations"""
import hashlib, base64, hmac, secrets, json, struct, time, os

# ── Base64 ────────────────────────────────────────────────────────────────────
def b64_encode(data):
    if isinstance(data, str): data = data.encode()
    return base64.b64encode(data).decode()

def b64_decode(s):
    try:    return base64.b64decode(s + "==").decode(errors="replace")
    except: return ""

# ── Hashing ───────────────────────────────────────────────────────────────────
def md5(s):    return hashlib.md5(s.encode()).hexdigest()
def sha1(s):   return hashlib.sha1(s.encode()).hexdigest()
def sha256(s): return hashlib.sha256(s.encode()).hexdigest()
def sha512(s): return hashlib.sha512(s.encode()).hexdigest()

def ntlm(s):
    # NTLM = MD4(UTF-16LE)
    try:
        import hashlib
        return hashlib.new("md4", s.encode("utf-16-le")).hexdigest()
    except Exception:
        return ""

def hash_identify(h):
    l = len(h)
    if l == 32:  return "MD5 or NTLM"
    if l == 40:  return "SHA1"
    if l == 64:  return "SHA256"
    if l == 128: return "SHA512"
    if h.startswith("$2"):  return "bcrypt"
    if h.startswith("$6"):  return "sha512crypt"
    if h.startswith("$1"):  return "md5crypt"
    if h.startswith("$krb5"): return "Kerberos"
    return "Unknown"

def hash_match(hash_val, word):
    h = hash_val.lower()
    for fn in [md5, sha1, sha256, sha512, ntlm]:
        try:
            if fn(word) == h: return True
        except Exception:
            pass
    return False

# ── JWT ───────────────────────────────────────────────────────────────────────
def _b64url_enc(data):
    if isinstance(data, str): data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _b64url_dec(s):
    return base64.urlsafe_b64decode(s + "==")

def jwt_sign(payload_json, secret, alg="HS256"):
    if isinstance(payload_json, str): payload = json.loads(payload_json)
    else: payload = payload_json
    header  = _b64url_enc(json.dumps({"alg": alg, "typ": "JWT"}))
    body    = _b64url_enc(json.dumps(payload))
    sig_input = f"{header}.{body}".encode()
    if alg == "HS256":
        sig = _b64url_enc(hmac.new(secret.encode(), sig_input, hashlib.sha256).digest())
    elif alg == "HS384":
        sig = _b64url_enc(hmac.new(secret.encode(), sig_input, hashlib.sha384).digest())
    elif alg == "none":
        sig = ""
    else:
        sig = _b64url_enc(hmac.new(secret.encode(), sig_input, hashlib.sha256).digest())
    return f"{header}.{body}.{sig}"

def jwt_verify(token, secret):
    try:
        parts = token.split(".")
        if len(parts) != 3: return False
        h = json.loads(_b64url_dec(parts[0]))
        alg = h.get("alg", "HS256")
        rebuilt = jwt_sign(json.loads(_b64url_dec(parts[1])), secret, alg)
        return rebuilt == token
    except Exception:
        return False

def jwt_alg_none(token):
    parts = token.split(".")
    if len(parts) < 2: return token
    header = json.loads(_b64url_dec(parts[0]))
    header["alg"] = "none"
    return _b64url_enc(json.dumps(header)) + "." + parts[1] + "."

# ── AES (Fernet-style via XOR for portability) ────────────────────────────────
def aes_keygen():
    return secrets.token_hex(32)

def aes_encrypt(data, key):
    if isinstance(data, str): data = data.encode()
    k = bytes.fromhex(key[:64].ljust(64, "0"))
    enc = bytes(b ^ k[i % 32] for i, b in enumerate(data))
    return base64.b64encode(enc).decode()

def aes_decrypt(data, key):
    try:
        raw = base64.b64decode(data)
        k   = bytes.fromhex(key[:64].ljust(64, "0"))
        dec = bytes(b ^ k[i % 32] for i, b in enumerate(raw))
        return dec.decode(errors="replace")
    except Exception:
        return ""

# ── Misc ──────────────────────────────────────────────────────────────────────
def random_hex(n): return secrets.token_hex(n)
def random_key(n): return secrets.token_bytes(n)

class _Encoded:
    def __init__(self, data, enc_type):
        self.data = data; self.size = len(data)
        self.hex  = data.hex() if isinstance(data, bytes) else data

def xor_string(s, key):
    if isinstance(s, str): s = s.encode()
    if isinstance(key, str): key = key.encode()
    out = bytes(b ^ key[i % len(key)] for i, b in enumerate(s))
    return _Encoded(out, "xor")

def apply_rule(word, rule):
    if rule == "upper":       return word.upper()
    if rule == "lower":       return word.lower()
    if rule == "reverse":     return word[::-1]
    if rule == "leet":        return word.replace("a","4").replace("e","3").replace("i","1").replace("o","0")
    if rule == "append_year": return word + "2024"
    return word
