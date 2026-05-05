"""KOPPA stdlib: hash — hashing, cracking, identification."""
import hashlib, hmac, base64, re, subprocess


def md5(s):    return hashlib.md5(_b(s)).hexdigest()
def sha1(s):   return hashlib.sha1(_b(s)).hexdigest()
def sha256(s): return hashlib.sha256(_b(s)).hexdigest()
def sha512(s): return hashlib.sha512(_b(s)).hexdigest()

def ntlm(s):
    try:    return hashlib.new("md4", _b(s, "utf-16-le")).hexdigest()
    except: return hashlib.md4(_b(s, "utf-16-le")).hexdigest() if hasattr(hashlib, "md4") else ""

def _b(s, enc="utf-8"):
    return s.encode(enc) if isinstance(s, str) else s

def bcrypt_hash(s, rounds=12):
    try:
        import bcrypt
        return bcrypt.hashpw(_b(s), bcrypt.gensalt(rounds)).decode()
    except ImportError:
        return ""

def pbkdf2(s, salt="koppa", iterations=260000):
    return hashlib.pbkdf2_hmac("sha256", _b(s), _b(salt), iterations).hex()

def hmac_sha256(s, key):
    return hmac.new(_b(key), _b(s), hashlib.sha256).hexdigest()

def identify(h):
    h = str(h).strip()
    if re.match(r"^\$2[aby]\$", h):         return "bcrypt"
    if re.match(r"^\$6\$",      h):         return "sha512crypt"
    if re.match(r"^\$5\$",      h):         return "sha256crypt"
    if re.match(r"^\$1\$",      h):         return "md5crypt"
    if re.match(r"^\$P\$",      h):         return "phpass (WordPress)"
    if re.match(r"^\$krb5tgs\$",h):         return "Kerberos TGS (hashcat 13100)"
    if re.match(r"^\$krb5asrep\$",h):       return "AS-REP (hashcat 18200)"
    if re.match(r"^[0-9a-fA-F]{32}$", h):  return "MD5 / NTLM (32 hex)"
    if re.match(r"^[0-9a-fA-F]{40}$", h):  return "SHA1 (40 hex)"
    if re.match(r"^[0-9a-fA-F]{64}$", h):  return "SHA256 (64 hex)"
    if re.match(r"^[0-9a-fA-F]{128}$", h): return "SHA512 (128 hex)"
    if re.match(r"^[a-zA-Z0-9+/]{60}=$", h): return "bcrypt (base64 variant)"
    if re.match(r"^\*[0-9A-F]{40}$", h):   return "MySQL 4.1+ password"
    return "Unknown"

def crack(h, wordlist):
    """Try to crack a hash against a wordlist. Returns plaintext or None."""
    h = h.strip().lower()
    funcs = [md5, sha1, sha256, sha512, ntlm]
    for word in wordlist:
        for fn in funcs:
            try:
                if fn(word).lower() == h:
                    return word
            except Exception:
                pass
    return None

def crack_file(h, path):
    """Crack hash against a wordlist file. Returns plaintext or None."""
    try:
        with open(path, errors="replace") as f:
            words = [l.strip() for l in f if l.strip()]
        return crack(h, words)
    except Exception:
        return None

def hashcat(h, wordlist="/usr/share/wordlists/rockyou.txt", mode=None):
    """Run hashcat and return cracked value if found."""
    if not mode:
        htype = identify(h)
        mode_map = {
            "MD5 / NTLM (32 hex)": 0,
            "SHA1 (40 hex)":        100,
            "SHA256 (64 hex)":      1400,
            "SHA512 (128 hex)":     1700,
            "bcrypt":               3200,
            "Kerberos TGS (hashcat 13100)": 13100,
            "AS-REP (hashcat 18200)":       18200,
        }
        mode = mode_map.get(htype, 0)
    import tempfile, os
    hf = tempfile.NamedTemporaryFile(mode="w", suffix=".hash", delete=False)
    hf.write(h); hf.close()
    out = subprocess.getoutput(f"hashcat -m {mode} {hf.name} {wordlist} --potfile-disable --quiet 2>/dev/null")
    os.unlink(hf.name)
    for line in out.splitlines():
        if ":" in line and not line.startswith("["):
            parts = line.rsplit(":", 1)
            if len(parts) == 2:
                return parts[1]
    return None
