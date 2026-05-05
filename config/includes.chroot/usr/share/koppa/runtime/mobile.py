"""KOPPA stdlib: mobile — Android APK and iOS IPA security analysis."""
import subprocess, re, os, json, zipfile, tempfile


def _sh(cmd, timeout=120):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, timeout=timeout)
        return r.stdout.decode(errors="replace")
    except Exception:
        return ""


# ── Android (APK) ─────────────────────────────────────────────────────────────
def apk_info(apk_path):
    """Extract APK metadata using aapt/aapt2."""
    out = _sh(f"aapt dump badging {apk_path} 2>/dev/null || aapt2 dump badging {apk_path} 2>/dev/null")
    info = {}
    for key, pat in [
        ("package",     r"package: name='([^']+)'"),
        ("version",     r"versionName='([^']+)'"),
        ("version_code",r"versionCode='([^']+)'"),
        ("sdk_min",     r"sdkVersion:'(\d+)'"),
        ("sdk_target",  r"targetSdkVersion:'(\d+)'"),
        ("label",       r"application-label:'([^']+)'"),
    ]:
        m = re.search(pat, out)
        if m: info[key] = m.group(1)
    return info


def apk_permissions(apk_path):
    """List declared permissions in APK."""
    out = _sh(f"aapt dump permissions {apk_path} 2>/dev/null")
    return re.findall(r"uses-permission: name='([^']+)'", out)


def apk_strings(apk_path, min_len=8):
    """Extract strings from APK (from dex/resources)."""
    tmp = tempfile.mkdtemp()
    _sh(f"unzip -q {apk_path} -d {tmp}/apk 2>/dev/null")
    results = []
    for root, dirs, files in os.walk(f"{tmp}/apk"):
        for f in files:
            fp = os.path.join(root, f)
            out = _sh(f"strings -n {min_len} {fp} 2>/dev/null")
            for line in out.splitlines():
                if line.strip():
                    results.append(line.strip())
    import shutil; shutil.rmtree(tmp, ignore_errors=True)
    return list(set(results))


def apk_secrets(apk_path):
    """Scan APK for hardcoded secrets and API keys."""
    strings_list = apk_strings(apk_path)
    text = "\n".join(strings_list)
    patterns = {
        "url":        r"https?://[^\s\"'<>]+",
        "ip":         r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        "api_key":    r"(?i)(api[_-]?key|apikey)[^\w]([A-Za-z0-9_\-]{16,})",
        "aws_key":    r"AKIA[0-9A-Z]{16}",
        "jwt":        r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        "password":   r"(?i)(password|passwd|pwd)\s*[:=]\s*([^\s\"',]{6,})",
        "private_key":r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
        "firebase":   r"https://[a-z0-9-]+\.firebaseio\.com",
        "google_key": r"AIza[0-9A-Za-z\-_]{35}",
    }
    found = {}
    for name, pat in patterns.items():
        hits = re.findall(pat, text)
        if hits:
            found[name] = hits[:20]
    return found


def apk_decompile(apk_path, output_dir="/tmp/koppa_decompile"):
    """Decompile APK using jadx."""
    _sh(f"jadx -d {output_dir} {apk_path} 2>/dev/null")
    return output_dir if os.path.exists(output_dir) else ""


def apk_smali(apk_path, output_dir="/tmp/koppa_smali"):
    """Disassemble APK to smali using apktool."""
    _sh(f"apktool d {apk_path} -o {output_dir} -f 2>/dev/null")
    return output_dir if os.path.exists(output_dir) else ""


def apk_cert(apk_path):
    """Extract APK signing certificate info."""
    out = _sh(f"keytool -printcert -jarfile {apk_path} 2>/dev/null || "
              f"apksigner verify --verbose --print-certs {apk_path} 2>/dev/null")
    return out


def apk_manifest(apk_path):
    """Extract and decode AndroidManifest.xml."""
    return _sh(
        f"aapt dump xmltree {apk_path} AndroidManifest.xml 2>/dev/null || "
        f"apktool d {apk_path} -o /tmp/koppa_mf -f 2>/dev/null && "
        f"cat /tmp/koppa_mf/AndroidManifest.xml 2>/dev/null"
    )


def apk_network_security(apk_path):
    """Check if cleartext traffic is allowed."""
    manifest = apk_manifest(apk_path)
    cleartext = "android:usesCleartextTraffic=\"true\"" in manifest
    debug = "android:debuggable=\"true\"" in manifest
    return {
        "cleartext_allowed": cleartext,
        "debuggable": debug,
    }


def adb_shell(device=None, cmd="id"):
    """Run a command on connected Android device via ADB."""
    target = f"-s {device}" if device else ""
    return _sh(f"adb {target} shell {cmd} 2>/dev/null")


def adb_install(apk_path, device=None):
    target = f"-s {device}" if device else ""
    return _sh(f"adb {target} install {apk_path} 2>/dev/null")


def adb_pull(remote, local="/tmp/pulled", device=None):
    target = f"-s {device}" if device else ""
    return _sh(f"adb {target} pull {remote} {local} 2>/dev/null")


# ── iOS (IPA) ──────────────────────────────────────────────────────────────────
def ipa_info(ipa_path):
    """Extract IPA metadata from Info.plist."""
    tmp = tempfile.mkdtemp()
    _sh(f"unzip -q {ipa_path} -d {tmp} 2>/dev/null")
    plist_path = _sh(f"find {tmp} -name 'Info.plist' -maxdepth 4 2>/dev/null").strip()
    if not plist_path:
        return {}
    out = _sh(f"plutil -convert json -o - {plist_path} 2>/dev/null")
    try:
        data = json.loads(out)
        return {
            "bundle_id":   data.get("CFBundleIdentifier"),
            "name":        data.get("CFBundleName"),
            "version":     data.get("CFBundleShortVersionString"),
            "min_ios":     data.get("MinimumOSVersion"),
        }
    except Exception:
        return {}


def ipa_strings(ipa_path):
    """Extract strings from IPA binary."""
    tmp = tempfile.mkdtemp()
    _sh(f"unzip -q {ipa_path} -d {tmp} 2>/dev/null")
    binary = _sh(f"find {tmp} -type f -perm +111 2>/dev/null").strip().split("\n")[0]
    if binary:
        return [l.strip() for l in _sh(f"strings {binary} 2>/dev/null").splitlines() if len(l.strip()) > 8]
    return []


def frida_hook_template(package, function_name):
    """Generate Frida JS hook template for a function."""
    return f"""Java.perform(function() {{
  var cls = Java.use("{package}");
  cls.{function_name}.implementation = function() {{
    console.log("[KOPPA] {function_name} called, args: " + JSON.stringify(arguments));
    var ret = this.{function_name}.apply(this, arguments);
    console.log("[KOPPA] {function_name} return: " + ret);
    return ret;
  }};
}});"""
