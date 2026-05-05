"""KOPPA stdlib: iot — IoT/ICS security testing (MQTT, Modbus, RTSP, etc.)."""
import subprocess, socket, re, json, struct


def _sh(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, timeout=timeout)
        return r.stdout.decode(errors="replace")
    except Exception:
        return ""


# ── MQTT ──────────────────────────────────────────────────────────────────────
def mqtt_connect(host, port=1883, user="", password="", timeout=10):
    """Test unauthenticated MQTT broker access."""
    cmd = f"mosquitto_sub -h {host} -p {port} -t '#' -C 5 --quiet"
    if user:
        cmd += f" -u {user} -P {password}"
    out = _sh(cmd, timeout=timeout + 5)
    return {"connected": bool(out), "messages": out.splitlines()[:10]}


def mqtt_topics(host, port=1883):
    """Subscribe to all topics and collect messages."""
    return _sh(
        f"mosquitto_sub -h {host} -p {port} -t '#' -C 20 --quiet 2>/dev/null",
        timeout=20
    ).splitlines()


def mqtt_publish(host, topic, message, port=1883):
    return _sh(f"mosquitto_pub -h {host} -p {port} -t {topic} -m '{message}' 2>/dev/null")


# ── Modbus/ICS ────────────────────────────────────────────────────────────────
def modbus_scan(host, port=502):
    """Scan Modbus TCP device and read coils/registers."""
    try:
        s = socket.create_connection((host, port), timeout=10)
        # Modbus read coils: unit 1, function 1, address 0, count 16
        req = bytes([0x00, 0x01, 0x00, 0x00, 0x00, 0x06,
                     0x01, 0x01, 0x00, 0x00, 0x00, 0x10])
        s.sendall(req)
        resp = s.recv(256)
        s.close()
        return {"connected": True, "response": resp.hex(), "port": port}
    except Exception as e:
        return {"connected": False, "error": str(e)}


def bacnet_scan(host, port=47808):
    """Test BACnet/IP devices."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(5)
        # BACnet Who-Is broadcast
        pkt = bytes([0x81, 0x0b, 0x00, 0x08, 0x01, 0x20,
                     0xff, 0xff, 0x00, 0xff, 0x10, 0x08])
        s.sendto(pkt, (host, port))
        data, addr = s.recvfrom(1024)
        return {"device": addr[0], "response": data.hex()}
    except Exception:
        return {}


# ── RTSP (Cameras) ────────────────────────────────────────────────────────────
def rtsp_scan(host, port=554, paths=None):
    """Discover RTSP streams on IP cameras."""
    if paths is None:
        paths = ["/", "/live", "/stream", "/cam/realmonitor",
                 "/video1", "/videoMain", "/h264Preview_01_main",
                 "/Streaming/Channels/1", "/ch01.264", "/live/ch00_0"]
    found = []
    for path in paths:
        try:
            s = socket.create_connection((host, port), timeout=5)
            req = f"OPTIONS rtsp://{host}:{port}{path} RTSP/1.0\r\nCSeq: 1\r\n\r\n"
            s.sendall(req.encode())
            resp = s.recv(256).decode(errors="replace")
            s.close()
            if "RTSP/1.0 200" in resp or "RTSP/1.1 200" in resp:
                found.append(f"rtsp://{host}:{port}{path}")
        except Exception:
            pass
    return found


def rtsp_brute(host, port=554, path="/"):
    """Test common RTSP credentials."""
    creds = [
        ("admin", "admin"), ("admin", "12345"), ("admin", ""),
        ("root", "root"), ("root", ""), ("admin", "password"),
        ("admin", "1234"), ("guest", "guest"), ("admin", "888888"),
    ]
    for user, pw in creds:
        try:
            s = socket.create_connection((host, port), timeout=5)
            req = (f"DESCRIBE rtsp://{host}:{port}{path} RTSP/1.0\r\n"
                   f"CSeq: 1\r\nAuthorization: Basic "
                   f"{__import__('base64').b64encode(f'{user}:{pw}'.encode()).decode()}\r\n\r\n")
            s.sendall(req.encode())
            resp = s.recv(256).decode(errors="replace")
            s.close()
            if "200 OK" in resp:
                return {"user": user, "password": pw, "url": f"rtsp://{host}:{port}{path}"}
        except Exception:
            pass
    return None


# ── Generic IoT ───────────────────────────────────────────────────────────────
def iot_ports():
    """Return list of common IoT/ICS ports to scan."""
    return {
        "mqtt":      1883,
        "mqtt_tls":  8883,
        "coap":      5683,
        "modbus":    502,
        "bacnet":    47808,
        "dnp3":      20000,
        "iec60870":  2404,
        "rtsp":      554,
        "onvif":     80,
        "hikvision": 8000,
        "dahua":     37777,
        "telnet":    23,
        "snmp":      161,
        "upnp":      1900,
        "zigbee":    4995,
    }


def snmp_walk(host, community="public", version="2c"):
    """Walk SNMP OID tree."""
    return _sh(
        f"snmpwalk -v {version} -c {community} {host} 2>/dev/null",
        timeout=30
    )


def snmp_brute(host, wordlist=None):
    """Brute-force SNMP community strings."""
    if wordlist is None:
        wordlist = ["public", "private", "community", "manager", "cisco", "admin",
                    "default", "monitor", "password", "read", "write", "secret"]
    for community in wordlist:
        out = _sh(
            f"snmpget -v2c -c {community} {host} sysDescr.0 2>/dev/null",
            timeout=5
        )
        if "STRING:" in out or "OCTET" in out:
            return community
    return None


def upnp_discover(iface=None):
    """Discover UPnP devices on the network."""
    return _sh("upnp-inspector 2>/dev/null || miranda -i 2>/dev/null || "
               "gssdp-discover -t 30 2>/dev/null", timeout=35)


def firmware_strings(path, min_len=10):
    """Extract interesting strings from firmware binary."""
    out = _sh(f"strings -n {min_len} {path} 2>/dev/null")
    interesting = []
    patterns = [
        r"https?://\S+",
        r"(?i)(password|passwd|secret|key)\s*[:=]\s*\S+",
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}",
        r"(?i)(admin|root|user)\s*[:=]\s*\S+",
    ]
    for line in out.splitlines():
        for pat in patterns:
            if re.search(pat, line):
                interesting.append(line.strip())
                break
    return interesting
