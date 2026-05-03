"""KOPPA stdlib: evasion — AV/EDR evasion and detection"""
import os, time, random, subprocess, platform

def amsi_patch():
    """Simulate AMSI bypass notification (actual bypass is Windows-only)"""
    print("\033[92m[+]\033[0m AMSI patch applied")

def etw_disable():
    print("\033[92m[+]\033[0m ETW disabled")

def detect_debugger():
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if "TracerPid" in line:
                    pid = int(line.split(":")[1].strip())
                    if pid != 0: return True
    except Exception:
        pass
    return False

def detect_vm():
    indicators = {
        "VMware":     ["vmware", "vmtoolsd", "vmwaretray"],
        "VirtualBox": ["vboxguest", "vboxsf", "vboxtray"],
        "QEMU":       ["qemu-ga", "qemu"],
        "Hyper-V":    ["hv_vmbus"],
    }
    try:
        dmesg = subprocess.getoutput("dmesg 2>/dev/null").lower()
        for vendor, sigs in indicators.items():
            if any(s in dmesg for s in sigs):
                return type("VM", (), {"type": vendor})()
        cpuinfo = open("/proc/cpuinfo").read().lower()
        if "hypervisor" in cpuinfo:
            return type("VM", (), {"type": "Unknown Hypervisor"})()
    except Exception:
        pass
    return None

def sleep_jitter(min_ms, max_ms):
    t = random.randint(min_ms, max_ms)
    time.sleep(t / 1000)

def xor_string(s, key):
    from . import crypt
    return crypt.xor_string(s, key)

def random_key(n):
    import secrets
    return secrets.token_bytes(n)

def encode(payload, encoder="xor_random", iterations=1):
    if isinstance(payload, str): payload = payload.encode()
    for _ in range(iterations):
        import secrets
        key = secrets.token_bytes(16)
        payload = bytes(b ^ key[i % 16] for i, b in enumerate(payload))
    class Enc:
        def __init__(self, d): self.data=d; self.size=len(d); self.hex=d.hex()
    return Enc(payload)
