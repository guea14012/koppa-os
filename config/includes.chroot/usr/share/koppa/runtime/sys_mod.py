"""KOPPA stdlib: sys — system operations"""
import subprocess, os, time, random, secrets, sys as _sys

def exec(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL,
                                       timeout=30).decode(errors="replace")
    except Exception:
        return ""

def prompt(msg=""):  return input(msg)
def sleep(ms):       time.sleep(ms / 1000)
def time_ms():       return int(time.time() * 1000)
def exit(code=0):    _sys.exit(code)
def range(a, b):     return list(__builtins__["range"](a, b) if isinstance(__builtins__, dict) else __import__("builtins").range(a, b))
def random_int(a, b):return random.randint(a, b)
def random_hex(n):   return secrets.token_hex(n)

def read_lines(path):
    try:
        with open(path, "r", errors="replace") as f:
            return [l.rstrip("\n") for l in f if l.strip()]
    except Exception:
        return []

def read_file(path):
    try:
        with open(path, "r", errors="replace") as f: return f.read()
    except Exception:
        return ""

def write_file(path, data):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f: f.write(data)

def screenshot():
    exec("scrot /tmp/koppa_screen.png 2>/dev/null || import -window root /tmp/koppa_screen.png 2>/dev/null")
    try:
        with open("/tmp/koppa_screen.png", "rb") as f: return f.read()
    except Exception:
        return b""
