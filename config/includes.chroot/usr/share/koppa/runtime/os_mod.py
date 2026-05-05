"""KOPPA stdlib: os — OS/shell operations with rich result objects."""
import subprocess, os, time, sys, shlex, signal


class ShellResult(str):
    """Shell result that behaves as a string (stdout) but also has .stdout/.stderr/.code."""
    def __new__(cls, stdout="", stderr="", code=0):
        obj = str.__new__(cls, stdout)
        return obj

    def __init__(self, stdout="", stderr="", code=0):
        self.stdout = stdout
        self.stderr = stderr
        self.code   = code
        self.ok     = (code == 0)

    def trim(self):
        return self.stdout.strip()

    def lines(self):
        return [l for l in self.stdout.splitlines() if l.strip()]

    def split(self, sep=None):
        return self.stdout.split(sep)

    def contains(self, s):
        return s in self.stdout

    def __repr__(self):
        return f"<ShellResult code={self.code} len={len(self.stdout)}>"


def shell(cmd, timeout=60, env=None):
    """Run a shell command. Returns ShellResult (string-compatible)."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True,
            timeout=timeout, env=env or os.environ,
        )
        stdout = result.stdout.decode(errors="replace").rstrip()
        stderr = result.stderr.decode(errors="replace").rstrip()
        return ShellResult(stdout, stderr, result.returncode)
    except subprocess.TimeoutExpired:
        return ShellResult("", "TIMEOUT", -1)
    except Exception as e:
        return ShellResult("", str(e), -1)


def exec_bg(cmd):
    """Run command in background. Returns PID."""
    try:
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        return p.pid
    except Exception:
        return -1


def which(tool):
    """Return full path of a tool if installed, else empty string."""
    r = shell(f"which {tool} 2>/dev/null")
    return r.trim()


def is_root():
    return os.getuid() == 0 if hasattr(os, "getuid") else False


def hostname():
    return shell("hostname").trim()


def username():
    return shell("whoami").trim()


def cwd():
    return os.getcwd()


def env(var, default=""):
    return os.environ.get(var, default)


def set_env(var, val):
    os.environ[var] = str(val)


def sleep(ms):
    time.sleep(ms / 1000.0)


def kill(pid, sig=signal.SIGTERM):
    try:
        os.kill(pid, sig)
        return True
    except Exception:
        return False


def platform():
    import platform as _p
    return _p.system().lower()


def arch():
    import platform as _p
    return _p.machine()


def distro():
    r = shell("cat /etc/os-release 2>/dev/null | grep ^PRETTY_NAME | cut -d= -f2 | tr -d '\"'")
    return r.trim() or shell("uname -s").trim()


def interfaces():
    r = shell("ip -o addr show 2>/dev/null")
    ifaces = {}
    for line in r.lines():
        parts = line.split()
        if len(parts) >= 4:
            name = parts[1]
            addr = parts[3].split("/")[0]
            ifaces[name] = addr
    return ifaces


def open_ports():
    r = shell("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
    ports = []
    for line in r.lines():
        m = __import__("re").search(r":(\d+)\s+", line)
        if m:
            ports.append(int(m.group(1)))
    return sorted(set(ports))


def processes():
    r = shell("ps aux --no-header 2>/dev/null || ps aux 2>/dev/null")
    procs = []
    for line in r.lines():
        parts = line.split(None, 10)
        if len(parts) >= 11:
            procs.append({"pid": parts[1], "user": parts[0], "cmd": parts[10]})
    return procs


def tool_check(tools):
    """Return dict {tool: installed_bool} for a list of tool names."""
    return {t: bool(which(t)) for t in tools}
