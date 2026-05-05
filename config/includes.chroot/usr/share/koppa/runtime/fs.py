"""KOPPA stdlib: fs — filesystem operations."""
import os, shutil, json, re, stat, tempfile, glob as _glob


def read(path):
    try:
        with open(path, errors="replace") as f:
            return f.read()
    except Exception:
        return ""

def read_bytes(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except Exception:
        return b""

def read_lines(path):
    try:
        with open(path, errors="replace") as f:
            return [l.rstrip("\n") for l in f]
    except Exception:
        return []

def write(path, content):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w") as f:
        f.write(str(content))

def write_bytes(path, data):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)

def append(path, content):
    with open(path, "a") as f:
        f.write(str(content))

def append_line(path, line):
    append(path, line + "\n")

def exists(path):
    return os.path.exists(path)

def is_file(path):
    return os.path.isfile(path)

def is_dir(path):
    return os.path.isdir(path)

def mkdir(path):
    os.makedirs(path, exist_ok=True)

def remove(path):
    try:
        if os.path.isdir(path):
            shutil.rmtree(path)
        else:
            os.remove(path)
        return True
    except Exception:
        return False

def move(src, dst):
    shutil.move(src, dst)

def copy(src, dst):
    shutil.copy2(src, dst)

def size(path):
    try:    return os.path.getsize(path)
    except: return 0

def list_dir(path=".", pattern=None):
    try:
        entries = os.listdir(path)
        if pattern:
            entries = [e for e in entries if re.search(pattern, e)]
        return sorted(entries)
    except Exception:
        return []

def glob(pattern):
    return _glob.glob(pattern, recursive=True)

def find(path, name_pat=None, min_size=None, perm_bit=None):
    """Walk a directory tree and filter files."""
    results = []
    for root, dirs, files in os.walk(path):
        for f in files:
            fp = os.path.join(root, f)
            if name_pat and not re.search(name_pat, f):
                continue
            if min_size and os.path.getsize(fp) < min_size:
                continue
            if perm_bit:
                if not (os.stat(fp).st_mode & perm_bit):
                    continue
            results.append(fp)
    return results

def find_suid():
    """Find SUID binaries."""
    return find("/", perm_bit=stat.S_ISUID)

def find_writable(path="/"):
    """Find world-writable files."""
    return find(path, perm_bit=stat.S_IWOTH)

def tmpfile(suffix="", content=""):
    f = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False)
    f.write(content); f.close()
    return f.name

def json_read(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None

def json_write(path, obj, indent=2):
    write(path, json.dumps(obj, indent=indent, default=str))

def shred(path, passes=3):
    """Securely delete a file by overwriting before removing."""
    try:
        size_bytes = os.path.getsize(path)
        with open(path, "wb") as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(size_bytes))
        os.remove(path)
        return True
    except Exception:
        return False
