"""An HTTP proxy for one CONNECT tunnel (RFC 9110 9.3.6), for testing.

  httpproxy.py PORT LOG [USER PASSWORD]

Logs the target as asked and the credentials' verdict, answers 407
without the right ones, and relays bytes both ways until a side closes.
"""
import base64, select, socket, sys

port, logp = int(sys.argv[1]), sys.argv[2]
user, pw = (sys.argv[3], sys.argv[4]) if len(sys.argv) > 4 else ("", "")
log = open(logp, "w")
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(1)
c, _ = srv.accept()
c.settimeout(20)
head = b""
while not head.endswith(b"\r\n\r\n"):
    d = c.recv(1)
    if not d:
        sys.exit(0)
    head += d
lines = head.decode("utf-8", "replace").split("\r\n")
method, target, _ = lines[0].split(" ")
log.write("%s %s\n" % (method, target))
hdrs = {l.split(":", 1)[0].lower(): l.split(":", 1)[1].strip() for l in lines[1:] if ":" in l}
if user:
    want = "Basic " + base64.b64encode(("%s:%s" % (user, pw)).encode()).decode()
    ok = hdrs.get("proxy-authorization") == want
    log.write("auth %s\n" % ("ok" if ok else "refused"))
    if not ok:
        c.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n")
        sys.exit(0)
log.flush()
if method != "CONNECT":
    c.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
    sys.exit(0)
host, _, tport = target.rpartition(":")
try:
    t = socket.create_connection((host.strip("[]"), int(tport)), timeout=10)
except OSError:
    c.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
    sys.exit(0)
c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
c.settimeout(None)
while True:
    r, _, _ = select.select([c, t], [], [], 30)
    if not r:
        break
    done = False
    for s in r:
        d = s.recv(65536)
        if not d:
            done = True
            break
        (t if s is c else c).sendall(d)
    if done:
        break
