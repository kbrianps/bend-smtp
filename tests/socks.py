"""A SOCKS5 proxy for one connection (RFC 1928, 1929), for testing.

  socks.py PORT LOG [USER PASSWORD]

Logs the target as asked (so a test can see the name was not resolved by
the client) and relays bytes both ways until either side closes.
"""
import select, socket, sys

port, logp = int(sys.argv[1]), sys.argv[2]
user, pw = (sys.argv[3], sys.argv[4]) if len(sys.argv) > 4 else ("", "")
log = open(logp, "w")
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(1)
c, _ = srv.accept()
c.settimeout(20)


def get(n):
    b = b""
    while len(b) < n:
        d = c.recv(n - len(b))
        if not d:
            raise EOFError
        b += d
    return b


ver, n = get(2)
methods = get(n)
if user:
    if 2 not in methods:
        c.sendall(b"\x05\xff")
        log.write("no acceptable method\n")
        sys.exit(0)
    c.sendall(b"\x05\x02")
    get(1)
    u = get(get(1)[0]).decode()
    p = get(get(1)[0]).decode()
    ok = (u, p) == (user, pw)
    log.write("auth %s %s\n" % (u, "ok" if ok else "refused"))
    c.sendall(b"\x01\x00" if ok else b"\x01\x01")
    if not ok:
        sys.exit(0)
else:
    c.sendall(b"\x05\x00")
ver, cmd, _, atyp = get(4)
if atyp == 3:
    host = get(get(1)[0]).decode()
elif atyp == 1:
    host = socket.inet_ntoa(get(4))
else:
    host = socket.inet_ntop(socket.AF_INET6, get(16))
tport = int.from_bytes(get(2), "big")
log.write("connect atyp=%d %s:%d\n" % (atyp, host, tport))
log.flush()
try:
    t = socket.create_connection((host, tport), timeout=10)
except OSError:
    c.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
    sys.exit(0)
c.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01" + (0).to_bytes(2, "big"))
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
