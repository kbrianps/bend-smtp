"""A scriptable SMTP server for testing the client (stdlib only).

One connection, then it exits. Writes the dialog (C:/S: lines) to
--log and the message, as received after unstuffing, to --out.

  --mode plain|tls|starttls   implicit TLS wraps the socket at once;
                              starttls offers STARTTLS (and requires it
                              before MAIL)
  --auth none|plain|login|xoauth2|oauthbearer
                              the AUTH mechanism to offer (needs TLS)
  --token T                   the bearer token OAuth must carry
  --user/--password           the credentials AUTH must carry
  --no-ehlo                   answer EHLO 502 (an old server: HELO only)
  --size N                    announce SIZE N
  --reject-rcpt               answer RCPT 550
  --reject ADDR               answer RCPT 550 for this address (repeats)
  --smtputf8                  announce SMTPUTF8 (RFC 6531)
  --inject                    put a plaintext "250 injected" right after
                              STARTTLS's 220 (the client must refuse)
"""
import argparse, base64, socket, ssl

p = argparse.ArgumentParser()
p.add_argument("--port", type=int, required=True)
p.add_argument("--mode", default="plain")
p.add_argument("--auth", default="none")
p.add_argument("--user", default="")
p.add_argument("--password", default="")
p.add_argument("--no-ehlo", action="store_true")
p.add_argument("--size", type=int, default=0)
p.add_argument("--reject-rcpt", action="store_true")
p.add_argument("--reject", action="append", default=[])
p.add_argument("--token", default="")
p.add_argument("--inject", action="store_true")
p.add_argument("--smtputf8", action="store_true")
p.add_argument("--cert", default="")
p.add_argument("--key", default="")
p.add_argument("--log", required=True)
p.add_argument("--out", required=True)
a = p.parse_args()

ctx = None
if a.mode != "plain":
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(a.cert, a.key)

log = open(a.log, "w")
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", a.port))
srv.listen(1)
print("ready", flush=True)
conn, _ = srv.accept()
conn.settimeout(20)
if a.mode == "tls":
    conn = ctx.wrap_socket(conn, server_side=True)
f = conn.makefile("rb")
secure = a.mode == "tls"
authed = a.auth == "none"


def say(x):
    conn.sendall(x.encode())
    for line in x.strip("\r\n").split("\r\n"):
        log.write("S: " + line + "\n")


def line():
    l = f.readline()
    if not l:
        raise EOFError
    if not l.endswith(b"\r\n"):
        log.write("BAD LINE ENDING: %r\n" % l)
    return l[:-2].decode("utf-8", "replace") if l.endswith(b"\r\n") else l.decode()


def caps():
    out = ["250-test.example"]
    if a.mode == "starttls" and not secure:
        out.append("250-STARTTLS")
    if secure and a.auth == "plain":
        out.append("250-AUTH PLAIN")
    if secure and a.auth == "login":
        out.append("250-AUTH LOGIN")
    if secure and a.auth == "xoauth2":
        out.append("250-AUTH XOAUTH2 PLAIN-CLIENTTOKEN")
    if secure and a.auth == "oauthbearer":
        out.append("250-AUTH OAUTHBEARER")
    if a.size:
        out.append("250-SIZE %d" % a.size)
    if a.smtputf8:
        out.append("250-SMTPUTF8")
    out.append("250 8BITMIME")
    out[-1] = out[-1].replace("250-", "250 ", 1)
    return "\r\n".join(out) + "\r\n"


say("220 test.example ESMTP ready\r\n")
try:
    while True:
        l = line()
        if len(l) + 2 > 512:
            log.write("LONG COMMAND LINE: %d octets\n" % (len(l) + 2))
        log.write("C: " + (l if not l.upper().startswith("AUTH PLAIN ") else "AUTH PLAIN <b64>") + "\n")
        v = l[:4].upper()
        if v == "EHLO":
            say("502 command not implemented\r\n" if a.no_ehlo else caps())
        elif v == "HELO":
            say("250 test.example\r\n")
        elif l.upper() == "STARTTLS" and a.mode == "starttls" and not secure:
            say("220 go ahead\r\n" + ("250 injected\r\n" if a.inject else ""))
            if a.inject:
                log.write("S: (injected a plaintext reply)\n")
            conn = ctx.wrap_socket(conn, server_side=True)
            f = conn.makefile("rb")
            secure = True
        elif v == "AUTH":
            parts = l.split()
            if not secure:
                say("538 encryption required\r\n")
                continue
            mech = parts[1].upper()
            if mech in ("XOAUTH2", "OAUTHBEARER"):
                if len(parts) == 3:
                    resp = parts[2]
                else:
                    say("334 \r\n")
                    resp = line()
                    log.write("C: <b64 %s response>\n" % mech)
                raw = base64.b64decode(resp).decode()
                fields = dict(f.split("=", 1) for f in raw.split("\x01") if "=" in f)
                if mech == "XOAUTH2":
                    u = fields.get("user", "")
                else:
                    gs2 = raw.split("\x01")[0]
                    u = gs2.split("a=", 1)[1].rstrip(",").replace("=2C", ",").replace("=3D", "=")
                    log.write("OAUTHBEARER host=%s port=%s\n" % (fields.get("host"), fields.get("port")))
                tok = fields.get("auth", "")
                if u == a.user and tok == "Bearer " + a.token:
                    authed = True
                    say("235 2.7.0 accepted\r\n")
                else:
                    err = base64.b64encode(b'{"status":"401","schemes":"bearer","scope":"https://mail.google.com/"}').decode()
                    say("334 " + err + "\r\n")
                    cancel = line()
                    log.write("C: cancel %r\n" % cancel)
                    say("535 5.7.8 Username and Password not accepted\r\n")
                continue
            if parts[1].upper() == "PLAIN" and len(parts) == 3:
                _, u, pw = base64.b64decode(parts[2]).split(b"\0")
            elif parts[1].upper() == "PLAIN":
                say("334 \r\n")
                _, u, pw = base64.b64decode(line()).split(b"\0")
                log.write("C: <b64 plain response>\n")
            elif parts[1].upper() == "LOGIN":
                say("334 VXNlcm5hbWU6\r\n")
                u = base64.b64decode(line())
                log.write("C: <b64 user>\n")
                say("334 UGFzc3dvcmQ6\r\n")
                pw = base64.b64decode(line())
                log.write("C: <b64 password>\n")
            else:
                say("504 unrecognized\r\n")
                continue
            if u.decode() == a.user and pw.decode() == a.password:
                authed = True
                say("235 2.7.0 authenticated\r\n")
            else:
                say("535 5.7.8 bad credentials\r\n")
        elif v == "MAIL":
            if a.mode == "starttls" and not secure:
                say("530 5.7.0 must issue STARTTLS first\r\n")
            elif not authed:
                say("530 5.7.0 authentication required\r\n")
            else:
                say("250 ok\r\n")
        elif v == "RCPT":
            addr = l[l.find("<") + 1:l.rfind(">")]
            bad = a.reject_rcpt or addr in a.reject
            say("550 5.1.1 no such user\r\n" if bad else "250 ok\r\n")
        elif v == "DATA":
            say("354 go\r\n")
            data = []
            while True:
                d = f.readline()
                if d == b".\r\n":
                    break
                if not d.endswith(b"\r\n") or len(d) > 1000:
                    log.write("BAD DATA LINE: %r\n" % d[:80])
                data.append(d[1:] if d.startswith(b".") else d)
            open(a.out, "wb").write(b"".join(data))
            say("250 2.0.0 queued\r\n")
        elif v == "QUIT":
            say("221 bye\r\n")
            break
        else:
            say("502 unknown\r\n")
except (EOFError, ConnectionError, ssl.SSLError, socket.timeout) as e:
    log.write("END: %s\n" % type(e).__name__)
log.close()
conn.close()
