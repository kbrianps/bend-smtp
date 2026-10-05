# Net: connections that may turn TLS mid-stream (net.c, native only).
# A connection is a Socket; after Net.tls, Net.send, Net.poll and
# Net.close go through the TLS session. Net.connect resolves host names,
# which Base's TCP.connect does not.
import Base

# A host (name or IP) and port; tries every address it resolves to.
def Net.connect(host: String, port: U32) ->
  IO(Result<&1, &1, U32 & String, Socket>):
  import "./net.c"
  import "./net.js"

# A verified TLS 1.2+ session on the socket, for host; cafile "" trusts
# the system's certificate store; cert and key ("" for none) are PEM
# files with this side's certificate, for a server that asks for one.
def Net.tls(sock: Socket, host: String, cafile: String, cert: String,
  key: String) -> IO(Socket & Result<&1, &1, U32 & String, Unit>):
  import "./net.c"
  import "./net.js"

# A connection to host:port through a proxy, which resolves the host:
# kind 0 is SOCKS5 (RFC 1928; user "" skips its password step, RFC
# 1929), kind 1 an HTTP proxy's CONNECT (RFC 9110 9.3.6; user "" sends
# no Proxy-Authorization).
def Net.connect_via(proxy: String, pport: U32, user: String, pass: String,
  host: String, port: U32, kind: U32) -> IO(Result<&1, &1, U32 & String, Socket>):
  import "./net.c"
  import "./net.js"

# The server's side of the handshake, with a PEM certificate chain and
# its PEM key.
def Net.tls_accept(sock: Socket, cert: String, key: String) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  import "./net.c"
  import "./net.js"

def Net.send(sock: Socket, data: String) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
  import "./net.c"
  import "./net.js"

# Up to max bytes; Some{""} when the peer closed, None{} after ms.
def Net.poll(sock: Socket, max: U32, ms: U32) ->
  IO(Socket & Result<&1, &1, U32 & String, Maybe<&1, String>>):
  import "./net.c"
  import "./net.js"

def Net.close(sock: Socket) -> IO(Unit):
  import "./net.c"
  import "./net.js"

# Seconds since 1970-01-01 UTC.
def Net.time() -> IO(U32):
  import "./net.c"
  import "./net.js"

# What to say after EHLO: the host's FQDN, else an address literal.
def Net.helo(sock: Socket) -> IO(Socket & String):
  import "./net.c"
  import "./net.js"

# The host's name as configured, maybe not fully qualified (for HELO).
def Net.hostname() -> IO(String):
  import "./net.c"
  import "./net.js"

# Turn the dialog trace on (1) or off (0): every line sent and received
# goes to stderr as "C: " and "S: ", with AUTH data masked and the
# message's text replaced by its size.
def Net.debug(on: U32) -> IO(Unit):
  import "./net.c"
  import "./net.js"

# DKIM's hash and signature (the pure parts are in dkim.bend)
# ----------------------------------------------------------

# The SHA-256 of a text's bytes, in base64.
def Dkim.sha256(data: String) -> IO(Result<&1, &1, U32 & String, String>):
  import "./net.c"
  import "./net.js"

# "rsa-sha256" or "ed25519-sha256", by the kind of the PEM private key.
def Dkim.alg(keyfile: String) -> IO(Result<&1, &1, U32 & String, String>):
  import "./net.c"
  import "./net.js"

# The signature of a text's bytes with the PEM private key, in base64.
def Dkim.sign(keyfile: String, data: String) ->
  IO(Result<&1, &1, U32 & String, String>):
  import "./net.c"
  import "./net.js"
