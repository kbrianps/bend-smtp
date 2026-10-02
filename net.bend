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
# the system's certificate store.
def Net.tls(sock: Socket, host: String, cafile: String) ->
  IO(Socket & Result<&1, &1, U32 & String, Unit>):
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
