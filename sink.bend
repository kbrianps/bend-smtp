# A test SMTP server: it speaks enough SMTP to take a message and saves
# each one to DIR/N.eml, unstuffed, delivering nothing to anyone. One
# connection at a time; runs until killed.
#
#   bend sink.bend -o sink
#   ./sink PORT DIR                          # plain text
#   ./sink PORT DIR tls CERT KEY             # implicit TLS (RFC 8314)
#   ./sink PORT DIR starttls CERT KEY        # STARTTLS (RFC 3207), required
#                                            # before MAIL
#
# The dialog is a pure state machine (Sink.step), which LAWS.bend pins;
# the IO part only moves lines between it and the socket.
import Base
import ./text.bend as T
import ./net.bend as N
import ./sink_core.bend as K

def Sink.sent(m: Socket & Result<&1, &1, U32 & String, Unit>) -> IO(Socket):
  (s, _) = m
  IO.pure(Socket, s)

def Sink.send(s: Socket, reply: String) -> IO(Socket):
  match reply:
    case SNil{}:
      IO.pure(Socket, s)
    case SCon{h, t}:
      do IO<Socket>:
        m : Socket & Result<&1, &1, U32 & String, Unit> <- N.Net.send(s, SCon{h, t})
        Sink.sent(m)

def Sink.wrote(m: File & Result<&1, &1, U32 & String, Unit>, path: String,
  +k: U32) -> IO(U32):
  (f, _) = m
  do IO<U32>:
    File.close(f)
    IO.print("saved " ++ path)
    IO.pure(U32, (k + 1 : U32))

def Sink.save(saved: Maybe<&2, String>, +dir: String, +k: U32) -> IO(U32):
  match saved:
    case None{}:
      IO.pure(U32, k)
    case Some{msg}:
      +path = dir ++ "/" ++ U32.show(k) ++ ".eml"
      do IO<U32>:
        f : File <- IO.try(File, File.open(path, "w"))
        m : File & Result<&1, &1, U32 & String, Unit> <- File.write(f, msg)
        Sink.wrote(m, path, k)

# After the handshake the dialog starts over with an empty buffer: what
# the client sent before it is dropped (RFC 3207 4.2).
def Sink.upgraded(m: Socket & Result<&1, &1, U32 & String, Unit>, k: U32,
  loop: K.Ev -> K.Sink -> Bool -> U32 -> IO(Unit)) -> IO(Unit):
  (s, r) = m
  match r:
    case Done{_}:
      loop(K.Open{s, T.Need{""}}, K.Sink.init(), True{}, k)
    case Fail{e}:
      (_, msg) = e
      do IO<Unit>:
        IO.print("tls: " ++ msg)
        loop(K.Closed{s}, K.Sink.init(), False{}, k)

def Sink.next(tls: Bool, quit: Bool, s: Socket, rest: String, st: K.Sink,
  +cfg: K.Cfg, secure: Bool, k: U32, loop: K.Ev -> K.Sink -> Bool -> U32 -> IO(Unit)) ->
  IO(Unit):
  match tls:
    case True{}:
      do IO<Unit>:
        m : Socket & Result<&1, &1, U32 & String, Unit> <-
          N.Net.tls_accept(s, K.Cfg.cert(cfg), K.Cfg.key(cfg))
        Sink.upgraded(m, k, loop)
    case False{}:
      loop(K.Sink.after(quit, s, rest), st, secure, k)

# A line's step carried out: save, reply, maybe TLS, then the next line.
def Sink.act(step: K.Step, s: Socket, rest: String, +cfg: K.Cfg, secure: Bool,
  k: U32, loop: K.Ev -> K.Sink -> Bool -> U32 -> IO(Unit)) -> IO(Unit):
  K.Step{st2, reply, quit, saved, tls} = step
  do IO<Unit>:
    k2 : U32 <- Sink.save(saved, K.Cfg.dir(cfg), k)
    s2 : Socket <- Sink.send(s, reply)
    Sink.next(tls, quit, s2, rest, st2, cfg, secure, k2, loop)

@unsafe
def Sink.talk(ev: K.Ev, st: K.Sink, +cfg: K.Cfg, +secure: Bool, k: U32,
  fin: U32 -> IO(Unit)) -> IO(Unit):
  match ev:
    case K.Closed{s}:
      do IO<Unit>:
        N.Net.close(s)
        fin(k)
    case K.Open{s, ln}:
      match ln:
        case T.Need{buf}:
          do IO<Unit>:
            m : Socket & Result<&1, &1, U32 & String, Maybe<&1, String>> <-
              N.Net.poll(s, 4096, 300000)
            Sink.talk(K.Sink.chunk(m, buf), st, cfg, secure, k, fin)
        case T.Line{l, rest}:
          Sink.act(K.Sink.stepx(st, K.Cfg.offer(cfg, secure), l), s, rest, cfg, secure,
            k, e => st2 => sec2 => k2 => Sink.talk(e, st2, cfg, sec2, k2, fin))

def Sink.greet(s: Socket, +cfg: K.Cfg, secure: Bool, k: U32, fin: U32 -> IO(Unit)) ->
  IO(Unit):
  do IO<Unit>:
    s2 : Socket <- Sink.send(s, "220 bend-smtp sink ready\r\n")
    Sink.talk(K.Open{s2, T.Need{""}}, K.Sink.init(), cfg, secure, k, fin)

def Sink.opened(m: Socket & Result<&1, &1, U32 & String, Unit>, +cfg: K.Cfg, k: U32,
  fin: U32 -> IO(Unit)) -> IO(Unit):
  (s, r) = m
  match r:
    case Done{_}:
      Sink.greet(s, cfg, True{}, k, fin)
    case Fail{e}:
      (_, msg) = e
      do IO<Unit>:
        N.Net.close(s)
        IO.print("tls: " ++ msg)
        fin(k)

# Implicit TLS: the handshake comes before the greeting (RFC 8314 3.3).
def Sink.open(implicit: Bool, s: Socket, +cfg: K.Cfg, k: U32,
  fin: U32 -> IO(Unit)) -> IO(Unit):
  match implicit:
    case True{}:
      do IO<Unit>:
        m : Socket & Result<&1, &1, U32 & String, Unit> <-
          N.Net.tls_accept(s, K.Cfg.cert(cfg), K.Cfg.key(cfg))
        Sink.opened(m, cfg, k, fin)
    case False{}:
      Sink.greet(s, cfg, False{}, k, fin)

def Sink.conn(m: Listener & Result<&1, &1, U32 & String, Socket>, +cfg: K.Cfg,
  k: U32, next: Listener -> U32 -> IO(Unit)) -> IO(Unit):
  (l, r) = m
  match r:
    case Fail{_}:
      next(l, k)
    case Done{s}:
      Sink.open(K.Cfg.implicit(K.Cfg.mode(cfg)), s, cfg, k, k2 => next(l, k2))

@unsafe
def Sink.serve(l: Listener, +cfg: K.Cfg, k: U32) -> IO(Unit):
  do IO<Unit>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TCP.accept(l)
    Sink.conn(m, cfg, k, l2 => k2 => Sink.serve(l2, cfg, k2))

def Sink.listen(+p: U32, +cfg: K.Cfg) -> IO(Unit):
  do IO<Unit>:
    l : Listener <- IO.try(Listener, TCP.listen("127.0.0.1", p))
    IO.print("sink on 127.0.0.1:" ++ U32.show(p) ++ ", saving to " ++ K.Cfg.dir(cfg))
    Sink.serve(l, cfg, 1)

def Sink.with(m: Maybe<&2, K.Mode>, port: String, dir: String, cert: String,
  key: String) -> IO(Unit):
  match m:
    case None{}:
      IO.die(Unit, 2, "the mode is tls or starttls")
    case Some{mode}:
      Sink.listen(K.Sink.port.or(U32.read(port)), K.Cfg{mode, cert, key, dir})

def Sink.run(args: List<String>) -> IO(Unit):
  match args:
    case Con{_, Con{port, Con{dir, Nil{}}}}:
      Sink.listen(K.Sink.port.or(U32.read(port)), K.Cfg{K.MPlain{}, "", "", dir})
    case Con{_, Con{port, Con{dir, Con{mode, Con{cert, Con{key, Nil{}}}}}}}:
      Sink.with(K.Sink.mode(mode), port, dir, cert, key)
    case _:
      IO.die(Unit, 2, "usage: sink PORT DIR [tls|starttls CERT KEY]")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    Sink.run(args)
