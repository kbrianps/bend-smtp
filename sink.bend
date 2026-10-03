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

type Phase is Data:
  InCmd{}
  InData{}

# The phase, the MAIL sender (empty: none yet), the recipient count,
# and the message read so far (reversed).
type Sink is Data:
  Sink{phase: Phase, from: String, rcpts: U32, data: String}

# What a line does: the next state, the reply (empty: none), whether
# the connection ends, a message to save, and whether TLS starts once
# the reply is sent.
type Step is Data:
  Step{state: Sink, reply: String, quit: Bool, saved: Maybe<&2, String>,
    tls: Bool}

type Verb is Data:
  VEhlo{}
  VHelo{}
  VMail{}
  VRcpt{}
  VData{}
  VRset{}
  VNoop{}
  VVrfy{}
  VStls{}
  VQuit{}
  VOther{}

def Sink.init() -> Sink:
  Sink{InCmd{}, "", 0, ""}

# Verbs
# -----

def Verb.pick(c: Bool, a: Verb, b: Verb) -> Verb:
  match c:
    case True{}:
      a
    case False{}:
      b

def Verb.of(+w: String) -> Verb:
  Verb.pick(String.eq(w, "EHLO"), VEhlo{},
  Verb.pick(String.eq(w, "HELO"), VHelo{},
  Verb.pick(String.eq(w, "MAIL"), VMail{},
  Verb.pick(String.eq(w, "RCPT"), VRcpt{},
  Verb.pick(String.eq(w, "DATA"), VData{},
  Verb.pick(String.eq(w, "RSET"), VRset{},
  Verb.pick(String.eq(w, "NOOP"), VNoop{},
  Verb.pick(String.eq(w, "VRFY"), VVrfy{},
  Verb.pick(String.eq(w, "STARTTLS"), VStls{},
  Verb.pick(String.eq(w, "QUIT"), VQuit{}, VOther{}))))))))))

# A line's verb: its first word, upper-cased (verbs are case-blind, RFC
# 5321 2.4); "DATAX" is no DATA.
def Verb.word(s: String) -> String:
  match s:
    case SNil{}:
      SNil{}
    case SCon{Chr{32}, _}:
      SNil{}
    case SCon{c, t}:
      SCon{c, Verb.word(t)}

# Steps
# -----

def Sink.say(st: Sink, reply: String) -> Step:
  Step{st, reply, False{}, None{}, False{}}

def Sink.rcpt(none: Bool, from: String, +n: U32, data: String) -> Step:
  match none:
    case True{}:
      Sink.say(Sink{InCmd{}, from, n, data}, "503 need MAIL first\r\n")
    case False{}:
      Sink.say(Sink{InCmd{}, from, (n + 1 : U32), data}, "250 ok\r\n")

def Sink.data(none: Bool, from: String, n: U32, data: String) -> Step:
  match none:
    case True{}:
      Sink.say(Sink{InCmd{}, from, n, data}, "503 need RCPT first\r\n")
    case False{}:
      Sink.say(Sink{InData{}, from, n, ""}, "354 end with <CRLF>.<CRLF>\r\n")

def Sink.mail(busy: Bool, from: String, +n: U32, data: String, line: String) ->
  Step:
  match busy:
    case True{}:
      Sink.say(Sink{InCmd{}, from, n, data}, "503 nested MAIL command\r\n")
    case False{}:
      Sink.say(Sink{InCmd{}, String.drop(line, 10n), 0, ""}, "250 ok\r\n")

def Sink.mail.tls(need: Bool, +from: String, +n: U32, data: String,
  line: String) -> Step:
  match need:
    case True{}:
      Sink.say(Sink{InCmd{}, from, n, data},
        "530 5.7.0 must issue a STARTTLS command first\r\n")
    case False{}:
      Sink.mail(Bool.not(String.is_empty(from)), from, n, data, line)

# The EHLO reply; STARTTLS only while it is on offer (RFC 3207 4.2).
def Sink.ehlo(offer: Bool) -> String:
  "250-bend-smtp sink\r\n"
    ++ Bool.pick(String, offer, "250-STARTTLS\r\n", "")
    ++ "250-8BITMIME\r\n250 SMTPUTF8\r\n"

# STARTTLS takes no parameters (RFC 3207 4); after its 220 the dialog
# starts over, as on a new connection.
def Sink.starttls(offer: Bool, bare: Bool, from: String, n: U32, data: String) ->
  Step:
  match offer bare:
    case True{} True{}:
      Step{Sink.init(), "220 2.0.0 ready to start TLS\r\n", False{}, None{},
        True{}}
    case True{} False{}:
      Sink.say(Sink{InCmd{}, from, n, data}, "501 5.5.4 STARTTLS takes no parameters\r\n")
    case False{} _:
      Sink.say(Sink{InCmd{}, from, n, data}, "502 5.5.1 STARTTLS is not offered\r\n")

# EHLO and HELO also reset the transaction (RFC 5321 4.1.4). offer: TLS
# is on offer and not yet on, so MAIL must wait for it.
def Sink.cmd(v: Verb, +offer: Bool, +from: String, +n: U32, data: String,
  +line: String) -> Step:
  match v:
    case VEhlo{}:
      Sink.say(Sink.init(), Sink.ehlo(offer))
    case VHelo{}:
      Sink.say(Sink.init(), "250 bend-smtp sink\r\n")
    case VMail{}:
      Sink.mail.tls(offer, from, n, data, line)
    case VRcpt{}:
      Sink.rcpt(String.is_empty(from), from, n, data)
    case VData{}:
      Sink.data(U32.is_zero(n), from, n, data)
    case VRset{}:
      Sink.say(Sink.init(), "250 ok\r\n")
    case VNoop{}:
      Sink.say(Sink{InCmd{}, from, n, data}, "250 ok\r\n")
    case VVrfy{}:
      Sink.say(Sink{InCmd{}, from, n, data},
        "252 cannot VRFY user, but will accept message\r\n")
    case VStls{}:
      Sink.starttls(offer, String.eq(String.to_upper(line), "STARTTLS"), from, n,
        data)
    case VQuit{}:
      Step{Sink{InCmd{}, from, n, data}, "221 bye\r\n", True{}, None{}, False{}}
    case VOther{}:
      Sink.say(Sink{InCmd{}, from, n, data}, "500 unknown command\r\n")

# A message line with its stuffing dot taken off.
def Sink.unstuff(l: String) -> String:
  match l:
    case SCon{Chr{46}, t}:
      t
    case SNil{}:
      SNil{}
    case SCon{c, t}:
      SCon{c, t}

# s's chars pushed onto acc, so acc ends with s reversed.
def Sink.push(s: String, acc: String) -> String:
  match s:
    case SNil{}:
      acc
    case SCon{c, t}:
      Sink.push(t, SCon{c, acc})

# In DATA, the message is kept reversed: a line is pushed on in its own
# length, where appending would copy the whole message each time.
def Sink.line(dot: Bool, from: String, n: U32, data: String, line: String) ->
  Step:
  match dot:
    case True{}:
      Step{Sink.init(), "250 ok: queued\r\n", False{}, Some{T.Text.onto(data, "")},
        False{}}
    case False{}:
      Sink.say(Sink{InData{}, from, n,
        SCon{Chr{10}, SCon{Chr{13}, Sink.push(Sink.unstuff(line), data)}}}, "")

def Sink.go(p: Phase, offer: Bool, from: String, n: U32, data: String,
  +line: String) -> Step:
  match p:
    case InCmd{}:
      Sink.cmd(Verb.of(String.to_upper(Verb.word(line))), offer, from, n, data,
        line)
    case InData{}:
      Sink.line(String.eq(line, "."), from, n, data, line)

# One line through the machine; offer: STARTTLS is on offer (and
# required before MAIL).
def Sink.stepx(st: Sink, offer: Bool, line: String) -> Step:
  Sink{p, from, n, data} = st
  Sink.go(p, offer, from, n, data, line)

# One line through the machine, with no TLS on offer.
def Sink.step(st: Sink, line: String) -> Step:
  Sink.stepx(st, False{}, line)

# IO
# --

type Mode is Data:
  MPlain{}
  MTls{}
  MStart{}

# The mode, the certificate and key files, and where messages go.
type Cfg is Data:
  Cfg{mode: Mode, cert: String, key: String, dir: String}

def Cfg.dir(c: Cfg) -> String:
  Cfg{_, _, _, d} = c
  d

def Cfg.cert(c: Cfg) -> String:
  Cfg{_, c2, _, _} = c
  c2

def Cfg.key(c: Cfg) -> String:
  Cfg{_, _, k, _} = c
  k

def Cfg.starttls(m: Mode) -> Bool:
  match m:
    case MStart{}:
      True{}
    case _:
      False{}

def Cfg.implicit(m: Mode) -> Bool:
  match m:
    case MTls{}:
      True{}
    case _:
      False{}

def Cfg.mode(c: Cfg) -> Mode:
  Cfg{m, _, _, _} = c
  m

# STARTTLS is on offer: the mode has it and TLS is not on yet.
def Cfg.offer(+c: Cfg, secure: Bool) -> Bool:
  Cfg.starttls(Cfg.mode(c)) && Bool.not(secure)

# A connection: closed, or open with the cut of its read buffer.
type Ev is Type:
  Closed{sock: Socket}
  Open{sock: Socket, line: T.Line}

# What a read gave: more bytes, or the end (a close, an error, or 5
# minutes of silence, RFC 5321 4.5.3.2.7).
def Sink.chunk(m: Socket & Result<&1, &1, U32 & String, Maybe<&1, String>>,
  buf: String) -> Ev:
  (s, r) = m
  match r:
    case Done{Some{SCon{h, t}}}:
      Open{s, T.Text.cut(buf ++ SCon{h, t})}
    case _:
      Closed{s}

def Sink.after(quit: Bool, s: Socket, rest: String) -> Ev:
  match quit:
    case True{}:
      Closed{s}
    case False{}:
      Open{s, T.Text.cut(rest)}

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
  loop: Ev -> Sink -> Bool -> U32 -> IO(Unit)) -> IO(Unit):
  (s, r) = m
  match r:
    case Done{_}:
      loop(Open{s, T.Need{""}}, Sink.init(), True{}, k)
    case Fail{e}:
      (_, msg) = e
      do IO<Unit>:
        IO.print("tls: " ++ msg)
        loop(Closed{s}, Sink.init(), False{}, k)

def Sink.next(tls: Bool, quit: Bool, s: Socket, rest: String, st: Sink,
  +cfg: Cfg, secure: Bool, k: U32, loop: Ev -> Sink -> Bool -> U32 -> IO(Unit)) ->
  IO(Unit):
  match tls:
    case True{}:
      do IO<Unit>:
        m : Socket & Result<&1, &1, U32 & String, Unit> <-
          N.Net.tls_accept(s, Cfg.cert(cfg), Cfg.key(cfg))
        Sink.upgraded(m, k, loop)
    case False{}:
      loop(Sink.after(quit, s, rest), st, secure, k)

# A line's step carried out: save, reply, maybe TLS, then the next line.
def Sink.act(step: Step, s: Socket, rest: String, +cfg: Cfg, secure: Bool,
  k: U32, loop: Ev -> Sink -> Bool -> U32 -> IO(Unit)) -> IO(Unit):
  Step{st2, reply, quit, saved, tls} = step
  do IO<Unit>:
    k2 : U32 <- Sink.save(saved, Cfg.dir(cfg), k)
    s2 : Socket <- Sink.send(s, reply)
    Sink.next(tls, quit, s2, rest, st2, cfg, secure, k2, loop)

@unsafe
def Sink.talk(ev: Ev, st: Sink, +cfg: Cfg, +secure: Bool, k: U32,
  fin: U32 -> IO(Unit)) -> IO(Unit):
  match ev:
    case Closed{s}:
      do IO<Unit>:
        N.Net.close(s)
        fin(k)
    case Open{s, ln}:
      match ln:
        case T.Need{buf}:
          do IO<Unit>:
            m : Socket & Result<&1, &1, U32 & String, Maybe<&1, String>> <-
              N.Net.poll(s, 4096, 300000)
            Sink.talk(Sink.chunk(m, buf), st, cfg, secure, k, fin)
        case T.Line{l, rest}:
          Sink.act(Sink.stepx(st, Cfg.offer(cfg, secure), l), s, rest, cfg, secure,
            k, e => st2 => sec2 => k2 => Sink.talk(e, st2, cfg, sec2, k2, fin))

def Sink.greet(s: Socket, +cfg: Cfg, secure: Bool, k: U32, fin: U32 -> IO(Unit)) ->
  IO(Unit):
  do IO<Unit>:
    s2 : Socket <- Sink.send(s, "220 bend-smtp sink ready\r\n")
    Sink.talk(Open{s2, T.Need{""}}, Sink.init(), cfg, secure, k, fin)

def Sink.opened(m: Socket & Result<&1, &1, U32 & String, Unit>, +cfg: Cfg, k: U32,
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
def Sink.open(implicit: Bool, s: Socket, +cfg: Cfg, k: U32,
  fin: U32 -> IO(Unit)) -> IO(Unit):
  match implicit:
    case True{}:
      do IO<Unit>:
        m : Socket & Result<&1, &1, U32 & String, Unit> <-
          N.Net.tls_accept(s, Cfg.cert(cfg), Cfg.key(cfg))
        Sink.opened(m, cfg, k, fin)
    case False{}:
      Sink.greet(s, cfg, False{}, k, fin)

def Sink.conn(m: Listener & Result<&1, &1, U32 & String, Socket>, +cfg: Cfg,
  k: U32, next: Listener -> U32 -> IO(Unit)) -> IO(Unit):
  (l, r) = m
  match r:
    case Fail{_}:
      next(l, k)
    case Done{s}:
      Sink.open(Cfg.implicit(Cfg.mode(cfg)), s, cfg, k, k2 => next(l, k2))

@unsafe
def Sink.serve(l: Listener, +cfg: Cfg, k: U32) -> IO(Unit):
  do IO<Unit>:
    m : Listener & Result<&1, &1, U32 & String, Socket> <- TCP.accept(l)
    Sink.conn(m, cfg, k, l2 => k2 => Sink.serve(l2, cfg, k2))

def Sink.port.or(m: Maybe<&2, U32>) -> U32:
  match m:
    case None{}:
      2525
    case Some{p}:
      p

def Sink.listen(+p: U32, +cfg: Cfg) -> IO(Unit):
  do IO<Unit>:
    l : Listener <- IO.try(Listener, TCP.listen(p))
    IO.print("sink on 127.0.0.1:" ++ U32.show(p) ++ ", saving to " ++ Cfg.dir(cfg))
    Sink.serve(l, cfg, 1)

def Sink.mode(+m: String) -> Maybe<&2, Mode>:
  Bool.pick(Maybe<&2, Mode>, String.eq(m, "tls"), Some{MTls{}},
  Bool.pick(Maybe<&2, Mode>, String.eq(m, "starttls"), Some{MStart{}}, None{}))

def Sink.with(m: Maybe<&2, Mode>, port: String, dir: String, cert: String,
  key: String) -> IO(Unit):
  match m:
    case None{}:
      IO.die(Unit, 2, "the mode is tls or starttls")
    case Some{mode}:
      Sink.listen(Sink.port.or(U32.read(port)), Cfg{mode, cert, key, dir})

def Sink.run(args: List<String>) -> IO(Unit):
  match args:
    case Con{port, Con{dir, Nil{}}}:
      Sink.listen(Sink.port.or(U32.read(port)), Cfg{MPlain{}, "", "", dir})
    case Con{port, Con{dir, Con{mode, Con{cert, Con{key, Nil{}}}}}}:
      Sink.with(Sink.mode(mode), port, dir, cert, key)
    case _:
      IO.die(Unit, 2, "usage: sink PORT DIR [tls|starttls CERT KEY]")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    Sink.run(args)
