# The test server's dialog as a pure state machine (Sink.step): what a
# line does to the state, what is answered, when a message is saved and
# when TLS starts. LAWS.bend pins it; sink.bend moves the lines between
# it and the socket.
import Base
import ./text.bend as T

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

def Sink.port.or(m: Maybe<&2, U32>) -> U32:
  match m:
    case None{}:
      2525
    case Some{p}:
      p

def Sink.mode(+m: String) -> Maybe<&2, Mode>:
  Bool.pick(Maybe<&2, Mode>, String.eq(m, "tls"), Some{MTls{}},
  Bool.pick(Maybe<&2, Mode>, String.eq(m, "starttls"), Some{MStart{}}, None{}))
