# SMTP client (RFC 5321), with STARTTLS (RFC 3207), implicit TLS (RFC
# 8314), SIZE (RFC 1870), SMTPUTF8 (RFC 6531) and AUTH PLAIN, LOGIN,
# XOAUTH2 and OAUTHBEARER (RFC 4954, 4616, 7628). One message per
# connection:
#
#   S: 220 greeting                 (implicit TLS: after the handshake)
#   C: EHLO name          S: 250    (a 5xx: HELO name, no extensions)
#   C: STARTTLS           S: 220    (STARTTLS mode; then the handshake
#                                    and EHLO again, RFC 3207 4.2)
#   C: AUTH ...           S: 235    (with a user; only under TLS)
#   C: MAIL FROM:<from>   S: 250
#   C: RCPT TO:<to>       S: 250    (once per To, Cc and Bcc address; a
#                                    refused one is reported, not fatal)
#   C: DATA               S: 354
#   C: the message, then "."   S: 250
#   C: QUIT               S: 221
#
# Any other refusal ends the talk with QUIT. The pure part (commands,
# capabilities, mechanisms, the message) is what LAWS.bend pins; the IO
# part threads the socket and the read buffer through continuations.
import Base
import ./text.bend as T
import ./reply.bend as R
import ./mime.bend as M
import ./net.bend as N
import ./idna.bend as I
import ./addr.bend as A

# A message: sender, To, Cc, Bcc (never in the headers), Reply-To,
# subject, plain text, HTML ("" for none) and attachments.
type Mail is Data:
  Mail{from: A.Mbox, to: List<&2, A.Mbox>, cc: List<&2, A.Mbox>,
    bcc: List<&2, A.Mbox>, reply: List<&2, A.Mbox>, subject: String,
    text: String, html: String, files: List<&2, M.Part>}

# Plain: no TLS. Tls: TLS from the first byte (port 465). StartTls: plain,
# then STARTTLS, and the talk refuses to go on without it (port 587).
type Mode is Data:
  Plain{}
  Tls{}
  StartTls{}

# The AUTH mechanism asked for; AAuto picks from what the server offers.
type Auth is Data:
  AAuto{}
  APlain{}
  ALogin{}
  AXoauth2{}
  ABearer{}

# Where and how to send. cafile "" trusts the system's store; user ""
# sends no AUTH; helo "" asks the host (Net.helo); token is an OAuth 2
# access token ("" for none).
type Opts is Data:
  Opts{host: String, port: U32, mode: Mode, cafile: String, helo: String,
    user: String, pass: String, auth: Auth, token: String}

# What EHLO announced: STARTTLS, the AUTH mechanisms, SIZE (0: none),
# SMTPUTF8 and 8BITMIME.
type Caps is Data:
  Caps{tls: Bool, mechs: List<&2, String>, size: U32, utf8: Bool, eight: Bool}

# The mechanism to use, or why there is none.
type Mech is Data:
  MPlain{}
  MLogin{}
  MXoauth2{}
  MBearer{}
  MNo{why: String}

# The outcome: an error, or the recipients the server refused (the rest
# got the message).
def Out() -> Type:
  Result<&1, &1, U32 & String, List<&2, String>>

def Caps.none() -> Caps:
  Caps{False{}, Nil{}, 0, False{}, False{}}

# The message's addresses
# -----------------------

def Mail.from(m: Mail) -> String:
  Mail{f, _, _, _, _, _, _, _, _} = m
  A.Mbox.addr(f)

def Smtp.uniq.at(seen: Bool, +x: String, rest: List<&2, String>) ->
  List<&2, String>:
  match seen:
    case True{}:
      rest
    case False{}:
      x <> rest

def Smtp.uniq(xs: List<&2, String>, +seen: List<&2, String>) -> List<&2, String>:
  match xs:
    case Nil{}:
      Nil{}
    case Con{+x, t}:
      Smtp.uniq.at(List.contains(~String, ~String.eq, seen, x), x,
        Smtp.uniq(t, x <> seen))

# Who gets RCPT: To, Cc and Bcc, each address once.
def Mail.rcpts(m: Mail) -> List<&2, String>:
  Mail{_, to, cc, bcc, _, _, _, _, _} = m
  Smtp.uniq(List.append(&2, String, A.Mbox.addrs(to),
    List.append(&2, String, A.Mbox.addrs(cc), A.Mbox.addrs(bcc))), Nil{})

# Whether the message needs SMTPUTF8 (RFC 6531): some local part is not
# ASCII. A non-ASCII domain alone does not: it goes as A-labels.
def Mail.utf8(m: Mail) -> Bool:
  Mail{from, to, cc, bcc, reply, _, _, _, _} = m
  A.Addr.utf8(A.Mbox.addr(from)) || A.Mbox.any.utf8(to) || A.Mbox.any.utf8(cc)
    || A.Mbox.any.utf8(bcc) || A.Mbox.any.utf8(reply)

def Mail.ascii.at(utf8: Bool, m: Mail) -> Mail:
  match utf8:
    case True{}:
      m
    case False{}:
      Mail{from, to, cc, bcc, reply, subject, text, html, files} = m
      Mail{A.Mbox.ascii(from), A.Mbox.asciis(to), A.Mbox.asciis(cc),
        A.Mbox.asciis(bcc), A.Mbox.asciis(reply), subject, text, html, files}

# The addresses as they will travel: with A-label domains, unless the
# message needs SMTPUTF8, which carries them as written.
def Mail.ascii(+m: Mail) -> Mail:
  Mail.ascii.at(Mail.utf8(m), m)

def Mail.bad(+what: String, +a: String) -> String:
  Bool.pick(String, String.is_empty(a), "", "bad " ++ what ++ " address: " ++ a)

# What is wrong with a message's addresses, or "" if nothing.
def Mail.problem(+m: Mail) -> String:
  Mail{from, to, cc, bcc, reply, _, _, _, _} = m
  +f = A.Mbox.addr(from)
  +b = A.Mbox.bad(to) ++ A.Mbox.bad(cc) ++ A.Mbox.bad(bcc)
  Bool.pick(String, Bool.not(A.Addr.ok(f)), "bad sender address: " ++ f,
  Bool.pick(String, List.is_empty(&2, String, Mail.rcpts(m)), "no recipients",
  Bool.pick(String, Bool.not(String.is_empty(b)), "bad recipient address: " ++ b,
    Mail.bad("Reply-To", A.Mbox.bad(reply)))))

# Commands
# --------

def Smtp.ehlo(name: String) -> String:
  "EHLO " ++ T.Text.clean(name) ++ "\r\n"

def Smtp.helo(name: String) -> String:
  "HELO " ++ T.Text.clean(name) ++ "\r\n"

def Smtp.size.param(+size: U32, +len: U32) -> String:
  Bool.pick(String, U32.is_zero(size), "", " SIZE=" ++ U32.show(len))

# SMTPUTF8 (RFC 6531 3.4) and, when the server has it, BODY=8BITMIME:
# the headers then carry UTF-8 addresses (RFC 6532).
def Smtp.utf8.param(utf8: Bool, eight: Bool) -> String:
  match utf8:
    case True{}:
      " SMTPUTF8" ++ Bool.pick(String, eight, " BODY=8BITMIME", "")
    case False{}:
      ""

# MAIL, with the message's size (octets) when the server announced SIZE,
# and SMTPUTF8 when the message needs it.
def Smtp.mail(from: String, +size: U32, +len: U32, utf8: Bool, eight: Bool) ->
  String:
  "MAIL FROM:<" ++ T.Text.clean(from) ++ ">" ++ Smtp.size.param(size, len)
    ++ Smtp.utf8.param(utf8, eight) ++ "\r\n"

def Smtp.rcpt(to: String) -> String:
  "RCPT TO:<" ++ T.Text.clean(to) ++ ">\r\n"

# SASL
# ----

def Sasl.soh() -> String:
  SCon{Chr{1}, SNil{}}

# AUTH PLAIN's response: base64 of NUL user NUL pass (RFC 4616).
def Smtp.plain.resp(user: String, pass: String) -> String:
  M.B64.encode(0 <> List.append(&2, U32, M.Utf8.bytes(user),
    0 <> M.Utf8.bytes(pass)))

# AUTH PLAIN with its initial response.
def Smtp.plain(user: String, pass: String) -> String:
  "AUTH PLAIN " ++ Smtp.plain.resp(user, pass) ++ "\r\n"

# XOAUTH2's response (Google's and Microsoft's SASL XOAUTH2):
# "user=" user ^A "auth=Bearer " token ^A ^A, in base64.
def Smtp.xoauth2.resp(user: String, token: String) -> String:
  M.B64.text("user=" ++ user ++ Sasl.soh() ++ "auth=Bearer " ++ token ++ Sasl.soh()
    ++ Sasl.soh())

# A saslname (RFC 5801 5.1): "=" as "=3D" and "," as "=2C".
def Sasl.name(s: String) -> String:
  match s:
    case SNil{}:
      SNil{}
    case SCon{Chr{61}, t}:
      "=3D" ++ Sasl.name(t)
    case SCon{Chr{44}, t}:
      "=2C" ++ Sasl.name(t)
    case SCon{c, t}:
      SCon{c, Sasl.name(t)}

# OAUTHBEARER's response (RFC 7628 3.1): the GS2 header with the user,
# then host, port and the bearer token, ^A-separated, in base64.
def Smtp.bearer.resp(user: String, host: String, +port: U32, token: String) ->
  String:
  M.B64.text("n,a=" ++ Sasl.name(user) ++ "," ++ Sasl.soh() ++ "host=" ++ host
    ++ Sasl.soh() ++ "port=" ++ U32.show(port) ++ Sasl.soh() ++ "auth=Bearer "
    ++ token ++ Sasl.soh() ++ Sasl.soh())

# One AUTH LOGIN answer: the text in base64.
def Smtp.b64.line(s: String) -> String:
  M.B64.text(s) ++ "\r\n"

def Mech.has(ms: List<&2, String>, +w: String) -> Bool:
  match ms:
    case Nil{}:
      False{}
    case Con{x, t}:
      String.eq(x, w) || Mech.has(t, w)

def Mech.only(+ms: List<&2, String>, +w: String, m: Mech) -> Mech:
  Bool.pick(Mech, Mech.has(ms, w), m, MNo{"the server does not offer AUTH " ++ w})

# The mechanism for these options and these offers: the one asked for,
# if offered; else, for AAuto, XOAUTH2 or OAUTHBEARER with a token,
# PLAIN or LOGIN without.
def Mech.pick(a: Auth, oauth: Bool, +ms: List<&2, String>) -> Mech:
  match a:
    case APlain{}:
      Mech.only(ms, "PLAIN", MPlain{})
    case ALogin{}:
      Mech.only(ms, "LOGIN", MLogin{})
    case AXoauth2{}:
      Mech.only(ms, "XOAUTH2", MXoauth2{})
    case ABearer{}:
      Mech.only(ms, "OAUTHBEARER", MBearer{})
    case AAuto{}:
      Bool.pick(Mech, oauth,
        Bool.pick(Mech, Mech.has(ms, "XOAUTH2"), MXoauth2{},
        Bool.pick(Mech, Mech.has(ms, "OAUTHBEARER"), MBearer{},
          MNo{"the server offers no XOAUTH2 or OAUTHBEARER"})),
        Bool.pick(Mech, Mech.has(ms, "PLAIN"), MPlain{},
        Bool.pick(Mech, Mech.has(ms, "LOGIN"), MLogin{},
          MNo{"the server offers no AUTH PLAIN or LOGIN"})))

# Capabilities
# ------------

def Caps.size.of(m: Maybe<&2, U32>) -> U32:
  match m:
    case None{}:
      0
    case Some{n}:
      n

def Caps.size(yes: Bool, l: String, old: U32) -> U32:
  match yes:
    case True{}:
      Caps.size.of(U32.read(String.trim(String.drop(l, 4n))))
    case False{}:
      old

def Caps.mechs(auth: Bool, l: String, old: List<&2, String>) -> List<&2, String>:
  match auth:
    case True{}:
      List.append(&2, String, old, String.split(String.drop(l, 5n), ' '))
    case False{}:
      old

# One EHLO line, upper-cased, into the capabilities. "AUTH=" is the
# pre-standard spelling some servers still send.
def Caps.line(+l: String, c: Caps) -> Caps:
  Caps{tls, mechs, size, utf8, eight} = c
  Caps{tls || String.eq(l, "STARTTLS"),
    Caps.mechs(String.starts_with(l, "AUTH ") || String.starts_with(l, "AUTH="), l,
      mechs),
    Caps.size(String.starts_with(l, "SIZE"), l, size),
    utf8 || String.eq(l, "SMTPUTF8"), eight || String.eq(l, "8BITMIME")}

def Caps.lines(ls: List<&2, String>, c: Caps) -> Caps:
  match ls:
    case Nil{}:
      c
    case Con{l, t}:
      Caps.lines(t, Caps.line(String.to_upper(l), c))

# An EHLO reply's capabilities; its first line is the server's name.
def Caps.of(text: String) -> Caps:
  Caps.lines(List.drop(&2, String, String.split(text, '\n'), 1n), Caps.none())

# The message
# -----------

def Smtp.data.end(nl: Bool) -> String:
  match nl:
    case True{}:
      ".\r\n"
    case False{}:
      "\r\n.\r\n"

# What follows DATA, in one pass: bare LFs become CRLFs, bare CRs go, a
# line that starts with "." gets a second one (so no line reads as the
# end), and the end line follows, after a CRLF if the text lacks one.
# bol: at the start of a line; acc: the output so far, reversed (a tail
# call per char, where a nested one would cost a frame per char).
def Smtp.stuff(s: String, bol: Bool, acc: String) -> String:
  match s bol:
    case SNil{} _:
      T.Text.onto(acc, Smtp.data.end(bol))
    case SCon{Chr{46}, t} True{}:
      Smtp.stuff(t, False{}, SCon{'.', SCon{'.', acc}})
    case SCon{Chr{13}, t} _:
      Smtp.stuff(t, False{}, acc)
    case SCon{Chr{10}, t} _:
      Smtp.stuff(t, True{}, SCon{Chr{10}, SCon{Chr{13}, acc}})
    case SCon{c, t} _:
      Smtp.stuff(t, False{}, SCon{c, acc})

def Smtp.data(msg: String) -> String:
  Smtp.stuff(msg, True{}, SNil{})

def Hex.digit(+d: U32) -> Char:
  Chr{M.Word.pick((d < 10 : U32), (d + 48 : U32), (d + 87 : U32))}

def Hex.go(n: Nat, +x: U32, acc: String) -> String:
  match n:
    case 0n:
      acc
    case 1n+p:
      Hex.go(p, U32.shrn(x, 4n), SCon{Hex.digit(U32.and(x, 15)), acc})

# x as 8 hex digits.
def Hex.of(x: U32) -> String:
  Hex.go(8n, x, "")

# A list header, or nothing when the list is empty.
def Smtp.header(name: String, +ms: List<&2, A.Mbox>) -> String:
  Bool.pick(String, List.is_empty(&2, A.Mbox, ms), "",
    name ++ ": " ++ A.Mbox.shows(ms) ++ "\r\n")

# With only Bcc recipients, To names an empty group (RFC 5322 A.1.3).
def Smtp.nobody(+to: List<&2, A.Mbox>, +cc: List<&2, A.Mbox>) -> String:
  Bool.pick(String, List.is_empty(&2, A.Mbox, to) && List.is_empty(&2, A.Mbox, cc),
    "To: undisclosed-recipients:;\r\n", "")

# The message (RFC 5322): Date, From, To, Cc, Reply-To, Subject,
# Message-ID, MIME-Version, then the MIME entity. Bcc is never written.
# t is the time, id a unique string, b the boundary stem.
def Smtp.text(m: Mail, +t: U32, id: String, +b: String) -> String:
  Mail{+from, +to, +cc, _, +reply, subject, text, html, files} = m
  "Date: " ++ M.Date.fmt(t) ++ "\r\n"
    ++ "From: " ++ A.Mbox.show(from) ++ "\r\n"
    ++ Smtp.header("To", to) ++ Smtp.header("Cc", cc) ++ Smtp.nobody(to, cc)
    ++ Smtp.header("Reply-To", reply)
    ++ "Subject: " ++ M.Mime.subject(T.Text.clean(subject)) ++ "\r\n"
    ++ "Message-ID: <" ++ T.Text.clean(id) ++ "@"
    ++ T.Text.clean(A.Addr.domain(A.Mbox.addr(from))) ++ ">\r\n"
    ++ "MIME-Version: 1.0\r\n"
    ++ M.Mime.entity(text, html, files, b)

# Options
# -------

def Opts.host(o: Opts) -> String:
  Opts{h, _, _, _, _, _, _, _, _} = o
  h

def Opts.port(o: Opts) -> U32:
  Opts{_, p, _, _, _, _, _, _, _} = o
  p

def Opts.mode(o: Opts) -> Mode:
  Opts{_, _, m, _, _, _, _, _, _} = o
  m

def Opts.cafile(o: Opts) -> String:
  Opts{_, _, _, c, _, _, _, _, _} = o
  c

def Opts.helo(o: Opts) -> String:
  Opts{_, _, _, _, h, _, _, _, _} = o
  h

def Opts.user(o: Opts) -> String:
  Opts{_, _, _, _, _, u, _, _, _} = o
  u

def Opts.pass(o: Opts) -> String:
  Opts{_, _, _, _, _, _, p, _, _} = o
  p

def Opts.auth(o: Opts) -> Auth:
  Opts{_, _, _, _, _, _, _, a, _} = o
  a

def Opts.token(o: Opts) -> String:
  Opts{_, _, _, _, _, _, _, _, t} = o
  t

# IO
# --

# Timeouts in ms (RFC 5321 4.5.3.2): 5 min for the greeting, MAIL, RCPT
# and the rest; 2 min for DATA; 10 min for the end of the message.
def Smtp.wait() -> U32:
  300000

def Smtp.wait.data() -> U32:
  120000

def Smtp.wait.end() -> U32:
  600000

# Reads per reply before giving up (each waits up to its timeout).
def Smtp.fuel() -> Nat:
  64n

def Smtp.fail(code: U32, msg: String) -> Out():
  Fail{(code, msg)}

# The connection is broken: close it and report.
def Smtp.drop(s: Socket, code: U32, msg: String) -> IO(Out()):
  do IO<Out()>:
    N.Net.close(s)
    IO.pure(Out(), Smtp.fail(code, msg))

def Smtp.bye.got(m: Socket & Result<&1, &1, U32 & String, Maybe<&1, String>>,
  r: Out()) -> IO(Out()):
  (s, _) = m
  do IO<Out()>:
    N.Net.close(s)
    IO.pure(Out(), r)

def Smtp.bye.sent(m: Socket & Result<&1, &1, U32 & String, Unit>, r: Out()) ->
  IO(Out()):
  (s, _) = m
  do IO<Out()>:
    p : Socket & Result<&1, &1, U32 & String, Maybe<&1, String>> <-
      N.Net.poll(s, 4096, 10000)
    Smtp.bye.got(p, r)

# QUIT, a wait for the server's answer (up to 10 s), the close; then r,
# whatever the server said.
def Smtp.quit(s: Socket, r: Out()) -> IO(Out()):
  do IO<Out()>:
    m : Socket & Result<&1, &1, U32 & String, Unit> <- N.Net.send(s, "QUIT\r\n")
    Smtp.bye.sent(m, r)

# A poll's answer: more bytes on the buffer, or the end of the talk.
def Smtp.got(
  m: Socket & Result<&1, &1, U32 & String, Maybe<&1, String>>, buf: String,
  more: Socket -> String -> IO(Out())
) -> IO(Out()):
  (s, r) = m
  match r:
    case Fail{e}:
      (code, msg) = e
      Smtp.drop(s, code, "recv: " ++ msg)
    case Done{None{}}:
      Smtp.drop(s, 0, "timed out waiting for the server")
    case Done{Some{SNil{}}}:
      Smtp.drop(s, 0, "the server closed the connection")
    case Done{Some{SCon{h, t}}}:
      more(s, buf ++ SCon{h, t})

# The next reply: from the buffer if it holds one, else after a poll of
# up to ms.
def Smtp.read(
  fuel: Nat, sp: R.Split, s: Socket, +ms: U32,
  k: Socket -> String -> R.Reply -> IO(Out())
) -> IO(Out()):
  match fuel sp:
    case _ R.Got{r, rest}:
      k(s, rest, r)
    case 0n R.More{_}:
      Smtp.drop(s, 0, "no complete reply")
    case 1n+p R.More{buf}:
      do IO<Out()>:
        m : Socket & Result<&1, &1, U32 & String, Maybe<&1, String>> <-
          N.Net.poll(s, 4096, ms)
        Smtp.got(m, buf, s2 => b2 => Smtp.read(p, R.Reply.split(b2), s2, ms, k))

def Smtp.check(ok: Bool, r: R.Reply, s: Socket, buf: String,
  k: Socket -> String -> IO(Out())) -> IO(Out()):
  match ok:
    case True{}:
      k(s, buf)
    case False{}:
      R.Reply{code, text} = r
      Smtp.quit(s, Smtp.fail(code, text))

# Go on if the reply's class is the one wanted, else QUIT with it.
def Smtp.expect(+r: R.Reply, +want: U32, s: Socket, buf: String,
  k: Socket -> String -> IO(Out())) -> IO(Out()):
  Smtp.check(U32.is_eq(R.Reply.class(r), want), r, s, buf, k)

def Smtp.sent(m: Socket & Result<&1, &1, U32 & String, Unit>,
  k: Socket -> IO(Out())) -> IO(Out()):
  (s, r) = m
  match r:
    case Done{_}:
      k(s)
    case Fail{e}:
      (code, msg) = e
      Smtp.drop(s, code, "send: " ++ msg)

def Smtp.send(s: Socket, line: String, k: Socket -> IO(Out())) -> IO(Out()):
  do IO<Out()>:
    m : Socket & Result<&1, &1, U32 & String, Unit> <- N.Net.send(s, line)
    Smtp.sent(m, k)

# Send a line, read the reply (up to ms), go on if its class is `want`.
def Smtp.talk(s: Socket, buf: String, line: String, want: U32, ms: U32,
  k: Socket -> String -> IO(Out())) -> IO(Out()):
  Smtp.send(s, line, s2 => Smtp.read(Smtp.fuel(), R.Reply.split(buf), s2, ms,
    s3 => b3 => r => Smtp.expect(r, want, s3, b3, k)))

# Hello
# -----

def Smtp.helo.go(name: String, s: Socket, buf: String,
  next: Caps -> Socket -> String -> IO(Out())) -> IO(Out()):
  Smtp.talk(s, buf, Smtp.helo(name), 2, Smtp.wait(),
    s2 => b2 => next(Caps.none(), s2, b2))

# HELO takes a domain, never an address literal (RFC 5321 4.1.1.1): a
# literal EHLO name gives way to the host's own name.
def Smtp.helo.named(literal: Bool, name: String, s: Socket, buf: String,
  next: Caps -> Socket -> String -> IO(Out())) -> IO(Out()):
  match literal:
    case True{}:
      do IO<Out()>:
        host : String <- N.Net.hostname()
        Smtp.helo.go(host, s, buf, next)
    case False{}:
      Smtp.helo.go(name, s, buf, next)

def Smtp.hello.got(ok: Bool, old: Bool, r: R.Reply, s: Socket, buf: String,
  +name: String, next: Caps -> Socket -> String -> IO(Out())) -> IO(Out()):
  match ok old:
    case True{} _:
      R.Reply{_, text} = r
      next(Caps.of(text), s, buf)
    case False{} True{}:
      Smtp.helo.named(String.starts_with(name, "["), name, s, buf, next)
    case False{} False{}:
      R.Reply{code, text} = r
      Smtp.quit(s, Smtp.fail(code, "EHLO: " ++ text))

def Smtp.hello.named(m: Socket & String, buf: String,
  next: Caps -> Socket -> String -> IO(Out())) -> IO(Out()):
  (s, +name) = m
  Smtp.send(s, Smtp.ehlo(name), s2 => Smtp.read(Smtp.fuel(), R.Reply.split(buf),
    s2, Smtp.wait(), s3 => b3 => +r =>
      Smtp.hello.got(U32.is_eq(R.Reply.class(r), 2),
        U32.is_eq(R.Reply.class(r), 5), r, s3, b3, name, next)))

def Smtp.hello.name(ask: Bool, name: String, s: Socket) -> IO(Socket & String):
  match ask:
    case True{}:
      N.Net.helo(s)
    case False{}:
      IO.pure(Socket & String, (s, name))

# EHLO, or HELO when the server refuses EHLO with a 5xx (RFC 5321
# 3.2): then there are no extensions. next gets the capabilities.
def Smtp.hello(+o: Opts, s: Socket, buf: String,
  next: Caps -> Socket -> String -> IO(Out())) -> IO(Out()):
  +name = Opts.helo(o)
  do IO<Out()>:
    m : Socket & String <- Smtp.hello.name(String.is_empty(name), name, s)
    Smtp.hello.named(m, buf, next)

# Envelope and message
# --------------------

# A RCPT's reply: counted when taken; noted when refused, and the talk
# goes on; a 421 (the server is closing) ends it.
def Smtp.rcpt.got(ok: Bool, closing: Bool, +r: R.Reply, +a: String, s: Socket,
  buf: String, +n: U32, bad: List<&2, String>,
  k: Socket -> String -> U32 -> List<&2, String> -> IO(Out())) -> IO(Out()):
  match ok closing:
    case True{} _:
      k(s, buf, (n + 1 : U32), bad)
    case False{} True{}:
      R.Reply{code, text} = r
      Smtp.quit(s, Smtp.fail(code, text))
    case False{} False{}:
      R.Reply{code, text} = r
      k(s, buf, n, List.append(&2, String, bad,
        [a ++ " (" ++ U32.show(code) ++ " " ++ text ++ ")"]))

def Smtp.rcpts(to: List<&2, String>, s: Socket, buf: String, +n: U32,
  bad: List<&2, String>,
  k: Socket -> String -> U32 -> List<&2, String> -> IO(Out())) -> IO(Out()):
  match to:
    case Nil{}:
      k(s, buf, n, bad)
    case Con{+a, rest}:
      Smtp.send(s, Smtp.rcpt(a), s2 => Smtp.read(Smtp.fuel(), R.Reply.split(buf),
        s2, Smtp.wait(), s3 => b3 => +r => Smtp.rcpt.got(
          U32.is_eq(R.Reply.class(r), 2), U32.is_eq(R.Reply.code(r), 421), r, a,
          s3, b3, n, bad, s4 => b4 => n4 => bad4 =>
            Smtp.rcpts(rest, s4, b4, n4, bad4, k))))

def Smtp.octets.go(s: String, +n: U32) -> U32:
  match s:
    case SNil{}:
      n
    case SCon{Chr{+c}, t}:
      Smtp.octets.go(t, (n + U32.from_nat(M.Utf8.size(c)) : U32))

# The UTF-8 size of s, counted without building the bytes.
def Smtp.octets(s: String) -> U32:
  Smtp.octets.go(s, 0)

# With no recipient taken there is nothing to send: QUIT with the list.
def Smtp.body(none: Bool, +msg: String, bad: List<&2, String>, s: Socket,
  buf: String) -> IO(Out()):
  match none:
    case True{}:
      Smtp.quit(s, Smtp.fail(550, "every recipient was refused: "
        ++ String.join(bad, "; ")))
    case False{}:
      Smtp.talk(s, buf, "DATA\r\n", 3, Smtp.wait.data(),
        s2 => b2 => Smtp.talk(s2, b2, Smtp.data(msg), 2, Smtp.wait.end(),
          s3 => b3 => Smtp.quit(s3, Done{bad})))

def Smtp.deliver(+m: Mail, +msg: String, +c: Caps, s: Socket, buf: String) ->
  IO(Out()):
  Caps{_, _, +size, _, +eight} = c
  Smtp.talk(s, buf, Smtp.mail(Mail.from(m), size, Smtp.octets(msg), Mail.utf8(m),
    eight), 2, Smtp.wait(),
    s2 => b2 => Smtp.rcpts(Mail.rcpts(m), s2, b2, 0, Nil{},
      s3 => b3 => +n => bad => Smtp.body(U32.is_zero(n), msg, bad, s3, b3)))

def Smtp.sized(big: Bool, +m: Mail, +msg: String, +size: U32, +c: Caps,
  s: Socket, buf: String) -> IO(Out()):
  match big:
    case True{}:
      Smtp.quit(s, Smtp.fail(552, "the message has "
        ++ U32.show(Smtp.octets(msg)) ++ " bytes; the server takes at most "
        ++ U32.show(size)))
    case False{}:
      Smtp.deliver(m, msg, c, s, buf)

def Smtp.utf8.ok(lacking: Bool, +m: Mail, +msg: String, +c: Caps, s: Socket,
  buf: String) -> IO(Out()):
  match lacking:
    case True{}:
      Smtp.quit(s, Smtp.fail(553, "a non-ASCII address needs SMTPUTF8, which "
        ++ "the server does not offer"))
    case False{}:
      Caps{_, _, +size, _, _} = c
      Smtp.sized(Bool.not(U32.is_zero(size)) && (Smtp.octets(msg) > size : U32),
        m, msg, size, c, s, buf)

# MAIL (refused up front when SIZE says the message is too big, or when
# it needs SMTPUTF8 and the server lacks it), RCPT, DATA, the message.
def Smtp.envelope(+m: Mail, +msg: String, +c: Caps, s: Socket, buf: String) ->
  IO(Out()):
  Caps{_, _, _, +utf8, _} = c
  Smtp.utf8.ok(Mail.utf8(m) && Bool.not(utf8), m, msg, c, s, buf)

# AUTH
# ----

# What ends an exchange the server wants to go on with after the last
# response (a 334 carrying an error): an empty line for XOAUTH2, ^A for
# OAUTHBEARER (RFC 7628 3.2.3), "*" otherwise (RFC 4954 4).
def Sasl.cancel(+m: String) -> String:
  Bool.pick(String, String.eq(m, "XOAUTH2"), "\r\n",
    Bool.pick(String, String.eq(m, "OAUTHBEARER"), "AQ==\r\n", "*\r\n"))

def Smtp.sasl.end(m: Socket & Result<&1, &1, U32 & String, Maybe<&1, String>>,
  +why: String) -> IO(Out()):
  (s, _) = m
  do IO<Out()>:
    N.Net.close(s)
    IO.pure(Out(), Smtp.fail(535, why))

# The server's answer to the last response: 2xx goes on; a 334 is an
# error in base64 (OAuth's JSON), answered with the cancel line, then
# the 535; anything else is the failure itself.
def Smtp.sasl.got(ok: Bool, more: Bool, +r: R.Reply, +mech: String, s: Socket,
  buf: String, k: Socket -> String -> IO(Out())) -> IO(Out()):
  match ok more:
    case True{} _:
      k(s, buf)
    case False{} True{}:
      R.Reply{_, text} = r
      +why = "AUTH " ++ mech ++ " refused: " ++ M.B64.ascii(M.B64.decode(text))
      Smtp.send(s, Sasl.cancel(mech), s2 => Smtp.read(Smtp.fuel(),
        R.Reply.split(buf), s2, Smtp.wait(), s3 => b3 => r3 =>
          Smtp.quit(s3, Smtp.fail(R.Reply.code(r3), why))))
    case False{} False{}:
      R.Reply{code, text} = r
      Smtp.quit(s, Smtp.fail(code, "AUTH " ++ mech ++ ": " ++ text))

# Send the last response and read how it went.
def Smtp.sasl.last(s: Socket, buf: String, line: String, +mech: String,
  k: Socket -> String -> IO(Out())) -> IO(Out()):
  Smtp.send(s, line, s2 => Smtp.read(Smtp.fuel(), R.Reply.split(buf), s2,
    Smtp.wait(), s3 => b3 => +r => Smtp.sasl.got(U32.is_eq(R.Reply.class(r), 2),
      U32.is_eq(R.Reply.code(r), 334), r, mech, s3, b3, k)))

def Smtp.sasl.at(fits: Bool, line: String, +mech: String, resp: String,
  s: Socket, buf: String, k: Socket -> String -> IO(Out())) -> IO(Out()):
  match fits:
    case True{}:
      Smtp.sasl.last(s, buf, line, mech, k)
    case False{}:
      Smtp.talk(s, buf, "AUTH " ++ mech ++ "\r\n", 3, Smtp.wait(),
        s2 => b2 => Smtp.sasl.last(s2, b2, resp ++ "\r\n", mech, k))

# AUTH with an initial response; past 512 octets the response follows
# the server's 334 instead (RFC 4954 4, RFC 5321 4.5.3.1.4).
def Smtp.sasl(+mech: String, +resp: String, s: Socket, buf: String,
  k: Socket -> String -> IO(Out())) -> IO(Out()):
  +line = "AUTH " ++ mech ++ " " ++ resp ++ "\r\n"
  Smtp.sasl.at(Nat.is_le(String.length(line), 512n), line, mech, resp, s, buf, k)

def Smtp.auth.with(mech: Mech, +o: Opts, +m: Mail, +msg: String, +c: Caps,
  s: Socket, buf: String) -> IO(Out()):
  match mech:
    case MPlain{}:
      Smtp.sasl("PLAIN", Smtp.plain.resp(Opts.user(o), Opts.pass(o)), s, buf,
        s2 => b2 => Smtp.envelope(m, msg, c, s2, b2))
    case MXoauth2{}:
      Smtp.sasl("XOAUTH2", Smtp.xoauth2.resp(Opts.user(o), Opts.token(o)), s, buf,
        s2 => b2 => Smtp.envelope(m, msg, c, s2, b2))
    case MBearer{}:
      Smtp.sasl("OAUTHBEARER", Smtp.bearer.resp(Opts.user(o), Opts.host(o),
        Opts.port(o), Opts.token(o)), s, buf,
        s2 => b2 => Smtp.envelope(m, msg, c, s2, b2))
    case MLogin{}:
      Smtp.talk(s, buf, "AUTH LOGIN\r\n", 3, Smtp.wait(),
        s2 => b2 => Smtp.talk(s2, b2, Smtp.b64.line(Opts.user(o)), 3, Smtp.wait(),
          s3 => b3 => Smtp.sasl.last(s3, b3, Smtp.b64.line(Opts.pass(o)), "LOGIN",
            s4 => b4 => Smtp.envelope(m, msg, c, s4, b4))))
    case MNo{why}:
      Smtp.quit(s, Smtp.fail(0, why))

def Smtp.auth(none: Bool, secure: Bool, +o: Opts, +m: Mail, +msg: String,
  +c: Caps, s: Socket, buf: String) -> IO(Out()):
  match none secure:
    case True{} _:
      Smtp.envelope(m, msg, c, s, buf)
    case False{} False{}:
      Smtp.quit(s, Smtp.fail(0, "refusing to send credentials without TLS"))
    case False{} True{}:
      Caps{_, +mechs, _, _, _} = c
      Smtp.auth.with(Mech.pick(Opts.auth(o), Bool.not(String.is_empty(Opts.token(o))),
        mechs), o, m, msg, c, s, buf)

# AUTH when there is a user, and only over TLS (RFC 4954 4).
def Smtp.login(+o: Opts, +m: Mail, +msg: String, secure: Bool, +c: Caps,
  s: Socket, buf: String) -> IO(Out()):
  Smtp.auth(String.is_empty(Opts.user(o)), secure, o, m, msg, c, s, buf)

# TLS
# ---

def Smtp.tls.done(m: Socket & Result<&1, &1, U32 & String, Unit>,
  k: Socket -> IO(Out())) -> IO(Out()):
  (s, r) = m
  match r:
    case Done{_}:
      k(s)
    case Fail{e}:
      (code, msg) = e
      Smtp.drop(s, code, msg)

# The TLS handshake for the host, then k.
def Smtp.tls(+o: Opts, s: Socket, k: Socket -> IO(Out())) -> IO(Out()):
  do IO<Out()>:
    m : Socket & Result<&1, &1, U32 & String, Unit> <-
      N.Net.tls(s, Opts.host(o), Opts.cafile(o))
    Smtp.tls.done(m, k)

# After STARTTLS's 220, nothing may wait in the buffer: bytes sent
# before the handshake would be taken as sent under it (RFC 3207 4.2,
# the STARTTLS injection attack).
def Smtp.starttls(clean: Bool, +o: Opts, +m: Mail, +msg: String, s: Socket) ->
  IO(Out()):
  match clean:
    case True{}:
      Smtp.tls(o, s, s2 => Smtp.hello(o, s2, "",
        c => s3 => b3 => Smtp.login(o, m, msg, True{}, c, s3, b3)))
    case False{}:
      Smtp.drop(s, 0, "the server sent data after STARTTLS's reply")

def Smtp.upgrade(offered: Bool, +o: Opts, +m: Mail, +msg: String, s: Socket,
  buf: String) -> IO(Out()):
  match offered:
    case True{}:
      Smtp.talk(s, buf, "STARTTLS\r\n", 2, Smtp.wait(),
        s2 => +b2 => Smtp.starttls(String.is_empty(b2), o, m, msg, s2))
    case False{}:
      Smtp.quit(s, Smtp.fail(0, "the server does not offer STARTTLS"))

# After the first EHLO: STARTTLS and EHLO again in StartTls mode (with
# no fallback to plain text), then AUTH and the envelope.
def Smtp.secure(mode: Mode, +o: Opts, +m: Mail, +msg: String, +c: Caps,
  s: Socket, buf: String) -> IO(Out()):
  match mode:
    case Plain{}:
      Smtp.login(o, m, msg, False{}, c, s, buf)
    case Tls{}:
      Smtp.login(o, m, msg, True{}, c, s, buf)
    case StartTls{}:
      Caps{tls, _, _, _, _} = c
      Smtp.upgrade(tls, o, m, msg, s, buf)

# Connect
# -------

def Smtp.greet(+o: Opts, +m: Mail, +msg: String, s: Socket) -> IO(Out()):
  Smtp.read(Smtp.fuel(), R.Reply.split(""), s, Smtp.wait(), s1 => b1 => r =>
    Smtp.expect(r, 2, s1, b1, s2 => b2 => Smtp.hello(o, s2, b2,
      c => s3 => b3 => Smtp.secure(Opts.mode(o), o, m, msg, c, s3, b3))))

def Smtp.opened(mode: Mode, +o: Opts, +m: Mail, +msg: String, s: Socket) ->
  IO(Out()):
  match mode:
    case Tls{}:
      Smtp.tls(o, s, s2 => Smtp.greet(o, m, msg, s2))
    case _:
      Smtp.greet(o, m, msg, s)

def Smtp.connected(r: Result<&1, &1, U32 & String, Socket>, +o: Opts, +m: Mail,
  +msg: String) -> IO(Out()):
  match r:
    case Fail{e}:
      (code, err) = e
      IO.pure(Out(), Smtp.fail(code, "connect: " ++ err))
    case Done{s}:
      Smtp.opened(Opts.mode(o), o, m, msg, s)

def Smtp.go(+o: Opts, +m: Mail, +t: U32, +a: U32, b: U32, c: U32) -> IO(Out()):
  +msg = Smtp.text(m, t, Hex.of(t) ++ "." ++ Hex.of(a) ++ Hex.of(b),
    M.Mime.boundary(Hex.of(a) ++ Hex.of(c)))
  do IO<Out()>:
    r : Result<&1, &1, U32 & String, Socket> <- N.Net.connect(Opts.host(o),
      Opts.port(o))
    Smtp.connected(r, o, m, msg)

def Smtp.checked(problem: String, +o: Opts, +m: Mail) -> IO(Out()):
  match problem:
    case SNil{}:
      do IO<Out()>:
        t : U32 <- N.Net.time()
        a : U32 <- IO.try(U32, IO.random_u32())
        b : U32 <- IO.try(U32, IO.random_u32())
        c : U32 <- IO.try(U32, IO.random_u32())
        Smtp.go(o, m, t, a, b, c)
    case SCon{h, t}:
      IO.pure(Out(), Smtp.fail(0, SCon{h, t}))

# Send one message as o says.
def Smtp.send_mail(+o: Opts, +m: Mail) -> IO(Out()):
  Smtp.checked(Mail.problem(m), o, Mail.ascii(m))
