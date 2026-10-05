# SMTP client (RFC 5321), with STARTTLS (RFC 3207), implicit TLS (RFC
# 8314), SIZE (RFC 1870), SMTPUTF8 (RFC 6531) and AUTH PLAIN, LOGIN,
# CRAM-MD5, XOAUTH2 and OAUTHBEARER (RFC 4954, 4616, 2195, 7628). One
# connection, then one transaction per message:
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
#   (MAIL again for the next message; RSET first if one stopped midway)
#   C: QUIT               S: 221
#
# A refusal before the first MAIL ends the talk with QUIT; one inside a
# message ends that message only. This file is the IO: it threads the
# socket and the read buffer through continuations. What to say, and
# what a reply means, is in core.bend (the message, the options, the
# commands, the plan), which is pure and is what the laws are about.
#
#   import ./core.bend as C
#   import ./smtp.bend as S
#   S.Smtp.send_mail(C.Opts.login(C.Opts.new("smtp.example.com"), user, pass),
#     C.Mail.new("Me <me@example.com>", "Ana <ana@x.com>", "Hi", "text"))
import Base
import ./text.bend as T
import ./reply.bend as R
import ./mime.bend as M
import ./net.bend as N
import ./idna.bend as I
import ./addr.bend as A
import ./md5.bend as D
import ./dkim.bend as Q
import ./core.bend as C

# The connection is broken: close it and report.
def Smtp.drop(s: Socket, code: U32, msg: String) -> IO(C.Out()):
  do IO<C.Out()>:
    N.Net.close(s)
    IO.pure(C.Out(), C.Smtp.fail(code, msg))

def Smtp.bye.got(m: Socket & Result<&1, &1, U32 & String, Maybe<&1, String>>,
  r: C.Out()) -> IO(C.Out()):
  (s, _) = m
  do IO<C.Out()>:
    N.Net.close(s)
    IO.pure(C.Out(), r)

def Smtp.bye.sent(m: Socket & Result<&1, &1, U32 & String, Unit>, r: C.Out()) ->
  IO(C.Out()):
  (s, _) = m
  do IO<C.Out()>:
    p : Socket & Result<&1, &1, U32 & String, Maybe<&1, String>> <-
      N.Net.poll(s, 4096, 10000)
    Smtp.bye.got(p, r)

# QUIT, a wait for the server's answer (up to 10 s), the close; then r,
# whatever the server said.
def Smtp.quit(s: Socket, r: C.Out()) -> IO(C.Out()):
  do IO<C.Out()>:
    m : Socket & Result<&1, &1, U32 & String, Unit> <- N.Net.send(s, "QUIT\r\n")
    Smtp.bye.sent(m, r)

# A poll's answer: more bytes on the buffer, or the end of the talk.
def Smtp.got(
  m: Socket & Result<&1, &1, U32 & String, Maybe<&1, String>>, buf: String,
  more: Socket -> String -> IO(C.Out())
) -> IO(C.Out()):
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
  k: Socket -> String -> R.Reply -> IO(C.Out())
) -> IO(C.Out()):
  match fuel sp:
    case _ R.Got{r, rest}:
      k(s, rest, r)
    case 0n R.More{_}:
      Smtp.drop(s, 0, "no complete reply")
    case 1n+p R.More{buf}:
      do IO<C.Out()>:
        m : Socket & Result<&1, &1, U32 & String, Maybe<&1, String>> <-
          N.Net.poll(s, 4096, ms)
        Smtp.got(m, buf, s2 => b2 => Smtp.read(p, R.Reply.split(b2), s2, ms, k))

def Smtp.check(ok: Bool, r: R.Reply, s: Socket, buf: String,
  k: Socket -> String -> IO(C.Out())) -> IO(C.Out()):
  match ok:
    case True{}:
      k(s, buf)
    case False{}:
      R.Reply{code, text} = r
      Smtp.quit(s, C.Smtp.fail(code, text))

# Go on if the reply's class is the one wanted, else QUIT with it.
def Smtp.expect(+r: R.Reply, +want: U32, s: Socket, buf: String,
  k: Socket -> String -> IO(C.Out())) -> IO(C.Out()):
  Smtp.check(U32.is_eq(R.Reply.class(r), want), r, s, buf, k)

def Smtp.sent(m: Socket & Result<&1, &1, U32 & String, Unit>,
  k: Socket -> IO(C.Out())) -> IO(C.Out()):
  (s, r) = m
  match r:
    case Done{_}:
      k(s)
    case Fail{e}:
      (code, msg) = e
      Smtp.drop(s, code, "send: " ++ msg)

def Smtp.send(s: Socket, line: String, k: Socket -> IO(C.Out())) -> IO(C.Out()):
  do IO<C.Out()>:
    m : Socket & Result<&1, &1, U32 & String, Unit> <- N.Net.send(s, line)
    Smtp.sent(m, k)

# Send a line, read the reply (up to ms), go on if its class is `want`.
def Smtp.talk(s: Socket, buf: String, line: String, want: U32, ms: U32,
  k: Socket -> String -> IO(C.Out())) -> IO(C.Out()):
  Smtp.send(s, line, s2 => Smtp.read(C.Smtp.fuel(), R.Reply.split(buf), s2, ms,
    s3 => b3 => r => Smtp.expect(r, want, s3, b3, k)))

# Hello
# -----

def Smtp.helo.go(name: String, s: Socket, buf: String,
  next: C.Caps -> Socket -> String -> IO(C.Out())) -> IO(C.Out()):
  Smtp.talk(s, buf, C.Smtp.helo(name), 2, C.Smtp.wait(),
    s2 => b2 => next(C.Caps.none(), s2, b2))

# HELO takes a domain, never an address literal (RFC 5321 4.1.1.1): a
# literal EHLO name gives way to the host's own name.
def Smtp.helo.named(literal: Bool, name: String, s: Socket, buf: String,
  next: C.Caps -> Socket -> String -> IO(C.Out())) -> IO(C.Out()):
  match literal:
    case True{}:
      do IO<C.Out()>:
        host : String <- N.Net.hostname()
        Smtp.helo.go(host, s, buf, next)
    case False{}:
      Smtp.helo.go(name, s, buf, next)

def Smtp.hello.got(ok: Bool, old: Bool, r: R.Reply, s: Socket, buf: String,
  +name: String, next: C.Caps -> Socket -> String -> IO(C.Out())) -> IO(C.Out()):
  match ok old:
    case True{} _:
      R.Reply{_, text} = r
      next(C.Caps.of(text), s, buf)
    case False{} True{}:
      Smtp.helo.named(String.starts_with(name, "["), name, s, buf, next)
    case False{} False{}:
      R.Reply{code, text} = r
      Smtp.quit(s, C.Smtp.fail(code, "EHLO: " ++ text))

def Smtp.hello.named(m: Socket & String, lmtp: Bool, buf: String,
  next: C.Caps -> Socket -> String -> IO(C.Out())) -> IO(C.Out()):
  (s, +name) = m
  Smtp.send(s, Bool.pick(String, lmtp, C.Smtp.lhlo(name), C.Smtp.ehlo(name)), s2 => Smtp.read(C.Smtp.fuel(), R.Reply.split(buf),
    s2, C.Smtp.wait(), s3 => b3 => +r =>
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
def Smtp.hello(+o: C.Opts, s: Socket, buf: String,
  next: C.Caps -> Socket -> String -> IO(C.Out())) -> IO(C.Out()):
  +name = C.Opts.helo(o)
  do IO<C.Out()>:
    m : Socket & String <- Smtp.hello.name(String.is_empty(name), name, s)
    Smtp.hello.named(m, C.Opts.on(o, "lmtp"), buf, next)

# Envelope and message
# --------------------

# Send a line and read its reply (up to ms), whatever it says.
def Smtp.ask(s: Socket, buf: String, line: String, ms: U32,
  k: Socket -> String -> R.Reply -> IO(C.Out())) -> IO(C.Out()):
  Smtp.send(s, line, s2 => Smtp.read(C.Smtp.fuel(), R.Reply.split(buf), s2, ms, k))

# A reply to a command: sent now, or already sent with the others.
def Smtp.ask2(piped: Bool, s: Socket, buf: String, line: String, ms: U32,
  k: Socket -> String -> R.Reply -> IO(C.Out())) -> IO(C.Out()):
  match piped:
    case True{}:
      Smtp.read(C.Smtp.fuel(), R.Reply.split(buf), s, ms, k)
    case False{}:
      Smtp.ask(s, buf, line, ms, k)

# A RCPT's reply: the address kept when taken; noted when refused, and
# the talk goes on; a 421 (the server is closing) ends it.
def Smtp.rcpt.got(ok: Bool, closing: Bool, +r: R.Reply, +a: String, s: Socket,
  buf: String, good: List<&2, String>, bad: List<&2, String>,
  k: Socket -> String -> List<&2, String> -> List<&2, String> -> IO(C.Out())) ->
  IO(C.Out()):
  match ok closing:
    case True{} _:
      k(s, buf, List.append(&2, String, good, [a]), bad)
    case False{} True{}:
      R.Reply{code, text} = r
      Smtp.quit(s, C.Smtp.fail(code, text))
    case False{} False{}:
      k(s, buf, good, List.append(&2, String, bad, [C.Smtp.note(r, a)]))

def Smtp.rcpts(to: List<&2, C.Rc>, +piped: Bool, s: Socket, buf: String,
  good: List<&2, String>, bad: List<&2, String>,
  k: Socket -> String -> List<&2, String> -> List<&2, String> -> IO(C.Out())) ->
  IO(C.Out()):
  match to:
    case Nil{}:
      k(s, buf, good, bad)
    case Con{rc, rest}:
      C.Rc{a, line} = rc
      Smtp.ask2(piped, s, buf, line, C.Smtp.wait(), s3 => b3 => +r => Smtp.rcpt.got(
        U32.is_eq(R.Reply.class(r), 2), U32.is_eq(R.Reply.code(r), 421), r, a,
        s3, b3, good, bad, s4 => b4 => g4 => bad4 =>
          Smtp.rcpts(rest, piped, s4, b4, g4, bad4, k)))

# A message stopped inside its transaction: RSET clears it (RFC 5321
# 4.1.1.5), so the next message starts clean; then on with x.
def Smtp.reset(s: Socket, buf: String, x: C.Sent,
  next: Socket -> String -> C.Sent -> IO(C.Out())) -> IO(C.Out()):
  Smtp.talk(s, buf, "RSET\r\n", 2, C.Smtp.wait(), s2 => b2 => next(s2, b2, x))

# The reply to the message itself: taken, or refused whole.
def Smtp.end.got(ok: Bool, closing: Bool, r: R.Reply, bad: List<&2, String>,
  s: Socket, buf: String, next: Socket -> String -> C.Sent -> IO(C.Out())) ->
  IO(C.Out()):
  match ok closing:
    case True{} _:
      next(s, buf, C.Sent{0, "", bad})
    case False{} True{}:
      R.Reply{code, text} = r
      Smtp.quit(s, C.Smtp.fail(code, text))
    case False{} False{}:
      R.Reply{code, text} = r
      next(s, buf, C.Sent{code, text, bad})

def Smtp.final.got(ok: Bool, +r: R.Reply, a: String, s: Socket, buf: String,
  +n: U32, bad: List<&2, String>,
  k: Socket -> String -> U32 -> List<&2, String> -> IO(C.Out())) -> IO(C.Out()):
  match ok:
    case True{}:
      k(s, buf, (n + 1 : U32), bad)
    case False{}:
      k(s, buf, n, List.append(&2, String, bad, [C.Smtp.note(r, a)]))

# LMTP answers the message once per recipient taken, in RCPT's order
# (RFC 2033 4.2); n counts the ones that got it.
def Smtp.finals(good: List<&2, String>, s: Socket, buf: String, +n: U32,
  bad: List<&2, String>,
  k: Socket -> String -> U32 -> List<&2, String> -> IO(C.Out())) -> IO(C.Out()):
  match good:
    case Nil{}:
      k(s, buf, n, bad)
    case Con{a, rest}:
      Smtp.read(C.Smtp.fuel(), R.Reply.split(buf), s, C.Smtp.wait.end(),
        s2 => b2 => +r => Smtp.final.got(U32.is_eq(R.Reply.class(r), 2), r, a, s2,
          b2, n, bad, s3 => b3 => n3 => bad3 => Smtp.finals(rest, s3, b3, n3, bad3, k)))

def Smtp.lmtp.end(none: Bool, bad: List<&2, String>, s: Socket, buf: String,
  next: Socket -> String -> C.Sent -> IO(C.Out())) -> IO(C.Out()):
  match none:
    case True{}:
      next(s, buf, C.Sent{550, "no recipient took the message", bad})
    case False{}:
      next(s, buf, C.Sent{0, "", bad})

# How the message went, once its bytes are out: one reply (SMTP), or
# one per recipient (LMTP).
def Smtp.outcome(lmtp: Bool, good: List<&2, String>, bad: List<&2, String>,
  s: Socket, buf: String, next: Socket -> String -> C.Sent -> IO(C.Out())) ->
  IO(C.Out()):
  match lmtp:
    case True{}:
      Smtp.finals(good, s, buf, 0, bad, s2 => b2 => +n => bad2 =>
        Smtp.lmtp.end(U32.is_zero(n), bad2, s2, b2, next))
    case False{}:
      Smtp.read(C.Smtp.fuel(), R.Reply.split(buf), s, C.Smtp.wait.end(),
        s2 => b2 => +r => Smtp.end.got(U32.is_eq(R.Reply.class(r), 2),
          U32.is_eq(R.Reply.code(r), 421), r, bad, s2, b2, next))

# The message's bytes, then its outcome.
def Smtp.put(text: String, lmtp: Bool, good: List<&2, String>,
  bad: List<&2, String>, s: Socket, buf: String,
  next: Socket -> String -> C.Sent -> IO(C.Out())) -> IO(C.Out()):
  Smtp.send(s, text, s2 => Smtp.outcome(lmtp, good, bad, s2, buf, next))

def Smtp.data.got(ok: Bool, closing: Bool, r: R.Reply, +p: C.Plan,
  good: List<&2, String>, bad: List<&2, String>, s: Socket, buf: String,
  next: Socket -> String -> C.Sent -> IO(C.Out())) -> IO(C.Out()):
  match ok closing:
    case True{} _:
      Smtp.put(C.Smtp.data(C.Plan.msg(p)), C.Plan.lmtp(p), good, bad, s, buf, next)
    case False{} True{}:
      R.Reply{code, text} = r
      Smtp.quit(s, C.Smtp.fail(code, text))
    case False{} False{}:
      R.Reply{code, text} = r
      Smtp.reset(s, buf, C.Sent{code, text, bad}, next)

def Smtp.undata.got(go: Bool, s: Socket, buf: String,
  k: Socket -> String -> IO(C.Out())) -> IO(C.Out()):
  match go:
    case True{}:
      Smtp.ask(s, buf, ".\r\n", C.Smtp.wait.end(), s2 => b2 => r => k(s2, b2))
    case False{}:
      k(s, buf)

# A piped DATA still to be answered, for a message that will not go: if
# the server says 354 anyway, an empty message ends it (RFC 2920 3.1).
def Smtp.undata(s: Socket, buf: String, k: Socket -> String -> IO(C.Out())) ->
  IO(C.Out()):
  Smtp.read(C.Smtp.fuel(), R.Reply.split(buf), s, C.Smtp.wait.data(),
    s2 => b2 => r => Smtp.undata.got(U32.is_eq(R.Reply.class(r), 3), s2, b2, k))

# The outcome of io with x kept: if the clean-up after a refused message
# loses the connection, the refusal is still the message's outcome.
def Smtp.kept(x: C.Sent, io: IO(C.Out())) -> IO(C.Out()):
  IO.bind(C.Out(), C.Out(), io, r => IO.pure(C.Out(), C.Batch.first(x, r)))

# The message will not go: clear what is pending, then on with x.
def Smtp.empty(pending: Bool, +x: C.Sent, s: Socket, buf: String,
  next: Socket -> String -> C.Sent -> IO(C.Out())) -> IO(C.Out()):
  match pending:
    case True{}:
      Smtp.kept(x, Smtp.undata(s, buf, s2 => b2 => Smtp.reset(s2, b2, x, next)))
    case False{}:
      Smtp.kept(x, Smtp.reset(s, buf, x, next))

# With no recipient taken there is nothing to send; else the message,
# after DATA's 354 or as a BDAT chunk.
def Smtp.body(none: Bool, bdat: Bool, +p: C.Plan, good: List<&2, String>,
  bad: List<&2, String>, s: Socket, buf: String,
  next: Socket -> String -> C.Sent -> IO(C.Out())) -> IO(C.Out()):
  match none bdat:
    case True{} _:
      Smtp.empty(C.Plan.piped(p) && Bool.not(C.Plan.bdat(p)),
        C.Sent{550, "every recipient was refused", bad}, s, buf, next)
    case False{} True{}:
      Smtp.put(C.Plan.chunk(p), C.Plan.lmtp(p), good, bad, s, buf, next)
    case False{} False{}:
      Smtp.ask2(C.Plan.piped(p), s, buf, "DATA\r\n", C.Smtp.wait.data(),
        s2 => b2 => +r => Smtp.data.got(U32.is_eq(R.Reply.class(r), 3),
          U32.is_eq(R.Reply.code(r), 421), r, p, good, bad, s2, b2, next))

# Replies to skip: the ones to commands piped after one that failed.
def Smtp.skip(n: List<&2, C.Rc>, s: Socket, buf: String,
  k: Socket -> String -> IO(C.Out())) -> IO(C.Out()):
  match n:
    case Nil{}:
      k(s, buf)
    case Con{_, rest}:
      Smtp.read(C.Smtp.fuel(), R.Reply.split(buf), s, C.Smtp.wait(),
        s2 => b2 => r => Smtp.skip(rest, s2, b2, k))

# MAIL was refused. Alone, that is all; piped, the RCPTs' and DATA's
# replies are still to come.
def Smtp.refused(piped: Bool, +p: C.Plan, +x: C.Sent, s: Socket, buf: String,
  next: Socket -> String -> C.Sent -> IO(C.Out())) -> IO(C.Out()):
  match piped:
    case True{}:
      Smtp.kept(x, Smtp.skip(C.Plan.rcpts(p), s, buf, s2 => b2 =>
        Smtp.empty(Bool.not(C.Plan.bdat(p)), x, s2, b2, next)))
    case False{}:
      next(s, buf, x)

# MAIL's reply: on to the recipients, or the message is refused here.
def Smtp.mail.got(ok: Bool, closing: Bool, r: R.Reply, +p: C.Plan, s: Socket,
  buf: String, next: Socket -> String -> C.Sent -> IO(C.Out())) -> IO(C.Out()):
  match ok closing:
    case True{} _:
      Smtp.rcpts(C.Plan.rcpts(p), C.Plan.piped(p), s, buf, Nil{}, Nil{},
        s3 => b3 => +good => bad => Smtp.body(List.is_empty(&2, String, good),
          C.Plan.bdat(p), p, good, bad, s3, b3, next))
    case False{} True{}:
      R.Reply{code, text} = r
      Smtp.quit(s, C.Smtp.fail(code, text))
    case False{} False{}:
      R.Reply{code, text} = r
      Smtp.refused(C.Plan.piped(p), p, C.Sent{code, text, Nil{}}, s, buf, next)

def Smtp.deliver(piped: Bool, +p: C.Plan, s: Socket, buf: String,
  next: Socket -> String -> C.Sent -> IO(C.Out())) -> IO(C.Out()):
  match piped:
    case True{}:
      Smtp.send(s, C.Plan.blob(p), s1 => Smtp.read(C.Smtp.fuel(), R.Reply.split(buf),
        s1, C.Smtp.wait(), s2 => b2 => +r => Smtp.mail.got(
          U32.is_eq(R.Reply.class(r), 2), U32.is_eq(R.Reply.code(r), 421), r, p,
          s2, b2, next)))
    case False{}:
      Smtp.ask(s, buf, C.Plan.mail(p), C.Smtp.wait(), s2 => b2 => +r => Smtp.mail.got(
        U32.is_eq(R.Reply.class(r), 2), U32.is_eq(R.Reply.code(r), 421), r, p, s2,
        b2, next))

def Smtp.sized(big: Bool, +p: C.Plan, +size: U32, s: Socket, buf: String,
  next: Socket -> String -> C.Sent -> IO(C.Out())) -> IO(C.Out()):
  match big:
    case True{}:
      next(s, buf, C.Sent{552, "the message has "
        ++ U32.show(C.Smtp.octets(C.Plan.msg(p))) ++ " bytes; the server takes at most "
        ++ U32.show(size), Nil{}})
    case False{}:
      Smtp.deliver(C.Plan.piped(p), p, s, buf, next)

def Smtp.utf8.ok(lacking: Bool, +p: C.Plan, +size: U32, s: Socket, buf: String,
  next: Socket -> String -> C.Sent -> IO(C.Out())) -> IO(C.Out()):
  match lacking:
    case True{}:
      next(s, buf, C.Sent{553, "a non-ASCII address needs SMTPUTF8, which the "
        ++ "server does not offer", Nil{}})
    case False{}:
      Smtp.sized(Bool.not(U32.is_zero(size))
        && (C.Smtp.octets(C.Plan.msg(p)) > size : U32), p, size, s, buf, next)

# One message: MAIL (not even tried when SIZE says it is too big, or when
# it needs SMTPUTF8 and the server lacks it), RCPT, DATA, the message.
# next gets how it went; only a broken or closing connection ends here.
def Smtp.one(+j: C.Job, +o: C.Opts, +c: C.Caps, s: Socket, buf: String,
  next: Socket -> String -> C.Sent -> IO(C.Out())) -> IO(C.Out()):
  C.Caps{_, _, +size, +utf8, _, _} = c
  Smtp.utf8.ok(C.Mail.utf8(C.Job.mail(j)) && Bool.not(utf8), C.Smtp.plan(o, c, j), size,
    s, buf, next)

def Smtp.more(x: C.Sent, rest: IO(C.Out())) -> IO(C.Out()):
  IO.bind(C.Out(), C.Out(), rest, r => IO.pure(C.Out(), C.Batch.add(x, r)))

# The messages, one transaction each on the same connection, then QUIT.
# Each one's outcome is put in front of what the rest returns, so an
# error later still reports the messages already sent.
def Smtp.batch(js: List<&2, C.Job>, +o: C.Opts, +c: C.Caps, s: Socket, buf: String) ->
  IO(C.Out()):
  match js:
    case Nil{}:
      Smtp.quit(s, C.Batch{Nil{}, 0, ""})
    case Con{j, rest}:
      Smtp.one(j, o, c, s, buf, s2 => b2 => x =>
        Smtp.more(x, Smtp.batch(rest, o, c, s2, b2)))

def Smtp.sasl.end(m: Socket & Result<&1, &1, U32 & String, Maybe<&1, String>>,
  +why: String) -> IO(C.Out()):
  (s, _) = m
  do IO<C.Out()>:
    N.Net.close(s)
    IO.pure(C.Out(), C.Smtp.fail(535, why))

# The server's answer to the last response: 2xx goes on; a 334 is an
# error in base64 (OAuth's JSON), answered with the cancel line, then
# the 535; anything else is the failure itself.
def Smtp.sasl.got(ok: Bool, more: Bool, +r: R.Reply, +mech: String, s: Socket,
  buf: String, k: Socket -> String -> IO(C.Out())) -> IO(C.Out()):
  match ok more:
    case True{} _:
      k(s, buf)
    case False{} True{}:
      R.Reply{_, text} = r
      +why = "AUTH " ++ mech ++ " refused: " ++ M.B64.ascii(M.B64.decode(text))
      Smtp.send(s, C.Sasl.cancel(mech), s2 => Smtp.read(C.Smtp.fuel(),
        R.Reply.split(buf), s2, C.Smtp.wait(), s3 => b3 => r3 =>
          Smtp.quit(s3, C.Smtp.fail(R.Reply.code(r3), why))))
    case False{} False{}:
      R.Reply{code, text} = r
      Smtp.quit(s, C.Smtp.fail(code, "AUTH " ++ mech ++ ": " ++ text))

# Send the last response and read how it went.
def Smtp.sasl.last(s: Socket, buf: String, line: String, +mech: String,
  k: Socket -> String -> IO(C.Out())) -> IO(C.Out()):
  Smtp.send(s, line, s2 => Smtp.read(C.Smtp.fuel(), R.Reply.split(buf), s2,
    C.Smtp.wait(), s3 => b3 => +r => Smtp.sasl.got(U32.is_eq(R.Reply.class(r), 2),
      U32.is_eq(R.Reply.code(r), 334), r, mech, s3, b3, k)))

def Smtp.sasl.at(fits: Bool, line: String, +mech: String, resp: String,
  s: Socket, buf: String, k: Socket -> String -> IO(C.Out())) -> IO(C.Out()):
  match fits:
    case True{}:
      Smtp.sasl.last(s, buf, line, mech, k)
    case False{}:
      Smtp.talk(s, buf, C.Cmd.line("AUTH " ++ mech), 3, C.Smtp.wait(),
        s2 => b2 => Smtp.sasl.last(s2, b2, C.Cmd.line(resp), mech, k))

# AUTH with an initial response; past 512 octets the response follows
# the server's 334 instead (RFC 4954 4, RFC 5321 4.5.3.1.4).
def Smtp.sasl(+mech: String, +resp: String, s: Socket, buf: String,
  k: Socket -> String -> IO(C.Out())) -> IO(C.Out()):
  +line = C.Cmd.line("AUTH " ++ mech ++ " " ++ resp)
  Smtp.sasl.at(Nat.is_le(String.length(line), 512n), line, mech, resp, s, buf, k)

# CRAM-MD5's challenge, answered (RFC 2195 2).
def Smtp.cram(ok: Bool, r: R.Reply, +o: C.Opts, s: Socket, buf: String,
  k: Socket -> String -> IO(C.Out())) -> IO(C.Out()):
  match ok:
    case True{}:
      Smtp.sasl.last(s, buf, C.Cmd.line(C.Smtp.cram.resp(C.Opts.user(o),
        C.Opts.pass(o), R.Reply.text(r))), "CRAM-MD5", k)
    case False{}:
      R.Reply{code, text} = r
      Smtp.quit(s, C.Smtp.fail(code, "AUTH CRAM-MD5: " ++ text))

def Smtp.auth.with(mech: C.Mech, +o: C.Opts, +js: List<&2, C.Job>, +c: C.Caps,
  s: Socket, buf: String) -> IO(C.Out()):
  match mech:
    case C.MPlain{}:
      Smtp.sasl("PLAIN", C.Smtp.plain.resp(C.Opts.user(o), C.Opts.pass(o)), s, buf,
        s2 => b2 => Smtp.batch(js, o, c, s2, b2))
    case C.MXoauth2{}:
      Smtp.sasl("XOAUTH2", C.Smtp.xoauth2.resp(C.Opts.user(o), C.Opts.token(o)), s, buf,
        s2 => b2 => Smtp.batch(js, o, c, s2, b2))
    case C.MBearer{}:
      Smtp.sasl("OAUTHBEARER", C.Smtp.bearer.resp(C.Opts.user(o), C.Opts.host(o),
        C.Opts.port(o), C.Opts.token(o)), s, buf,
        s2 => b2 => Smtp.batch(js, o, c, s2, b2))
    case C.MLogin{}:
      Smtp.talk(s, buf, "AUTH LOGIN\r\n", 3, C.Smtp.wait(),
        s2 => b2 => Smtp.talk(s2, b2, C.Smtp.b64.line(C.Opts.user(o)), 3, C.Smtp.wait(),
          s3 => b3 => Smtp.sasl.last(s3, b3, C.Smtp.b64.line(C.Opts.pass(o)), "LOGIN",
            s4 => b4 => Smtp.batch(js, o, c, s4, b4))))
    case C.MCram{}:
      Smtp.ask(s, buf, "AUTH CRAM-MD5\r\n", C.Smtp.wait(), s2 => b2 => +r =>
        Smtp.cram(U32.is_eq(R.Reply.code(r), 334), r, o, s2, b2,
          s3 => b3 => Smtp.batch(js, o, c, s3, b3)))
    case C.MNo{why}:
      Smtp.quit(s, C.Smtp.fail(0, why))

def Smtp.auth(none: Bool, secure: Bool, +o: C.Opts, +js: List<&2, C.Job>,
  +c: C.Caps, s: Socket, buf: String) -> IO(C.Out()):
  match none secure:
    case True{} _:
      Smtp.batch(js, o, c, s, buf)
    case False{} False{}:
      Smtp.quit(s, C.Smtp.fail(0, "refusing to send credentials without TLS"))
    case False{} True{}:
      C.Caps{_, +mechs, _, _, _, _} = c
      Smtp.auth.with(C.Mech.pick(C.Opts.auth(o), Bool.not(String.is_empty(C.Opts.token(o))),
        mechs), o, js, c, s, buf)

# AUTH when there is a user, and only over TLS (RFC 4954 4).
def Smtp.login(+o: C.Opts, +js: List<&2, C.Job>, secure: Bool, +c: C.Caps,
  s: Socket, buf: String) -> IO(C.Out()):
  Smtp.auth(String.is_empty(C.Opts.user(o)), secure, o, js, c, s, buf)

# TLS
# ---

def Smtp.tls.done(m: Socket & Result<&1, &1, U32 & String, Unit>,
  k: Socket -> IO(C.Out())) -> IO(C.Out()):
  (s, r) = m
  match r:
    case Done{_}:
      k(s)
    case Fail{e}:
      (code, msg) = e
      Smtp.drop(s, code, msg)

# The TLS handshake for the host, then k.
def Smtp.tls(+o: C.Opts, s: Socket, k: Socket -> IO(C.Out())) -> IO(C.Out()):
  do IO<C.Out()>:
    m : Socket & Result<&1, &1, U32 & String, Unit> <-
      N.Net.tls(s, C.Opts.host(o), C.Opts.cafile(o), C.Opts.opt(o, "cert"),
        C.Opts.opt(o, "key"))
    Smtp.tls.done(m, k)

# After STARTTLS's 220, nothing may wait in the buffer: bytes sent
# before the handshake would be taken as sent under it (RFC 3207 4.2,
# the STARTTLS injection attack).
def Smtp.starttls(clean: Bool, +o: C.Opts, +js: List<&2, C.Job>, s: Socket) ->
  IO(C.Out()):
  match clean:
    case True{}:
      Smtp.tls(o, s, s2 => Smtp.hello(o, s2, "",
        c => s3 => b3 => Smtp.login(o, js, True{}, c, s3, b3)))
    case False{}:
      Smtp.drop(s, 0, "the server sent data after STARTTLS's reply")

def Smtp.upgrade(offered: Bool, +o: C.Opts, +js: List<&2, C.Job>, s: Socket,
  buf: String) -> IO(C.Out()):
  match offered:
    case True{}:
      Smtp.talk(s, buf, "STARTTLS\r\n", 2, C.Smtp.wait(),
        s2 => +b2 => Smtp.starttls(String.is_empty(b2), o, js, s2))
    case False{}:
      Smtp.quit(s, C.Smtp.fail(0, "the server does not offer STARTTLS"))

# After the first EHLO: STARTTLS and EHLO again in StartTls mode (with
# no fallback to plain text), then AUTH and the envelope.
def Smtp.secure(mode: C.Mode, +o: C.Opts, +js: List<&2, C.Job>, +c: C.Caps,
  s: Socket, buf: String) -> IO(C.Out()):
  match mode:
    case C.Plain{}:
      Smtp.login(o, js, False{}, c, s, buf)
    case C.Tls{}:
      Smtp.login(o, js, True{}, c, s, buf)
    case C.StartTls{}:
      C.Caps{tls, _, _, _, _, _} = c
      Smtp.upgrade(tls, o, js, s, buf)

# Connect
# -------

def Smtp.greet(+o: C.Opts, +js: List<&2, C.Job>, s: Socket) -> IO(C.Out()):
  Smtp.read(C.Smtp.fuel(), R.Reply.split(""), s, C.Smtp.wait(), s1 => b1 => r =>
    Smtp.expect(r, 2, s1, b1, s2 => b2 => Smtp.hello(o, s2, b2,
      c => s3 => b3 => Smtp.secure(C.Opts.mode(o), o, js, c, s3, b3))))

def Smtp.opened(mode: C.Mode, +o: C.Opts, +js: List<&2, C.Job>, s: Socket) ->
  IO(C.Out()):
  match mode:
    case C.Tls{}:
      Smtp.tls(o, s, s2 => Smtp.greet(o, js, s2))
    case _:
      Smtp.greet(o, js, s)

def Smtp.connected(r: Result<&1, &1, U32 & String, Socket>, +o: C.Opts, +js: List<&2, C.Job>) -> IO(C.Out()):
  match r:
    case Fail{e}:
      (code, err) = e
      IO.pure(C.Out(), C.Smtp.fail(code, "connect: " ++ err))
    case Done{s}:
      Smtp.opened(C.Opts.mode(o), o, js, s)

def Smtp.dial.at(direct: Bool, kind: U32, ph: String, pp: U32, user: String,
  pass: String, host: String, port: U32) ->
  IO(Result<&1, &1, U32 & String, Socket>):
  match direct:
    case True{}:
      N.Net.connect(host, port)
    case False{}:
      N.Net.connect_via(ph, pp, user, pass, host, port, kind)

# The connection: direct, or through the proxy.
def Smtp.dial(p: C.Proxy, host: String, port: U32) ->
  IO(Result<&1, &1, U32 & String, Socket>):
  C.Proxy{kind, +ph, pp, user, pass} = p
  Smtp.dial.at(String.is_empty(ph), kind, ph, pp, user, pass, host, port)

# A signing step's result, or the end of the program (exit 1) with why.
def Smtp.must(r: Result<&1, &1, U32 & String, String>) -> IO(String):
  match r:
    case Done{v}:
      IO.pure(String, v)
    case Fail{e}:
      (_, msg) = e
      IO.die(String, 1, msg)

def Smtp.sign.end(+tags: String, +hr: Bool, +fs: List<&2, Q.Field>, key: String,
  m: C.Mail, msg: String) -> IO(C.Job):
  do IO<C.Job>:
    r : Result<&1, &1, U32 & String, String> <- N.Dkim.sign(key,
      Q.Dkim.data(hr, fs, tags))
    sig : String <- Smtp.must(r)
    IO.pure(C.Job, C.Job{m, Q.Dkim.header(tags, sig) ++ msg})

def Smtp.sign.cut(c: Q.Cut, +o: C.Opts, t: U32, m: C.Mail, msg: String) -> IO(C.Job):
  Q.Cut{head, body} = c
  +fs = Q.Dkim.fields(head)
  +canon = C.Opts.opt(o, "dkim-canon")
  do IO<C.Job>:
    ra : Result<&1, &1, U32 & String, String> <- N.Dkim.alg(C.Opts.opt(o, "dkim-key"))
    alg : String <- Smtp.must(ra)
    rb : Result<&1, &1, U32 & String, String> <- N.Dkim.sha256(
      Q.Dkim.body.of(C.Canon.body(canon), body))
    bh : String <- Smtp.must(rb)
    Smtp.sign.end(Q.Dkim.tags(alg, C.Canon.header(canon), C.Canon.body(canon),
      C.Opts.opt(o, "dkim-domain"), C.Opts.opt(o, "dkim-selector"), t, fs,
      Bool.pick(List<&2, String>, C.Opts.on(o, "dkim-no-oversign"), Nil{}, Q.Dkim.over()),
      bh), C.Canon.header(canon), fs, C.Opts.opt(o, "dkim-key"), m, msg)

# The message with its DKIM-Signature in front, when a key was given. A
# key that cannot be read or cannot sign ends the program: nothing goes
# out unsigned by accident.
def Smtp.sign(dkim: Bool, j: C.Job, +o: C.Opts, t: U32) -> IO(C.Job):
  match dkim:
    case False{}:
      IO.pure(C.Job, j)
    case True{}:
      C.Job{m, +msg} = j
      Smtp.sign.cut(Q.Dkim.cut(msg, ""), o, t, m, msg)

def Smtp.job.io(+o: C.Opts, m: C.Mail, +t: U32, a: U32, b: U32, c: U32) -> IO(C.Job):
  Smtp.sign(C.Opts.on(o, "dkim-key"), C.Smtp.job(m, t, a, b, c), o, t)

# Each message's text, with its own Date, Message-ID and boundary, and
# signed if asked.
def Smtp.jobs(ms: List<&2, C.Mail>, +o: C.Opts) -> IO(List<&2, C.Job>):
  match ms:
    case Nil{}:
      IO.pure(List<&2, C.Job>, Nil{})
    case Con{m, rest}:
      do IO<List<&2, C.Job>>:
        t : U32 <- N.Net.time()
        a : U32 <- IO.try(U32, IO.random_u32())
        b : U32 <- IO.try(U32, IO.random_u32())
        c : U32 <- IO.try(U32, IO.random_u32())
        j : C.Job <- Smtp.job.io(o, m, t, a, b, c)
        js : List<&2, C.Job> <- Smtp.jobs(rest, o)
        IO.pure(List<&2, C.Job>, j <> js)

def Smtp.go(+o: C.Opts, ms: List<&2, C.Mail>) -> IO(C.Out()):
  do IO<C.Out()>:
    N.Net.debug(Bool.pick(U32, C.Opts.debug(o), 1, 0))
    js : List<&2, C.Job> <- Smtp.jobs(ms, o)
    r : Result<&1, &1, U32 & String, Socket> <- Smtp.dial(
      C.Proxy.of(C.Opts.opt(o, "proxy")), C.Opts.host(o), C.Opts.port(o))
    Smtp.connected(r, o, js)

def Smtp.checked(problem: String, +o: C.Opts, ms: List<&2, C.Mail>) -> IO(C.Out()):
  match problem:
    case SNil{}:
      Smtp.go(o, ms)
    case SCon{h, t}:
      IO.pure(C.Out(), C.Smtp.fail(0, SCon{h, t}))

# Send the messages over one connection, as o says: one transaction
# each, in order. Nothing is sent if any of them is malformed.
def Smtp.send_many(+o: C.Opts, +ms: List<&2, C.Mail>) -> IO(C.Out()):
  +bad = C.Opts.problem(o)
  Smtp.checked(Bool.pick(String, Bool.not(String.is_empty(bad)), bad,
    Bool.pick(String, List.is_empty(&2, C.Mail, ms), "no messages",
      C.Smtp.problems(ms))), o, C.Smtp.asciis(ms))

# Send one message as o says.
def Smtp.send_mail(+o: C.Opts, m: C.Mail) -> IO(C.Out()):
  Smtp.send_many(o, [m])
