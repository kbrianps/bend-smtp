# SMTP client (RFC 5321), with STARTTLS (RFC 3207), implicit TLS (RFC
# 8314), SIZE (RFC 1870), SMTPUTF8 (RFC 6531) and AUTH PLAIN, LOGIN,
# XOAUTH2 and OAUTHBEARER (RFC 4954, 4616, 7628). One connection, then
# one transaction per message:
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
# message ends that message only. The pure part (commands,
# capabilities, mechanisms, the message) is what LAWS.bend pins; the IO
# part threads the socket and the read buffer through continuations.
import Base
import ./text.bend as T
import ./reply.bend as R
import ./mime.bend as M
import ./net.bend as N
import ./idna.bend as I
import ./addr.bend as A
import ./md5.bend as D
import ./dkim.bend as Q

# An extra header field, as "X-Mailer: bend-smtp".
type Hdr is Data:
  Hdr{name: String, value: String}

# A message: sender, To, Cc, Bcc (never in the headers), Reply-To,
# subject, plain text, HTML ("" for none), attachments and extra headers.
type Mail is Data:
  Mail{from: A.Mbox, to: List<&2, A.Mbox>, cc: List<&2, A.Mbox>,
    bcc: List<&2, A.Mbox>, reply: List<&2, A.Mbox>, subject: String,
    text: String, html: String, files: List<&2, M.Part>,
    headers: List<&2, Hdr>}

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
  ACram{}
  AXoauth2{}
  ABearer{}

# Where and how to send. cafile "" trusts the system's store; user ""
# sends no AUTH; helo "" asks the host (Net.helo); token is an OAuth 2
# access token ("" for none); debug writes the dialog to stderr, secrets
# and the message's text left out.
# more holds the rest by name (Opts.opt): "lmtp" (speak LMTP, RFC 2033),
# "notify", "ret" and "envid" (delivery status notifications, RFC 3461),
# "no-pipelining", "chunking" (send with BDAT, RFC 3030), "proxy"
# (socks5://[user:pass@]host:port), "cert" and "key" (a TLS client
# certificate), "dkim-domain", "dkim-selector" and "dkim-key".
type Kv is Data:
  Kv{key: String, val: String}

type Opts is Data:
  Opts{host: String, port: U32, mode: Mode, cafile: String, helo: String,
    user: String, pass: String, auth: Auth, token: String, debug: Bool,
    more: List<&2, Kv>}

# What EHLO announced: STARTTLS, the AUTH mechanisms, SIZE (0: none),
# SMTPUTF8, 8BITMIME, and every extension's keyword (upper-cased).
type Caps is Data:
  Caps{tls: Bool, mechs: List<&2, String>, size: U32, utf8: Bool, eight: Bool,
    exts: List<&2, String>}

# The mechanism to use, or why there is none.
type Mech is Data:
  MPlain{}
  MLogin{}
  MCram{}
  MXoauth2{}
  MBearer{}
  MNo{why: String}

# How one message went: code 0 when the server took it, else the reply
# (or the reason) that stopped it; refused lists the recipients the
# server did not take, the others having got it.
type Sent is Data:
  Sent{code: U32, error: String, refused: List<&2, String>}

# How a connection went: one Sent per message tried, in order, then the
# error that ended it early (code 0 and "" when none did). A message
# after the error was not tried.
type Batch is Data:
  Batch{sent: List<&2, Sent>, code: U32, error: String}

# A message and its text, ready to send.
type Job is Data:
  Job{mail: Mail, msg: String}

def Out() -> Type:
  Batch

def Batch.first.at(sent: List<&2, Sent>, x: Sent, code: U32, error: String) ->
  Batch:
  match sent:
    case Nil{}:
      Batch{[x], code, error}
    case Con{h, t}:
      Batch{h <> t, code, error}

# x as the first outcome when b has none: for a message already refused
# whose clean-up lost the connection, so the refusal is still reported.
def Batch.first(x: Sent, b: Batch) -> Batch:
  Batch{sent, code, error} = b
  Batch.first.at(sent, x, code, error)

def Batch.add(x: Sent, b: Batch) -> Batch:
  Batch{xs, code, error} = b
  Batch{x <> xs, code, error}

def Job.mail(j: Job) -> Mail:
  Job{m, _} = j
  m

def Job.msg(j: Job) -> String:
  Job{_, t} = j
  t

def Caps.none() -> Caps:
  Caps{False{}, Nil{}, 0, False{}, False{}, Nil{}}

# The message's addresses
# -----------------------

def Mail.from(m: Mail) -> String:
  Mail{f, _, _, _, _, _, _, _, _, _} = m
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
  Mail{_, to, cc, bcc, _, _, _, _, _, _} = m
  Smtp.uniq(List.append(&2, String, A.Mbox.addrs(to),
    List.append(&2, String, A.Mbox.addrs(cc), A.Mbox.addrs(bcc))), Nil{})

# Whether the message needs SMTPUTF8 (RFC 6531): some local part is not
# ASCII. A non-ASCII domain alone does not: it goes as A-labels.
def Mail.utf8(m: Mail) -> Bool:
  Mail{from, to, cc, bcc, reply, _, _, _, _, _} = m
  A.Addr.utf8(A.Mbox.addr(from)) || A.Mbox.any.utf8(to) || A.Mbox.any.utf8(cc)
    || A.Mbox.any.utf8(bcc) || A.Mbox.any.utf8(reply)

def Mail.ascii.at(utf8: Bool, m: Mail) -> Mail:
  match utf8:
    case True{}:
      m
    case False{}:
      Mail{from, to, cc, bcc, reply, subject, text, html, files, headers} = m
      Mail{A.Mbox.ascii(from), A.Mbox.asciis(to), A.Mbox.asciis(cc),
        A.Mbox.asciis(bcc), A.Mbox.asciis(reply), subject, text, html, files,
        headers}

# The addresses as they will travel: with A-label domains, unless the
# message needs SMTPUTF8, which carries them as written.
def Mail.ascii(+m: Mail) -> Mail:
  Mail.ascii.at(Mail.utf8(m), m)

def Mail.bad(+what: String, +a: String) -> String:
  Bool.pick(String, String.is_empty(a), "", "bad " ++ what ++ " address: " ++ a)

# What is wrong with a message's addresses, or "" if nothing.
# A header name (RFC 5322 2.2): printable ASCII with no space or ":".
def Hdr.name.ok(s: String) -> Bool:
  match s:
    case SNil{}:
      True{}
    case SCon{Chr{+c}, t}:
      (c >= 33 && c <= 126 : U32) && Bool.not(U32.is_eq(c, 58)) && Hdr.name.ok(t)

# The fields the client writes itself; an extra one would double them.
def Hdr.own() -> List<&2, String>:
  ["date", "from", "sender", "to", "cc", "bcc", "reply-to", "subject",
    "message-id", "mime-version", "content-type", "content-transfer-encoding",
    "content-disposition"]

def Hdr.ok(+n: String) -> Bool:
  Bool.not(String.is_empty(n)) && Hdr.name.ok(n)
    && Bool.not(List.contains(~String, ~String.eq, Hdr.own(), String.to_lower(n)))

# The first header that cannot go, or "".
def Hdr.bad(hs: List<&2, Hdr>) -> String:
  match hs:
    case Nil{}:
      ""
    case Con{h, t}:
      Hdr{+n, _} = h
      Bool.pick(String, Hdr.ok(n), Hdr.bad(t), Bool.pick(String, String.is_empty(n),
        "(no name)", n))

# What is wrong with a message's addresses and headers, or "".
def Mail.problem(+m: Mail) -> String:
  Mail{from, to, cc, bcc, reply, _, _, _, _, headers} = m
  +f = A.Mbox.addr(from)
  +b = A.Mbox.bad(to) ++ A.Mbox.bad(cc) ++ A.Mbox.bad(bcc)
  +h = Hdr.bad(headers)
  Bool.pick(String, Bool.not(A.Addr.ok(f)), "bad sender address: " ++ f,
  Bool.pick(String, List.is_empty(&2, String, Mail.rcpts(m)), "no recipients",
  Bool.pick(String, Bool.not(String.is_empty(b)), "bad recipient address: " ++ b,
  Bool.pick(String, Bool.not(String.is_empty(h)),
    "bad header (a malformed name, or one the client writes itself): " ++ h,
    Mail.bad("Reply-To", A.Mbox.bad(reply))))))

# Commands
# --------

def Smtp.ehlo(name: String) -> String:
  "EHLO " ++ T.Text.clean(name) ++ "\r\n"

# LMTP's greeting (RFC 2033 4.1).
def Smtp.lhlo(name: String) -> String:
  "LHLO " ++ T.Text.clean(name) ++ "\r\n"

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
# and SMTPUTF8 when the message needs it; more: further parameters.
def Smtp.mail(from: String, +size: U32, +len: U32, utf8: Bool, eight: Bool,
  more: String) -> String:
  "MAIL FROM:<" ++ T.Text.clean(from) ++ ">" ++ Smtp.size.param(size, len)
    ++ Smtp.utf8.param(utf8, eight) ++ more ++ "\r\n"

def Xtext.hex(+d: U32) -> Char:
  Chr{M.Word.pick((d < 10 : U32), (d + 48 : U32), (d + 55 : U32))}

def Xtext.put(plain: Bool, +b: U32, rest: String) -> String:
  match plain:
    case True{}:
      SCon{Chr{b}, rest}
    case False{}:
      SCon{'+', SCon{Xtext.hex(U32.shrn(b, 4n)), SCon{Xtext.hex(U32.and(b, 15)), rest}}}

def Xtext.bytes(bs: List<&2, U32>) -> String:
  match bs:
    case Nil{}:
      SNil{}
    case Con{+b, t}:
      Xtext.put((b >= 33 && b <= 126 : U32) && Bool.not(U32.is_eq(b, 43))
        && Bool.not(U32.is_eq(b, 61)), b, Xtext.bytes(t))

# xtext (RFC 3461 4): printable ASCII but "+" and "=" as it is, any
# other byte as "+" and two hex digits.
def Xtext.of(s: String) -> String:
  Xtext.bytes(M.Utf8.bytes(s))

# The DSN parameters of MAIL (RFC 3461 4.3, 4.4): RET and ENVID, each
# only when asked for.
def Dsn.mail(+ret: String, +envid: String) -> String:
  Bool.pick(String, String.is_empty(ret), "", " RET=" ++ String.to_upper(ret))
    ++ Bool.pick(String, String.is_empty(envid), "", " ENVID=" ++ Xtext.of(envid))

# The DSN parameters of RCPT (RFC 3461 4.1, 4.2): NOTIFY and the
# original recipient; a non-ASCII address gets no ORCPT (it would need
# RFC 6533's utf-8 form).
def Dsn.rcpt(+notify: String, +a: String) -> String:
  Bool.pick(String, String.is_empty(notify), "",
    " NOTIFY=" ++ String.to_upper(notify)
      ++ Bool.pick(String, I.Idna.ascii(a), " ORCPT=rfc822;" ++ Xtext.of(a), ""))

def Smtp.rcpt(to: String, more: String) -> String:
  "RCPT TO:<" ++ T.Text.clean(to) ++ ">" ++ more ++ "\r\n"

# CRAM-MD5's response (RFC 2195): the user, a space, and the HMAC-MD5 of
# the server's challenge keyed by the password, in hex; all in base64.
def Smtp.cram.resp(user: String, pass: String, challenge: String) -> String:
  M.B64.text(user ++ " " ++ D.Md5.hex(D.Md5.hmac(M.Utf8.bytes(pass),
    M.B64.decode(challenge))))

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
# and PLAIN, LOGIN or CRAM-MD5 (in this order, RFC 8314 4.1) without.
def Mech.pick(a: Auth, oauth: Bool, +ms: List<&2, String>) -> Mech:
  match a:
    case APlain{}:
      Mech.only(ms, "PLAIN", MPlain{})
    case ALogin{}:
      Mech.only(ms, "LOGIN", MLogin{})
    case ACram{}:
      Mech.only(ms, "CRAM-MD5", MCram{})
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
        Bool.pick(Mech, Mech.has(ms, "CRAM-MD5"), MCram{},
          MNo{"the server offers no AUTH PLAIN, LOGIN or CRAM-MD5"}))))

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
  Caps{tls, mechs, size, utf8, eight, exts} = c
  Caps{tls || String.eq(l, "STARTTLS"),
    Caps.mechs(String.starts_with(l, "AUTH ") || String.starts_with(l, "AUTH="), l,
      mechs),
    Caps.size(String.starts_with(l, "SIZE"), l, size),
    utf8 || String.eq(l, "SMTPUTF8"), eight || String.eq(l, "8BITMIME"),
    List.append(&2, String, exts, List.take(&2, String, String.split(l, ' '), 1n))}

def Caps.lines(ls: List<&2, String>, c: Caps) -> Caps:
  match ls:
    case Nil{}:
      c
    case Con{l, t}:
      Caps.lines(t, Caps.line(String.to_upper(l), c))

# Whether the server announced this extension (its keyword, upper-case).
def Caps.ext(c: Caps, w: String) -> Bool:
  Caps{_, _, _, _, _, exts} = c
  Mech.has(exts, w)

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

# An extra header's value: as written when it is printable ASCII (a
# structured value, like a URL in angle brackets, must not be encoded),
# else as RFC 2047 words.
def Hdr.value(+v: String) -> String:
  Bool.pick(String, M.Mime.printable(v), v, M.Mime.encoded(v))

def Hdr.shows(hs: List<&2, Hdr>) -> String:
  match hs:
    case Nil{}:
      SNil{}
    case Con{h, t}:
      Hdr{n, v} = h
      T.Text.clean(n) ++ ": " ++ Hdr.value(String.trim(T.Text.clean(v))) ++ "\r\n"
        ++ Hdr.shows(t)

# A list header, or nothing when the list is empty.
def Smtp.header(name: String, +ms: List<&2, A.Mbox>) -> String:
  Bool.pick(String, List.is_empty(&2, A.Mbox, ms), "",
    name ++ ": " ++ A.Mbox.shows(ms) ++ "\r\n")

# With only Bcc recipients, To names an empty group (RFC 5322 A.1.3).
def Smtp.nobody(+to: List<&2, A.Mbox>, +cc: List<&2, A.Mbox>) -> String:
  Bool.pick(String, List.is_empty(&2, A.Mbox, to) && List.is_empty(&2, A.Mbox, cc),
    "To: undisclosed-recipients:;\r\n", "")

# The message (RFC 5322): Date, From, To, Cc, Reply-To, Subject,
# Message-ID, the extra headers, MIME-Version, then the MIME entity. Bcc is never written.
# t is the time, id a unique string, b the boundary stem.
def Smtp.text(m: Mail, +t: U32, id: String, +b: String) -> String:
  Mail{+from, +to, +cc, _, +reply, subject, text, html, files, headers} = m
  "Date: " ++ M.Date.fmt(t) ++ "\r\n"
    ++ "From: " ++ A.Mbox.show(from) ++ "\r\n"
    ++ Smtp.header("To", to) ++ Smtp.header("Cc", cc) ++ Smtp.nobody(to, cc)
    ++ Smtp.header("Reply-To", reply)
    ++ "Subject: " ++ M.Mime.subject(T.Text.clean(subject)) ++ "\r\n"
    ++ "Message-ID: <" ++ T.Text.clean(id) ++ "@"
    ++ T.Text.clean(A.Addr.domain(A.Mbox.addr(from))) ++ ">\r\n"
    ++ Hdr.shows(headers)
    ++ "MIME-Version: 1.0\r\n"
    ++ M.Mime.entity(text, html, files, b)

# Options
# -------

def Opts.host(o: Opts) -> String:
  Opts{h, _, _, _, _, _, _, _, _, _, _} = o
  h

def Opts.port(o: Opts) -> U32:
  Opts{_, p, _, _, _, _, _, _, _, _, _} = o
  p

def Opts.mode(o: Opts) -> Mode:
  Opts{_, _, m, _, _, _, _, _, _, _, _} = o
  m

def Opts.cafile(o: Opts) -> String:
  Opts{_, _, _, c, _, _, _, _, _, _, _} = o
  c

def Opts.helo(o: Opts) -> String:
  Opts{_, _, _, _, h, _, _, _, _, _, _} = o
  h

def Opts.user(o: Opts) -> String:
  Opts{_, _, _, _, _, u, _, _, _, _, _} = o
  u

def Opts.pass(o: Opts) -> String:
  Opts{_, _, _, _, _, _, p, _, _, _, _} = o
  p

def Opts.auth(o: Opts) -> Auth:
  Opts{_, _, _, _, _, _, _, a, _, _, _} = o
  a

def Opts.token(o: Opts) -> String:
  Opts{_, _, _, _, _, _, _, _, t, _, _} = o
  t

def Opts.debug(o: Opts) -> Bool:
  Opts{_, _, _, _, _, _, _, _, _, d, _} = o
  d

def Kv.get(kvs: List<&2, Kv>, +k: String, found: String) -> String:
  match kvs:
    case Nil{}:
      found
    case Con{kv, t}:
      Kv{key, val} = kv
      Kv.get(t, k, Bool.pick(String, String.eq(key, k), val, found))

# A named option's value, or "".
def Opts.opt(o: Opts, k: String) -> String:
  Opts{_, _, _, _, _, _, _, _, _, _, more} = o
  Kv.get(more, k, "")

def Opts.on(o: Opts, k: String) -> Bool:
  Bool.not(String.is_empty(Opts.opt(o, k)))

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

# The connection ended early, with nothing more sent.
def Smtp.fail(code: U32, msg: String) -> Out():
  Batch{Nil{}, code, msg}

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

def Smtp.hello.named(m: Socket & String, lmtp: Bool, buf: String,
  next: Caps -> Socket -> String -> IO(Out())) -> IO(Out()):
  (s, +name) = m
  Smtp.send(s, Bool.pick(String, lmtp, Smtp.lhlo(name), Smtp.ehlo(name)), s2 => Smtp.read(Smtp.fuel(), R.Reply.split(buf),
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
    Smtp.hello.named(m, Opts.on(o, "lmtp"), buf, next)

# Envelope and message
# --------------------

# Send a line and read its reply (up to ms), whatever it says.
def Smtp.ask(s: Socket, buf: String, line: String, ms: U32,
  k: Socket -> String -> R.Reply -> IO(Out())) -> IO(Out()):
  Smtp.send(s, line, s2 => Smtp.read(Smtp.fuel(), R.Reply.split(buf), s2, ms, k))

def Smtp.octets.go(s: String, +n: U32) -> U32:
  match s:
    case SNil{}:
      n
    case SCon{Chr{+c}, t}:
      Smtp.octets.go(t, (n + U32.from_nat(M.Utf8.size(c)) : U32))

# The UTF-8 size of s, counted without building the bytes.
def Smtp.octets(s: String) -> U32:
  Smtp.octets.go(s, 0)

# A recipient and its RCPT line.
type Rc is Data:
  Rc{addr: String, line: String}

# How one message goes: with its commands sent together (PIPELINING,
# RFC 2920), with BDAT in place of DATA (CHUNKING, RFC 3030), with one
# final reply per recipient (LMTP, RFC 2033); the MAIL line, the
# recipients, the text.
type Plan is Data:
  Plan{piped: Bool, bdat: Bool, lmtp: Bool, mail: String, rcpts: List<&2, Rc>,
    msg: String}

def Plan.piped(p: Plan) -> Bool:
  Plan{x, _, _, _, _, _} = p
  x

def Plan.bdat(p: Plan) -> Bool:
  Plan{_, x, _, _, _, _} = p
  x

def Plan.lmtp(p: Plan) -> Bool:
  Plan{_, _, x, _, _, _} = p
  x

def Plan.mail(p: Plan) -> String:
  Plan{_, _, _, x, _, _} = p
  x

def Plan.rcpts(p: Plan) -> List<&2, Rc>:
  Plan{_, _, _, _, x, _} = p
  x

def Plan.msg(p: Plan) -> String:
  Plan{_, _, _, _, _, x} = p
  x

def Plan.rcs(to: List<&2, String>, +notify: String) -> List<&2, Rc>:
  match to:
    case Nil{}:
      Nil{}
    case Con{+a, t}:
      Rc{a, Smtp.rcpt(a, Dsn.rcpt(notify, a))} <> Plan.rcs(t, notify)

def Plan.lines(rs: List<&2, Rc>) -> String:
  match rs:
    case Nil{}:
      SNil{}
    case Con{r, t}:
      Rc{_, line} = r
      line ++ Plan.lines(t)

# Everything up to the message in one write: MAIL, every RCPT, and DATA
# unless BDAT follows.
def Plan.blob(+p: Plan) -> String:
  Plan.mail(p) ++ Plan.lines(Plan.rcpts(p))
    ++ Bool.pick(String, Plan.bdat(p), "", "DATA\r\n")

# The message as one last chunk (RFC 3030 2): its exact size, then its
# bytes, with no dot-stuffing and no end line.
def Plan.chunk(+p: Plan) -> String:
  "BDAT " ++ U32.show(Smtp.octets(Plan.msg(p))) ++ " LAST\r\n" ++ Plan.msg(p)

# The plan for a message, from what was asked and what the server
# offers: an extension is used only when announced, and the DSN
# parameters only with DSN.
def Smtp.plan(+o: Opts, +c: Caps, +j: Job) -> Plan:
  Caps{_, _, +size, _, +eight, _} = c
  +dsn = Caps.ext(c, "DSN")
  Plan{Caps.ext(c, "PIPELINING") && Bool.not(Opts.on(o, "no-pipelining")),
    Caps.ext(c, "CHUNKING") && Opts.on(o, "chunking"), Opts.on(o, "lmtp"),
    Smtp.mail(Mail.from(Job.mail(j)), size, Smtp.octets(Job.msg(j)),
      Mail.utf8(Job.mail(j)), eight,
      Bool.pick(String, dsn, Dsn.mail(Opts.opt(o, "ret"), Opts.opt(o, "envid")), "")),
    Plan.rcs(Mail.rcpts(Job.mail(j)), Bool.pick(String, dsn, Opts.opt(o, "notify"), "")),
    Job.msg(j)}

# A reply to a command: sent now, or already sent with the others.
def Smtp.ask2(piped: Bool, s: Socket, buf: String, line: String, ms: U32,
  k: Socket -> String -> R.Reply -> IO(Out())) -> IO(Out()):
  match piped:
    case True{}:
      Smtp.read(Smtp.fuel(), R.Reply.split(buf), s, ms, k)
    case False{}:
      Smtp.ask(s, buf, line, ms, k)

def Smtp.note(+r: R.Reply, a: String) -> String:
  a ++ " (" ++ U32.show(R.Reply.code(r)) ++ " " ++ R.Reply.text(r) ++ ")"

# A RCPT's reply: the address kept when taken; noted when refused, and
# the talk goes on; a 421 (the server is closing) ends it.
def Smtp.rcpt.got(ok: Bool, closing: Bool, +r: R.Reply, +a: String, s: Socket,
  buf: String, good: List<&2, String>, bad: List<&2, String>,
  k: Socket -> String -> List<&2, String> -> List<&2, String> -> IO(Out())) ->
  IO(Out()):
  match ok closing:
    case True{} _:
      k(s, buf, List.append(&2, String, good, [a]), bad)
    case False{} True{}:
      R.Reply{code, text} = r
      Smtp.quit(s, Smtp.fail(code, text))
    case False{} False{}:
      k(s, buf, good, List.append(&2, String, bad, [Smtp.note(r, a)]))

def Smtp.rcpts(to: List<&2, Rc>, +piped: Bool, s: Socket, buf: String,
  good: List<&2, String>, bad: List<&2, String>,
  k: Socket -> String -> List<&2, String> -> List<&2, String> -> IO(Out())) ->
  IO(Out()):
  match to:
    case Nil{}:
      k(s, buf, good, bad)
    case Con{rc, rest}:
      Rc{a, line} = rc
      Smtp.ask2(piped, s, buf, line, Smtp.wait(), s3 => b3 => +r => Smtp.rcpt.got(
        U32.is_eq(R.Reply.class(r), 2), U32.is_eq(R.Reply.code(r), 421), r, a,
        s3, b3, good, bad, s4 => b4 => g4 => bad4 =>
          Smtp.rcpts(rest, piped, s4, b4, g4, bad4, k)))

# A message stopped inside its transaction: RSET clears it (RFC 5321
# 4.1.1.5), so the next message starts clean; then on with x.
def Smtp.reset(s: Socket, buf: String, x: Sent,
  next: Socket -> String -> Sent -> IO(Out())) -> IO(Out()):
  Smtp.talk(s, buf, "RSET\r\n", 2, Smtp.wait(), s2 => b2 => next(s2, b2, x))

# The reply to the message itself: taken, or refused whole.
def Smtp.end.got(ok: Bool, closing: Bool, r: R.Reply, bad: List<&2, String>,
  s: Socket, buf: String, next: Socket -> String -> Sent -> IO(Out())) ->
  IO(Out()):
  match ok closing:
    case True{} _:
      next(s, buf, Sent{0, "", bad})
    case False{} True{}:
      R.Reply{code, text} = r
      Smtp.quit(s, Smtp.fail(code, text))
    case False{} False{}:
      R.Reply{code, text} = r
      next(s, buf, Sent{code, text, bad})

def Smtp.final.got(ok: Bool, +r: R.Reply, a: String, s: Socket, buf: String,
  +n: U32, bad: List<&2, String>,
  k: Socket -> String -> U32 -> List<&2, String> -> IO(Out())) -> IO(Out()):
  match ok:
    case True{}:
      k(s, buf, (n + 1 : U32), bad)
    case False{}:
      k(s, buf, n, List.append(&2, String, bad, [Smtp.note(r, a)]))

# LMTP answers the message once per recipient taken, in RCPT's order
# (RFC 2033 4.2); n counts the ones that got it.
def Smtp.finals(good: List<&2, String>, s: Socket, buf: String, +n: U32,
  bad: List<&2, String>,
  k: Socket -> String -> U32 -> List<&2, String> -> IO(Out())) -> IO(Out()):
  match good:
    case Nil{}:
      k(s, buf, n, bad)
    case Con{a, rest}:
      Smtp.read(Smtp.fuel(), R.Reply.split(buf), s, Smtp.wait.end(),
        s2 => b2 => +r => Smtp.final.got(U32.is_eq(R.Reply.class(r), 2), r, a, s2,
          b2, n, bad, s3 => b3 => n3 => bad3 => Smtp.finals(rest, s3, b3, n3, bad3, k)))

def Smtp.lmtp.end(none: Bool, bad: List<&2, String>, s: Socket, buf: String,
  next: Socket -> String -> Sent -> IO(Out())) -> IO(Out()):
  match none:
    case True{}:
      next(s, buf, Sent{550, "no recipient took the message", bad})
    case False{}:
      next(s, buf, Sent{0, "", bad})

# How the message went, once its bytes are out: one reply (SMTP), or
# one per recipient (LMTP).
def Smtp.outcome(lmtp: Bool, good: List<&2, String>, bad: List<&2, String>,
  s: Socket, buf: String, next: Socket -> String -> Sent -> IO(Out())) ->
  IO(Out()):
  match lmtp:
    case True{}:
      Smtp.finals(good, s, buf, 0, bad, s2 => b2 => +n => bad2 =>
        Smtp.lmtp.end(U32.is_zero(n), bad2, s2, b2, next))
    case False{}:
      Smtp.read(Smtp.fuel(), R.Reply.split(buf), s, Smtp.wait.end(),
        s2 => b2 => +r => Smtp.end.got(U32.is_eq(R.Reply.class(r), 2),
          U32.is_eq(R.Reply.code(r), 421), r, bad, s2, b2, next))

# The message's bytes, then its outcome.
def Smtp.put(text: String, lmtp: Bool, good: List<&2, String>,
  bad: List<&2, String>, s: Socket, buf: String,
  next: Socket -> String -> Sent -> IO(Out())) -> IO(Out()):
  Smtp.send(s, text, s2 => Smtp.outcome(lmtp, good, bad, s2, buf, next))

def Smtp.data.got(ok: Bool, closing: Bool, r: R.Reply, +p: Plan,
  good: List<&2, String>, bad: List<&2, String>, s: Socket, buf: String,
  next: Socket -> String -> Sent -> IO(Out())) -> IO(Out()):
  match ok closing:
    case True{} _:
      Smtp.put(Smtp.data(Plan.msg(p)), Plan.lmtp(p), good, bad, s, buf, next)
    case False{} True{}:
      R.Reply{code, text} = r
      Smtp.quit(s, Smtp.fail(code, text))
    case False{} False{}:
      R.Reply{code, text} = r
      Smtp.reset(s, buf, Sent{code, text, bad}, next)

def Smtp.undata.got(go: Bool, s: Socket, buf: String,
  k: Socket -> String -> IO(Out())) -> IO(Out()):
  match go:
    case True{}:
      Smtp.ask(s, buf, ".\r\n", Smtp.wait.end(), s2 => b2 => r => k(s2, b2))
    case False{}:
      k(s, buf)

# A piped DATA still to be answered, for a message that will not go: if
# the server says 354 anyway, an empty message ends it (RFC 2920 3.1).
def Smtp.undata(s: Socket, buf: String, k: Socket -> String -> IO(Out())) ->
  IO(Out()):
  Smtp.read(Smtp.fuel(), R.Reply.split(buf), s, Smtp.wait.data(),
    s2 => b2 => r => Smtp.undata.got(U32.is_eq(R.Reply.class(r), 3), s2, b2, k))

# The outcome of io with x kept: if the clean-up after a refused message
# loses the connection, the refusal is still the message's outcome.
def Smtp.kept(x: Sent, io: IO(Out())) -> IO(Out()):
  IO.bind(Out(), Out(), io, r => IO.pure(Out(), Batch.first(x, r)))

# The message will not go: clear what is pending, then on with x.
def Smtp.empty(pending: Bool, +x: Sent, s: Socket, buf: String,
  next: Socket -> String -> Sent -> IO(Out())) -> IO(Out()):
  match pending:
    case True{}:
      Smtp.kept(x, Smtp.undata(s, buf, s2 => b2 => Smtp.reset(s2, b2, x, next)))
    case False{}:
      Smtp.kept(x, Smtp.reset(s, buf, x, next))

# With no recipient taken there is nothing to send; else the message,
# after DATA's 354 or as a BDAT chunk.
def Smtp.body(none: Bool, bdat: Bool, +p: Plan, good: List<&2, String>,
  bad: List<&2, String>, s: Socket, buf: String,
  next: Socket -> String -> Sent -> IO(Out())) -> IO(Out()):
  match none bdat:
    case True{} _:
      Smtp.empty(Plan.piped(p) && Bool.not(Plan.bdat(p)),
        Sent{550, "every recipient was refused", bad}, s, buf, next)
    case False{} True{}:
      Smtp.put(Plan.chunk(p), Plan.lmtp(p), good, bad, s, buf, next)
    case False{} False{}:
      Smtp.ask2(Plan.piped(p), s, buf, "DATA\r\n", Smtp.wait.data(),
        s2 => b2 => +r => Smtp.data.got(U32.is_eq(R.Reply.class(r), 3),
          U32.is_eq(R.Reply.code(r), 421), r, p, good, bad, s2, b2, next))

# Replies to skip: the ones to commands piped after one that failed.
def Smtp.skip(n: List<&2, Rc>, s: Socket, buf: String,
  k: Socket -> String -> IO(Out())) -> IO(Out()):
  match n:
    case Nil{}:
      k(s, buf)
    case Con{_, rest}:
      Smtp.read(Smtp.fuel(), R.Reply.split(buf), s, Smtp.wait(),
        s2 => b2 => r => Smtp.skip(rest, s2, b2, k))

# MAIL was refused. Alone, that is all; piped, the RCPTs' and DATA's
# replies are still to come.
def Smtp.refused(piped: Bool, +p: Plan, +x: Sent, s: Socket, buf: String,
  next: Socket -> String -> Sent -> IO(Out())) -> IO(Out()):
  match piped:
    case True{}:
      Smtp.kept(x, Smtp.skip(Plan.rcpts(p), s, buf, s2 => b2 =>
        Smtp.empty(Bool.not(Plan.bdat(p)), x, s2, b2, next)))
    case False{}:
      next(s, buf, x)

# MAIL's reply: on to the recipients, or the message is refused here.
def Smtp.mail.got(ok: Bool, closing: Bool, r: R.Reply, +p: Plan, s: Socket,
  buf: String, next: Socket -> String -> Sent -> IO(Out())) -> IO(Out()):
  match ok closing:
    case True{} _:
      Smtp.rcpts(Plan.rcpts(p), Plan.piped(p), s, buf, Nil{}, Nil{},
        s3 => b3 => +good => bad => Smtp.body(List.is_empty(&2, String, good),
          Plan.bdat(p), p, good, bad, s3, b3, next))
    case False{} True{}:
      R.Reply{code, text} = r
      Smtp.quit(s, Smtp.fail(code, text))
    case False{} False{}:
      R.Reply{code, text} = r
      Smtp.refused(Plan.piped(p), p, Sent{code, text, Nil{}}, s, buf, next)

def Smtp.deliver(piped: Bool, +p: Plan, s: Socket, buf: String,
  next: Socket -> String -> Sent -> IO(Out())) -> IO(Out()):
  match piped:
    case True{}:
      Smtp.send(s, Plan.blob(p), s1 => Smtp.read(Smtp.fuel(), R.Reply.split(buf),
        s1, Smtp.wait(), s2 => b2 => +r => Smtp.mail.got(
          U32.is_eq(R.Reply.class(r), 2), U32.is_eq(R.Reply.code(r), 421), r, p,
          s2, b2, next)))
    case False{}:
      Smtp.ask(s, buf, Plan.mail(p), Smtp.wait(), s2 => b2 => +r => Smtp.mail.got(
        U32.is_eq(R.Reply.class(r), 2), U32.is_eq(R.Reply.code(r), 421), r, p, s2,
        b2, next))

def Smtp.sized(big: Bool, +p: Plan, +size: U32, s: Socket, buf: String,
  next: Socket -> String -> Sent -> IO(Out())) -> IO(Out()):
  match big:
    case True{}:
      next(s, buf, Sent{552, "the message has "
        ++ U32.show(Smtp.octets(Plan.msg(p))) ++ " bytes; the server takes at most "
        ++ U32.show(size), Nil{}})
    case False{}:
      Smtp.deliver(Plan.piped(p), p, s, buf, next)

def Smtp.utf8.ok(lacking: Bool, +p: Plan, +size: U32, s: Socket, buf: String,
  next: Socket -> String -> Sent -> IO(Out())) -> IO(Out()):
  match lacking:
    case True{}:
      next(s, buf, Sent{553, "a non-ASCII address needs SMTPUTF8, which the "
        ++ "server does not offer", Nil{}})
    case False{}:
      Smtp.sized(Bool.not(U32.is_zero(size))
        && (Smtp.octets(Plan.msg(p)) > size : U32), p, size, s, buf, next)

# One message: MAIL (not even tried when SIZE says it is too big, or when
# it needs SMTPUTF8 and the server lacks it), RCPT, DATA, the message.
# next gets how it went; only a broken or closing connection ends here.
def Smtp.one(+j: Job, +o: Opts, +c: Caps, s: Socket, buf: String,
  next: Socket -> String -> Sent -> IO(Out())) -> IO(Out()):
  Caps{_, _, +size, +utf8, _, _} = c
  Smtp.utf8.ok(Mail.utf8(Job.mail(j)) && Bool.not(utf8), Smtp.plan(o, c, j), size,
    s, buf, next)

def Smtp.more(x: Sent, rest: IO(Out())) -> IO(Out()):
  IO.bind(Out(), Out(), rest, r => IO.pure(Out(), Batch.add(x, r)))

# The messages, one transaction each on the same connection, then QUIT.
# Each one's outcome is put in front of what the rest returns, so an
# error later still reports the messages already sent.
def Smtp.batch(js: List<&2, Job>, +o: Opts, +c: Caps, s: Socket, buf: String) ->
  IO(Out()):
  match js:
    case Nil{}:
      Smtp.quit(s, Batch{Nil{}, 0, ""})
    case Con{j, rest}:
      Smtp.one(j, o, c, s, buf, s2 => b2 => x =>
        Smtp.more(x, Smtp.batch(rest, o, c, s2, b2)))

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

# CRAM-MD5's challenge, answered (RFC 2195 2).
def Smtp.cram(ok: Bool, r: R.Reply, +o: Opts, s: Socket, buf: String,
  k: Socket -> String -> IO(Out())) -> IO(Out()):
  match ok:
    case True{}:
      Smtp.sasl.last(s, buf, Smtp.cram.resp(Opts.user(o), Opts.pass(o),
        R.Reply.text(r)) ++ "\r\n", "CRAM-MD5", k)
    case False{}:
      R.Reply{code, text} = r
      Smtp.quit(s, Smtp.fail(code, "AUTH CRAM-MD5: " ++ text))

def Smtp.auth.with(mech: Mech, +o: Opts, +js: List<&2, Job>, +c: Caps,
  s: Socket, buf: String) -> IO(Out()):
  match mech:
    case MPlain{}:
      Smtp.sasl("PLAIN", Smtp.plain.resp(Opts.user(o), Opts.pass(o)), s, buf,
        s2 => b2 => Smtp.batch(js, o, c, s2, b2))
    case MXoauth2{}:
      Smtp.sasl("XOAUTH2", Smtp.xoauth2.resp(Opts.user(o), Opts.token(o)), s, buf,
        s2 => b2 => Smtp.batch(js, o, c, s2, b2))
    case MBearer{}:
      Smtp.sasl("OAUTHBEARER", Smtp.bearer.resp(Opts.user(o), Opts.host(o),
        Opts.port(o), Opts.token(o)), s, buf,
        s2 => b2 => Smtp.batch(js, o, c, s2, b2))
    case MLogin{}:
      Smtp.talk(s, buf, "AUTH LOGIN\r\n", 3, Smtp.wait(),
        s2 => b2 => Smtp.talk(s2, b2, Smtp.b64.line(Opts.user(o)), 3, Smtp.wait(),
          s3 => b3 => Smtp.sasl.last(s3, b3, Smtp.b64.line(Opts.pass(o)), "LOGIN",
            s4 => b4 => Smtp.batch(js, o, c, s4, b4))))
    case MCram{}:
      Smtp.ask(s, buf, "AUTH CRAM-MD5\r\n", Smtp.wait(), s2 => b2 => +r =>
        Smtp.cram(U32.is_eq(R.Reply.code(r), 334), r, o, s2, b2,
          s3 => b3 => Smtp.batch(js, o, c, s3, b3)))
    case MNo{why}:
      Smtp.quit(s, Smtp.fail(0, why))

def Smtp.auth(none: Bool, secure: Bool, +o: Opts, +js: List<&2, Job>,
  +c: Caps, s: Socket, buf: String) -> IO(Out()):
  match none secure:
    case True{} _:
      Smtp.batch(js, o, c, s, buf)
    case False{} False{}:
      Smtp.quit(s, Smtp.fail(0, "refusing to send credentials without TLS"))
    case False{} True{}:
      Caps{_, +mechs, _, _, _, _} = c
      Smtp.auth.with(Mech.pick(Opts.auth(o), Bool.not(String.is_empty(Opts.token(o))),
        mechs), o, js, c, s, buf)

# AUTH when there is a user, and only over TLS (RFC 4954 4).
def Smtp.login(+o: Opts, +js: List<&2, Job>, secure: Bool, +c: Caps,
  s: Socket, buf: String) -> IO(Out()):
  Smtp.auth(String.is_empty(Opts.user(o)), secure, o, js, c, s, buf)

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
      N.Net.tls(s, Opts.host(o), Opts.cafile(o), Opts.opt(o, "cert"),
        Opts.opt(o, "key"))
    Smtp.tls.done(m, k)

# After STARTTLS's 220, nothing may wait in the buffer: bytes sent
# before the handshake would be taken as sent under it (RFC 3207 4.2,
# the STARTTLS injection attack).
def Smtp.starttls(clean: Bool, +o: Opts, +js: List<&2, Job>, s: Socket) ->
  IO(Out()):
  match clean:
    case True{}:
      Smtp.tls(o, s, s2 => Smtp.hello(o, s2, "",
        c => s3 => b3 => Smtp.login(o, js, True{}, c, s3, b3)))
    case False{}:
      Smtp.drop(s, 0, "the server sent data after STARTTLS's reply")

def Smtp.upgrade(offered: Bool, +o: Opts, +js: List<&2, Job>, s: Socket,
  buf: String) -> IO(Out()):
  match offered:
    case True{}:
      Smtp.talk(s, buf, "STARTTLS\r\n", 2, Smtp.wait(),
        s2 => +b2 => Smtp.starttls(String.is_empty(b2), o, js, s2))
    case False{}:
      Smtp.quit(s, Smtp.fail(0, "the server does not offer STARTTLS"))

# After the first EHLO: STARTTLS and EHLO again in StartTls mode (with
# no fallback to plain text), then AUTH and the envelope.
def Smtp.secure(mode: Mode, +o: Opts, +js: List<&2, Job>, +c: Caps,
  s: Socket, buf: String) -> IO(Out()):
  match mode:
    case Plain{}:
      Smtp.login(o, js, False{}, c, s, buf)
    case Tls{}:
      Smtp.login(o, js, True{}, c, s, buf)
    case StartTls{}:
      Caps{tls, _, _, _, _, _} = c
      Smtp.upgrade(tls, o, js, s, buf)

# Connect
# -------

def Smtp.greet(+o: Opts, +js: List<&2, Job>, s: Socket) -> IO(Out()):
  Smtp.read(Smtp.fuel(), R.Reply.split(""), s, Smtp.wait(), s1 => b1 => r =>
    Smtp.expect(r, 2, s1, b1, s2 => b2 => Smtp.hello(o, s2, b2,
      c => s3 => b3 => Smtp.secure(Opts.mode(o), o, js, c, s3, b3))))

def Smtp.opened(mode: Mode, +o: Opts, +js: List<&2, Job>, s: Socket) ->
  IO(Out()):
  match mode:
    case Tls{}:
      Smtp.tls(o, s, s2 => Smtp.greet(o, js, s2))
    case _:
      Smtp.greet(o, js, s)

def Smtp.connected(r: Result<&1, &1, U32 & String, Socket>, +o: Opts, +js: List<&2, Job>) -> IO(Out()):
  match r:
    case Fail{e}:
      (code, err) = e
      IO.pure(Out(), Smtp.fail(code, "connect: " ++ err))
    case Done{s}:
      Smtp.opened(Opts.mode(o), o, js, s)

# A SOCKS5 proxy: its host and port, and a user and password ("" for
# none); no host means no proxy.
type Proxy is Data:
  Proxy{host: String, port: U32, user: String, pass: String}

def Proxy.port(m: Maybe<&2, U32>) -> U32:
  match m:
    case None{}:
      1080
    case Some{p}:
      p

# "host[:port]" (port 1080 when absent).
def Proxy.host(hp: List<&2, String>, user: String, pass: String) -> Proxy:
  match hp:
    case Con{h, Nil{}}:
      Proxy{h, 1080, user, pass}
    case Con{h, Con{p, Nil{}}}:
      Proxy{h, Proxy.port(U32.read(p)), user, pass}
    case _:
      Proxy{"", 0, "", ""}

# "user[:pass]".
def Proxy.creds(up: List<&2, String>, hp: List<&2, String>) -> Proxy:
  match up:
    case Con{u, Nil{}}:
      Proxy.host(hp, u, "")
    case Con{u, Con{p, rest}}:
      Proxy.host(hp, u, String.join(p <> rest, ":"))
    case _:
      Proxy.host(hp, "", "")

# "[user[:pass]@]host[:port]"; the last "@" divides them.
def Proxy.parts(+ps: List<&2, String>) -> Proxy:
  +n = Nat.sub(List.length(&2, String, ps), 1n)
  Proxy.creds(String.split(String.join(List.take(&2, String, ps, n), "@"), ':'),
    String.split(String.join(List.drop(&2, String, ps, n), "@"), ':'))

# A proxy from "socks5://[user[:pass]@]host[:port]" (also "socks5h://",
# the same here: the proxy always resolves the name); "" and anything
# else give none.
def Proxy.of(+url: String) -> Proxy:
  +rest = Bool.pick(String, String.starts_with(url, "socks5://"), String.drop(url, 9n),
    Bool.pick(String, String.starts_with(url, "socks5h://"), String.drop(url, 10n), ""))
  Bool.pick(Proxy, String.is_empty(rest), Proxy{"", 0, "", ""},
    Proxy.parts(String.split(rest, '@')))

def Smtp.dial.at(direct: Bool, ph: String, pp: U32, user: String, pass: String,
  host: String, port: U32) -> IO(Result<&1, &1, U32 & String, Socket>):
  match direct:
    case True{}:
      N.Net.connect(host, port)
    case False{}:
      N.Net.connect_via(ph, pp, user, pass, host, port)

# The connection: direct, or through the proxy.
def Smtp.dial(p: Proxy, host: String, port: U32) ->
  IO(Result<&1, &1, U32 & String, Socket>):
  Proxy{+ph, pp, user, pass} = p
  Smtp.dial.at(String.is_empty(ph), ph, pp, user, pass, host, port)

def Smtp.job(+m: Mail, +t: U32, +a: U32, b: U32, c: U32) -> Job:
  Job{m, Smtp.text(m, t, Hex.of(t) ++ "." ++ Hex.of(a) ++ Hex.of(b),
    M.Mime.boundary(Hex.of(a) ++ Hex.of(c)))}

# A signing step's result, or the end of the program (exit 1) with why.
def Smtp.must(r: Result<&1, &1, U32 & String, String>) -> IO(String):
  match r:
    case Done{v}:
      IO.pure(String, v)
    case Fail{e}:
      (_, msg) = e
      IO.die(String, 1, msg)

def Smtp.sign.end(+tags: String, +fs: List<&2, Q.Field>, key: String, m: Mail,
  msg: String) -> IO(Job):
  do IO<Job>:
    r : Result<&1, &1, U32 & String, String> <- Q.Dkim.sign(key, Q.Dkim.data(fs, tags))
    sig : String <- Smtp.must(r)
    IO.pure(Job, Job{m, Q.Dkim.header(tags, sig) ++ msg})

def Smtp.sign.cut(c: Q.Cut, +o: Opts, t: U32, m: Mail, msg: String) -> IO(Job):
  Q.Cut{head, body} = c
  +fs = Q.Dkim.fields(head)
  do IO<Job>:
    ra : Result<&1, &1, U32 & String, String> <- Q.Dkim.alg(Opts.opt(o, "dkim-key"))
    alg : String <- Smtp.must(ra)
    rb : Result<&1, &1, U32 & String, String> <- Q.Dkim.sha256(Q.Dkim.body(body,
      False{}, 0n, ""))
    bh : String <- Smtp.must(rb)
    Smtp.sign.end(Q.Dkim.tags(alg, Opts.opt(o, "dkim-domain"),
      Opts.opt(o, "dkim-selector"), t, fs, bh), fs, Opts.opt(o, "dkim-key"), m, msg)

# The message with its DKIM-Signature in front, when a key was given. A
# key that cannot be read or cannot sign ends the program: nothing goes
# out unsigned by accident.
def Smtp.sign(dkim: Bool, j: Job, +o: Opts, t: U32) -> IO(Job):
  match dkim:
    case False{}:
      IO.pure(Job, j)
    case True{}:
      Job{m, +msg} = j
      Smtp.sign.cut(Q.Dkim.cut(msg, ""), o, t, m, msg)

def Smtp.job.io(+o: Opts, m: Mail, +t: U32, a: U32, b: U32, c: U32) -> IO(Job):
  Smtp.sign(Opts.on(o, "dkim-key"), Smtp.job(m, t, a, b, c), o, t)

# Each message's text, with its own Date, Message-ID and boundary, and
# signed if asked.
def Smtp.jobs(ms: List<&2, Mail>, +o: Opts) -> IO(List<&2, Job>):
  match ms:
    case Nil{}:
      IO.pure(List<&2, Job>, Nil{})
    case Con{m, rest}:
      do IO<List<&2, Job>>:
        t : U32 <- N.Net.time()
        a : U32 <- IO.try(U32, IO.random_u32())
        b : U32 <- IO.try(U32, IO.random_u32())
        c : U32 <- IO.try(U32, IO.random_u32())
        j : Job <- Smtp.job.io(o, m, t, a, b, c)
        js : List<&2, Job> <- Smtp.jobs(rest, o)
        IO.pure(List<&2, Job>, j <> js)

def Smtp.go(+o: Opts, ms: List<&2, Mail>) -> IO(Out()):
  do IO<Out()>:
    N.Net.debug(Bool.pick(U32, Opts.debug(o), 1, 0))
    js : List<&2, Job> <- Smtp.jobs(ms, o)
    r : Result<&1, &1, U32 & String, Socket> <- Smtp.dial(
      Proxy.of(Opts.opt(o, "proxy")), Opts.host(o), Opts.port(o))
    Smtp.connected(r, o, js)

def Smtp.checked(problem: String, +o: Opts, ms: List<&2, Mail>) -> IO(Out()):
  match problem:
    case SNil{}:
      Smtp.go(o, ms)
    case SCon{h, t}:
      IO.pure(Out(), Smtp.fail(0, SCon{h, t}))

# The first message's problem, or "" (and "no messages" for none).
def Smtp.problems(ms: List<&2, Mail>) -> String:
  match ms:
    case Nil{}:
      ""
    case Con{+m, rest}:
      +p = Mail.problem(m)
      Bool.pick(String, String.is_empty(p), Smtp.problems(rest), p)

def Smtp.asciis(ms: List<&2, Mail>) -> List<&2, Mail>:
  match ms:
    case Nil{}:
      Nil{}
    case Con{m, rest}:
      Mail.ascii(m) <> Smtp.asciis(rest)

# Send the messages over one connection, as o says: one transaction
# each, in order. Nothing is sent if any of them is malformed.
def Smtp.send_many(+o: Opts, +ms: List<&2, Mail>) -> IO(Out()):
  Smtp.checked(Bool.pick(String, List.is_empty(&2, Mail, ms), "no messages",
    Smtp.problems(ms)), o, Smtp.asciis(ms))

# Send one message as o says.
def Smtp.send_mail(+o: Opts, m: Mail) -> IO(Out()):
  Smtp.send_many(o, [m])
