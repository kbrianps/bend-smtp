# The pure core of the SMTP client: the message, the options, the
# commands, what a server's EHLO means, the plan for a message, and the
# outcome. Nothing here does IO or calls foreign code, which is what
# lets LAWS.bend state laws about it and PROOF.bend prove them; smtp.bend
# is the dialog over the network, built on this.
import Base
import ./text.bend as T
import ./reply.bend as R
import ./mime.bend as M
import ./idna.bend as I
import ./addr.bend as A
import ./md5.bend as D

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

# Building blocks
# ---------------
#
# The short way to say where and what:
#
#   Smtp.send_mail(Opts.login(Opts.new("smtp.example.com"), "me@example.com", pass),
#     Mail.new("Me <me@example.com>", "Ana <ana@x.com>, b@y.com", "Hi", "text"))

# The usual submission: STARTTLS on port 587, the system's trust store,
# no AUTH yet.
def Opts.new(host: String) -> Opts:
  Opts{host, 587, StartTls{}, "", "", "", "", AAuto{}, "", False{}, Nil{}}

# o with this port and mode (Tls{} for implicit TLS on 465, Plain{} for
# none).
def Opts.via(o: Opts, port: U32, mode: Mode) -> Opts:
  Opts{host, _, _, cafile, helo, user, pass, auth, token, debug, more} = o
  Opts{host, port, mode, cafile, helo, user, pass, auth, token, debug, more}

# o with a user and password; the mechanism is picked from the server's
# offers.
def Opts.login(o: Opts, user: String, pass: String) -> Opts:
  Opts{host, port, mode, cafile, helo, _, _, auth, token, debug, more} = o
  Opts{host, port, mode, cafile, helo, user, pass, auth, token, debug, more}

# o with a user and an OAuth 2 access token (XOAUTH2 or OAUTHBEARER).
def Opts.oauth(o: Opts, user: String, token: String) -> Opts:
  Opts{host, port, mode, cafile, helo, _, pass, auth, _, debug, more} = o
  Opts{host, port, mode, cafile, helo, user, pass, auth, token, debug, more}

# o with a named option set (see Opts): Opts.with(o, "proxy", "socks5://...").
def Opts.with(o: Opts, key: String, val: String) -> Opts:
  Opts{host, port, mode, cafile, helo, user, pass, auth, token, debug, more} = o
  Opts{host, port, mode, cafile, helo, user, pass, auth, token, debug,
    List.append(&2, Kv, more, [Kv{key, val}])}

# A plain-text message; from is one mailbox and to a list, both as people
# write them ("Name <addr>", comma-separated).
def Mail.new(from: String, to: String, subject: String, text: String) -> Mail:
  Mail{A.Mbox.parse(from), A.Mbox.list(to), Nil{}, Nil{}, Nil{}, subject, text, "",
    Nil{}, Nil{}}

# m with an HTML alternative to its text.
def Mail.html(m: Mail, html: String) -> Mail:
  Mail{from, to, cc, bcc, reply, subject, text, _, files, headers} = m
  Mail{from, to, cc, bcc, reply, subject, text, html, files, headers}

# m with these Cc and Bcc lists (as people write them).
def Mail.copy(m: Mail, cc: String, bcc: String) -> Mail:
  Mail{from, to, _, _, reply, subject, text, html, files, headers} = m
  Mail{from, to, A.Mbox.list(cc), A.Mbox.list(bcc), reply, subject, text, html, files,
    headers}

# m with one more attachment: a file name, its bytes, and a type guessed
# from the name.
def Mail.attach(m: Mail, +name: String, data: List<&2, U32>) -> Mail:
  Mail{from, to, cc, bcc, reply, subject, text, html, files, headers} = m
  Mail{from, to, cc, bcc, reply, subject, text, html,
    List.append(&2, M.Part, files, [M.Part{name, M.Mime.ctype(name), data}]), headers}

# m with one more header field.
def Mail.header(m: Mail, name: String, value: String) -> Mail:
  Mail{from, to, cc, bcc, reply, subject, text, html, files, headers} = m
  Mail{from, to, cc, bcc, reply, subject, text, html, files,
    List.append(&2, Hdr, headers, [Hdr{name, value}])}

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

def Smtp.note(+r: R.Reply, a: String) -> String:
  a ++ " (" ++ U32.show(R.Reply.code(r)) ++ " " ++ R.Reply.text(r) ++ ")"

# AUTH
# ----

# What ends an exchange the server wants to go on with after the last
# response (a 334 carrying an error): an empty line for XOAUTH2, ^A for
# OAUTHBEARER (RFC 7628 3.2.3), "*" otherwise (RFC 4954 4).
def Sasl.cancel(+m: String) -> String:
  Bool.pick(String, String.eq(m, "XOAUTH2"), "\r\n",
    Bool.pick(String, String.eq(m, "OAUTHBEARER"), "AQ==\r\n", "*\r\n"))

# A proxy: its kind (0: SOCKS5, RFC 1928; 1: HTTP CONNECT, RFC 9110
# 9.3.6), host and port, and a user and password ("" for none); no host
# means no proxy.
type Proxy is Data:
  Proxy{kind: U32, host: String, port: U32, user: String, pass: String}

def Proxy.none() -> Proxy:
  Proxy{0, "", 0, "", ""}

def Proxy.port(m: Maybe<&2, U32>, dflt: U32) -> U32:
  match m:
    case None{}:
      dflt
    case Some{p}:
      p

# "host[:port]"; dflt: the port when absent.
def Proxy.host(hp: List<&2, String>, kind: U32, dflt: U32, user: String,
  pass: String) -> Proxy:
  match hp:
    case Con{h, Nil{}}:
      Proxy{kind, h, dflt, user, pass}
    case Con{h, Con{p, Nil{}}}:
      Proxy{kind, h, Proxy.port(U32.read(p), dflt), user, pass}
    case _:
      Proxy.none()

# "user[:pass]".
def Proxy.creds(up: List<&2, String>, hp: List<&2, String>, kind: U32,
  dflt: U32) -> Proxy:
  match up:
    case Con{u, Nil{}}:
      Proxy.host(hp, kind, dflt, u, "")
    case Con{u, Con{p, rest}}:
      Proxy.host(hp, kind, dflt, u, String.join(p <> rest, ":"))
    case _:
      Proxy.host(hp, kind, dflt, "", "")

# "[user[:pass]@]host[:port]"; the last "@" divides them.
def Proxy.parts(+ps: List<&2, String>, kind: U32, dflt: U32) -> Proxy:
  +n = Nat.sub(List.length(&2, String, ps), 1n)
  Proxy.creds(String.split(String.join(List.take(&2, String, ps, n), "@"), ':'),
    String.split(String.join(List.drop(&2, String, ps, n), "@"), ':'), kind, dflt)

def Proxy.rest(+rest: String, kind: U32, dflt: U32) -> Proxy:
  Bool.pick(Proxy, String.is_empty(rest), Proxy.none(),
    Proxy.parts(String.split(rest, '@'), kind, dflt))

# A proxy from "socks5://[user[:pass]@]host[:port]" (port 1080; also
# "socks5h://", the same here: the proxy always resolves the name) or
# "http://..." (port 8080); "" and anything else give none.
def Proxy.of(+url: String) -> Proxy:
  Bool.pick(Proxy, String.starts_with(url, "socks5://"),
    Proxy.rest(String.drop(url, 9n), 0, 1080),
  Bool.pick(Proxy, String.starts_with(url, "socks5h://"),
    Proxy.rest(String.drop(url, 10n), 0, 1080),
  Bool.pick(Proxy, String.starts_with(url, "http://"),
    Proxy.rest(String.drop(url, 7n), 1, 8080), Proxy.none())))

def Proxy.named(p: Proxy) -> Bool:
  Proxy{_, h, _, _, _} = p
  Bool.not(String.is_empty(h))

# A proxy that was asked for but cannot be read is an error: going on
# without it would connect directly, which is what it was there to avoid.
def Proxy.problem(+url: String) -> String:
  Bool.pick(String, String.is_empty(url) || Proxy.named(Proxy.of(url)), "",
    "bad proxy URL (socks5://[user:pass@]host[:port] or http://...): " ++ url)

def Smtp.job(+m: Mail, +t: U32, +a: U32, b: U32, c: U32) -> Job:
  Job{m, Smtp.text(m, t, Hex.of(t) ++ "." ++ Hex.of(a) ++ Hex.of(b),
    M.Mime.boundary(Hex.of(a) ++ Hex.of(c)))}

# The header form of "header[/body]" (c=, RFC 6376 3.5): relaxed unless
# it says simple.
def Canon.header(+c: String) -> Bool:
  Bool.not(String.starts_with(String.to_lower(c), "simple"))

# The body form: relaxed by default here; with only the header form
# given, simple, as the tag reads.
def Canon.body(+c: String) -> Bool:
  String.is_empty(c) || String.ends_with(String.to_lower(c), "/relaxed")

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
