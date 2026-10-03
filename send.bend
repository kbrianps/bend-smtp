# Send mail over SMTP.
#
#   bend send.bend -o send
#   SMTP_PASSWORD=... ./send --host smtp.example.com --user me@example.com \
#     --from "Me <me@example.com>" --to "Ana <ana@x.com>, bia@y.com" \
#     --cc c@z.com --bcc d@w.com --subject "Oi" --body "texto" \
#     --html-file corpo.html --attach relatorio.pdf --attach foto.jpg \
#     --header "X-Campaign: outubro"
#
# Address lists take "Name <addr>" or "addr", comma-separated (quote a
# name with a comma: "\"Silva, Ana\" <ana@x.com>"). --attach and
# --header repeat. --individually sends one message per --to address,
# each seeing only itself, all over one connection. --debug prints the
# dialog on stderr, with secrets and the message's text left out.
# --tls starttls (default; port 587), tls (implicit; port 465) or plain
# (port 25); --port overrides. --auth plain, login, xoauth2 or
# oauthbearer (default: picked from what the server offers). Secrets
# come only from the environment: SMTP_PASSWORD, or SMTP_OAUTH_TOKEN (an
# OAuth 2 access token). --cafile trusts that CA instead of the
# system's; --helo names this host.
#
# Exit: 0 sent to everyone; 3 sent in part (a refused recipient, or some
# of the messages); 1 nothing sent; 2 bad usage.
import Base
import ./smtp.bend as S
import ./addr.bend as A
import ./mime.bend as M

# Arguments
# ---------

# An option and its value, as given.
type Opt is Data:
  Opt{key: String, val: String}

# The options that take a value, and the ones that stand alone.
def Args.valued() -> List<&2, String>:
  ["--host", "--port", "--tls", "--cafile", "--helo", "--user", "--auth",
    "--from", "--to", "--cc", "--bcc", "--reply-to", "--subject", "--body",
    "--body-file", "--html", "--html-file", "--attach", "--header", "--notify",
    "--ret", "--envid", "--proxy", "--cert", "--key", "--dkim-domain",
    "--dkim-selector", "--dkim-key"]

def Args.alone() -> List<&2, String>:
  ["--debug", "--individually", "--lmtp", "--no-pipelining", "--chunking"]

def Args.is(ks: List<&2, String>, k: String) -> Bool:
  List.contains(~String, ~String.eq, ks, k)

def Args.yes(add: Bool, rest: List<&2, String>) -> List<&2, String>:
  match add:
    case True{}:
      "yes" <> rest
    case False{}:
      rest

# The arguments with a "yes" after each option that stands alone, so
# they all come in pairs; val: this one is a value, not an option.
def Args.pair(xs: List<&2, String>, +val: Bool) -> List<&2, String>:
  match xs:
    case Nil{}:
      Nil{}
    case Con{+k, t}:
      +alone = Bool.not(val) && Args.is(Args.alone(), k)
      k <> Args.yes(alone, Args.pair(t, Bool.not(val) && Bool.not(alone)))

def Args.opts(xs: List<&2, String>) -> List<&2, Opt>:
  match xs:
    case Nil{}:
      Nil{}
    case Con{k, Nil{}}:
      [Opt{"?", k}]
    case Con{k, Con{v, rest}}:
      Opt{k, v} <> Args.opts(rest)

def Args.copy(xs: List<String>) -> List<&2, String>:
  match xs:
    case Nil{}:
      Nil{}
    case Con{x, rest}:
      x <> Args.copy(rest)

def Args.parse(xs: List<&2, String>) -> List<&2, Opt>:
  Args.opts(Args.pair(xs, False{}))

def Args.get.go(os: List<&2, Opt>, +k: String, found: String) -> String:
  match os:
    case Nil{}:
      found
    case Con{o, t}:
      Opt{key, val} = o
      Args.get.go(t, k, Bool.pick(String, String.eq(key, k), val, found))

# An option's value (the last one given), or "".
def Args.get(os: List<&2, Opt>, +k: String) -> String:
  Args.get.go(os, k, "")

def Args.keep(yes: Bool, v: String, rest: List<&2, String>) -> List<&2, String>:
  match yes:
    case True{}:
      v <> rest
    case False{}:
      rest

# Every value given for an option, in order.
def Args.all(os: List<&2, Opt>, +k: String) -> List<&2, String>:
  match os:
    case Nil{}:
      Nil{}
    case Con{o, t}:
      Opt{key, val} = o
      Args.keep(String.eq(key, k), val, Args.all(t, k))

def Args.on(os: List<&2, Opt>, k: String) -> Bool:
  Bool.not(String.is_empty(Args.get(os, k)))

# The first option that does not exist, or lacks its value; "" if none.
def Args.bad(os: List<&2, Opt>) -> String:
  match os:
    case Nil{}:
      ""
    case Con{o, t}:
      Opt{+key, val} = o
      Bool.pick(String, String.eq(key, "?"), "a value is missing after " ++ val,
      Bool.pick(String, Args.is(Args.valued(), key) || Args.is(Args.alone(), key),
        Args.bad(t), "unknown option " ++ key))

# Options
# -------

def Send.mode(+tls: String, +port: String) -> S.Mode:
  Bool.pick(S.Mode, String.eq(tls, "tls"), S.Tls{},
  Bool.pick(S.Mode, String.eq(tls, "plain"), S.Plain{},
  Bool.pick(S.Mode, String.eq(tls, "starttls"), S.StartTls{},
  Bool.pick(S.Mode, String.eq(port, "465"), S.Tls{}, S.StartTls{}))))

def Send.auth(+a: String) -> S.Auth:
  Bool.pick(S.Auth, String.eq(a, "plain"), S.APlain{},
  Bool.pick(S.Auth, String.eq(a, "login"), S.ALogin{},
  Bool.pick(S.Auth, String.eq(a, "cram-md5"), S.ACram{},
  Bool.pick(S.Auth, String.eq(a, "xoauth2"), S.AXoauth2{},
  Bool.pick(S.Auth, String.eq(a, "oauthbearer"), S.ABearer{}, S.AAuto{})))))

def Send.port.or(m: Maybe<&2, U32>, +dflt: U32) -> U32:
  match m:
    case None{}:
      dflt
    case Some{p}:
      p

def Send.port.dflt(mode: S.Mode) -> U32:
  match mode:
    case S.Tls{}:
      465
    case S.StartTls{}:
      587
    case S.Plain{}:
      25

def Send.both(+os: List<&2, Opt>, a: String, b: String) -> Bool:
  Args.on(os, a) && Args.on(os, b)

def Send.notify.words(ws: List<&2, String>) -> Bool:
  match ws:
    case Nil{}:
      True{}
    case Con{w, t}:
      Args.is(["", "never", "success", "failure", "delay"], w)
        && Send.notify.words(t)

# NOTIFY's values (RFC 3461 4.1): never alone, or any of the others.
def Send.notify.ok(+ws: List<&2, String>) -> Bool:
  Send.notify.words(ws) && Bool.not(Args.is(ws, "never")
    && Nat.is_lt(1n, List.length(&2, String, ws)))

def Send.some(+os: List<&2, Opt>, ks: List<&2, String>) -> Bool:
  match ks:
    case Nil{}:
      False{}
    case Con{k, t}:
      Args.on(os, k) || Send.some(os, t)

def Send.every(+os: List<&2, Opt>, ks: List<&2, String>) -> Bool:
  match ks:
    case Nil{}:
      True{}
    case Con{k, t}:
      Args.on(os, k) && Send.every(os, t)

# What is wrong with the options, or "".
def Send.problem(+os: List<&2, Opt>) -> String:
  +bad = Args.bad(os)
  +each = Args.on(os, "--individually")
  Bool.pick(String, Bool.not(String.is_empty(bad)), bad,
  Bool.pick(String, Bool.not(Args.on(os, "--host")), "--host is required",
  Bool.pick(String, Bool.not(Args.on(os, "--from")), "--from is required",
  Bool.pick(String, Bool.not(Args.on(os, "--to") || Args.on(os, "--cc")
    || Args.on(os, "--bcc")), "--to, --cc or --bcc is required",
  Bool.pick(String, each && Bool.not(Args.on(os, "--to")),
    "--individually needs --to",
  Bool.pick(String, each && (Args.on(os, "--cc") || Args.on(os, "--bcc")),
    "--individually sends to each --to alone: it takes no --cc or --bcc",
  Bool.pick(String, Bool.not(Args.is(["", "tls", "starttls", "plain"],
    Args.get(os, "--tls"))), "--tls takes starttls, tls or plain",
  Bool.pick(String, Bool.not(Args.is(["", "plain", "login", "cram-md5", "xoauth2",
    "oauthbearer"], Args.get(os, "--auth"))),
    "--auth takes plain, login, cram-md5, xoauth2 or oauthbearer",
  Bool.pick(String, Bool.not(Send.notify.ok(String.split(String.to_lower(
    Args.get(os, "--notify")), ','))),
    "--notify takes never, or success, failure and delay, comma-separated",
  Bool.pick(String, Bool.not(Args.is(["", "full", "hdrs"],
    String.to_lower(Args.get(os, "--ret")))), "--ret takes full or hdrs",
  Bool.pick(String, Bool.not(String.is_empty(Args.get(os, "--cert")))
    && String.is_empty(Args.get(os, "--key"))
    || String.is_empty(Args.get(os, "--cert"))
    && Bool.not(String.is_empty(Args.get(os, "--key"))),
    "--cert and --key go together",
  Bool.pick(String, Send.some(os, ["--dkim-domain", "--dkim-selector", "--dkim-key"])
    && Bool.not(Send.every(os, ["--dkim-domain", "--dkim-selector", "--dkim-key"])),
    "--dkim-domain, --dkim-selector and --dkim-key go together",
  Bool.pick(String, Send.both(os, "--body", "--body-file"),
    "--body and --body-file exclude each other",
  Bool.pick(String, Send.both(os, "--html", "--html-file"),
    "--html and --html-file exclude each other", ""))))))))))))))

# The named options of S.Opts, from the flags of the same names.
def Send.more(+os: List<&2, Opt>, ks: List<&2, String>) -> List<&2, S.Kv>:
  match ks:
    case Nil{}:
      Nil{}
    case Con{+k, t}:
      S.Kv{k, Args.get(os, "--" ++ k)} <> Send.more(os, t)

def Send.opts(+os: List<&2, Opt>, pass: String, token: String) -> S.Opts:
  +port = Args.get(os, "--port")
  +mode = Send.mode(Args.get(os, "--tls"), port)
  S.Opts{Args.get(os, "--host"),
    Send.port.or(U32.read(port), Send.port.dflt(mode)), mode,
    Args.get(os, "--cafile"), Args.get(os, "--helo"), Args.get(os, "--user"), pass,
    Send.auth(Args.get(os, "--auth")), token, Args.on(os, "--debug"),
    Send.more(os, ["lmtp", "notify", "ret", "envid", "no-pipelining", "chunking",
      "proxy", "cert", "key", "dkim-domain", "dkim-selector", "dkim-key"])}

# "Name: value" as a header; a line with no ":" has no name, and is
# refused later.
def Send.header.of(parts: List<&2, String>) -> S.Hdr:
  match parts:
    case Con{n, Con{v, rest}}:
      S.Hdr{String.trim(n), String.trim(String.join(v <> rest, ":"))}
    case _:
      S.Hdr{"", ""}

def Send.headers(hs: List<&2, String>) -> List<&2, S.Hdr>:
  match hs:
    case Nil{}:
      Nil{}
    case Con{h, t}:
      Send.header.of(String.split(h, ':')) <> Send.headers(t)

# The message as the options describe it.
def Send.mail(+os: List<&2, Opt>, text: String, html: String,
  files: List<&2, M.Part>) -> S.Mail:
  S.Mail{A.Mbox.parse(Args.get(os, "--from")), A.Mbox.list(Args.get(os, "--to")),
    A.Mbox.list(Args.get(os, "--cc")), A.Mbox.list(Args.get(os, "--bcc")),
    A.Mbox.list(Args.get(os, "--reply-to")), Args.get(os, "--subject"), text, html,
    files, Send.headers(Args.all(os, "--header"))}

# m with t as its only To.
def Send.only(m: S.Mail, t: A.Mbox) -> S.Mail:
  S.Mail{from, _, cc, bcc, reply, subject, text, html, files, headers} = m
  S.Mail{from, [t], cc, bcc, reply, subject, text, html, files, headers}

def Send.alone(+m: S.Mail, to: List<&2, A.Mbox>) -> List<&2, S.Mail>:
  match to:
    case Nil{}:
      Nil{}
    case Con{t, rest}:
      Send.only(m, t) <> Send.alone(m, rest)

def Send.to(m: S.Mail) -> List<&2, A.Mbox>:
  S.Mail{_, to, _, _, _, _, _, _, _, _} = m
  to

def Send.mails.at(each: Bool, +m: S.Mail) -> List<&2, S.Mail>:
  match each:
    case True{}:
      Send.alone(m, Send.to(m))
    case False{}:
      [m]

# The messages to send: the one described, or, with --individually, a
# copy of it for each --to address.
def Send.mails(+os: List<&2, Opt>, m: S.Mail) -> List<&2, S.Mail>:
  Send.mails.at(Args.on(os, "--individually"), m)

# What is missing for AUTH, or "": a password for PLAIN and LOGIN, a
# token for the OAuth mechanisms, one of the two otherwise.
def Send.creds(+user: String, +auth: String, +pass: String, +token: String) ->
  String:
  +oauth = String.eq(auth, "xoauth2") || String.eq(auth, "oauthbearer")
  +basic = String.eq(auth, "plain") || String.eq(auth, "login")
    || String.eq(auth, "cram-md5")
  Bool.pick(String, String.is_empty(user), "",
  Bool.pick(String, oauth && String.is_empty(token),
    "--auth " ++ auth ++ " needs the access token in SMTP_OAUTH_TOKEN",
  Bool.pick(String, basic && String.is_empty(pass),
    "--auth " ++ auth ++ " needs the password in SMTP_PASSWORD",
  Bool.pick(String, String.is_empty(pass) && String.is_empty(token),
    "--user needs SMTP_PASSWORD or SMTP_OAUTH_TOKEN", ""))))

# The report
# ----------

# What to print and the exit code: how many messages went and how many
# did not, and a line (or more) for each.
type Rep is Data:
  Rep{ok: U32, bad: U32, text: String}

def Rep.lines(xs: List<&2, String>) -> String:
  match xs:
    case Nil{}:
      ""
    case Con{x, t}:
      "\n  " ++ x ++ Rep.lines(t)

# " to <label>" when the messages are told apart, else nothing.
def Rep.to(+label: String) -> String:
  Bool.pick(String, String.is_empty(label), "", " to " ++ label)

def Rep.refused(+bad: List<&2, String>) -> String:
  Bool.pick(String, List.is_empty(&2, String, bad), "",
    ", but these recipients were refused:" ++ Rep.lines(bad))

# One message's line, and whether it went.
def Rep.one(+label: String, x: S.Sent) -> Bool & String:
  S.Sent{+code, +error, +bad} = x
  (U32.is_zero(code), Bool.pick(String, U32.is_zero(code),
    "sent" ++ Rep.to(label) ++ Rep.refused(bad),
    "failed" ++ Rep.to(label) ++ " (" ++ U32.show(code) ++ "): " ++ error
      ++ Rep.lines(bad)))

def Rep.add(r: Rep, l: Bool & String) -> Rep:
  Rep{ok, bad, +text} = r
  (+went, line) = l
  Rep{(ok + Bool.pick(U32, went, 1, 0) : U32), (bad + Bool.pick(U32, went, 0, 1) : U32),
    text ++ Bool.pick(String, String.is_empty(text), "", "\n") ++ line}

# The messages tried, each with its label.
def Rep.each(xs: List<&2, S.Sent>, ls: List<&2, String>, r: Rep) -> Rep:
  match xs ls:
    case Nil{} _:
      r
    case Con{x, t} Nil{}:
      Rep.each(t, Nil{}, Rep.add(r, Rep.one("", x)))
    case Con{x, t} Con{l, lt}:
      Rep.each(t, lt, Rep.add(r, Rep.one(l, x)))

# The error that ended the connection, and the messages it left untried.
def Rep.fatal(r: Rep, +code: U32, +error: String, +left: U32) -> Rep:
  Rep{+ok, +bad, +text} = r
  Bool.pick(Rep, String.is_empty(error), Rep{ok, bad, text},
    Rep{ok, (bad + 1 : U32), text ++ Bool.pick(String, String.is_empty(text), "", "\n")
      ++ "failed (" ++ U32.show(code) ++ "): " ++ error
      ++ Bool.pick(String, (left > 1 : U32),
        "\n" ++ U32.show(left) ++ " messages were not tried", "")})

# The report of a connection; labels name the messages ([""] for one).
def Rep.of(+labels: List<&2, String>, b: S.Batch) -> Rep:
  S.Batch{+sent, code, error} = b
  +n = U32.from_nat(List.length(&2, String, labels))
  +k = U32.from_nat(List.length(&2, S.Sent, sent))
  Rep.fatal(Rep.each(sent, labels, Rep{0, 0, ""}), code, error, (n - k : U32))

# 0 when every message went to everyone, 1 when none went, else 3.
def Rep.exit(r: Rep) -> U32:
  Rep{+ok, +bad, +text} = r
  Bool.pick(U32, U32.is_zero(ok), 1,
    Bool.pick(U32, U32.is_zero(bad) && Bool.not(String.contains(text, "refused")),
      0, 3))

def Rep.text(r: Rep) -> String:
  Rep{_, _, t} = r
  t

# IO
# --

def Send.say(ok: Bool, code: U32, text: String) -> IO(Unit):
  match ok:
    case True{}:
      IO.print(text)
    case False{}:
      IO.die(Unit, code, text)

def Send.report(+r: Rep) -> IO(Unit):
  +code = Rep.exit(r)
  Send.say(U32.is_zero(code), code, Rep.text(r))

def Send.env.or(r: Result<&1, &1, U32 & String, String>) -> String:
  match r:
    case Done{v}:
      v
    case Fail{_}:
      ""

def Send.env(name: String) -> IO(String):
  do IO<String>:
    r : Result<&1, &1, U32 & String, String> <- IO.get_env(name)
    IO.pure(String, Send.env.or(r))

def Send.read(m: File & Result<&1, &1, U32 & String, String>) -> IO(String):
  (f, r) = m
  do IO<String>:
    File.close(f)
    IO.pass(String, r)

def Send.text.at(none: Bool, file: String, text: String) -> IO(String):
  match none:
    case True{}:
      IO.pure(String, text)
    case False{}:
      do IO<String>:
        f : File <- IO.try(File, File.open(file, "r"))
        m : File & Result<&1, &1, U32 & String, String> <- File.read(f, 16777216)
        Send.read(m)

# A text from its file (up to 16 MiB), else as given.
def Send.text(+file: String, text: String) -> IO(String):
  Send.text.at(String.is_empty(file), file, text)

def Send.base.of(m: Maybe<&2, String>) -> String:
  match m:
    case None{}:
      "file"
    case Some{n}:
      n

# A path's last part, the file's name.
def Send.base(path: String) -> String:
  Send.base.of(List.last(&2, String, String.split(path, '/')))

def Send.got(m: File & Result<&1, &1, U32 & String, List<&2, U32>>, +path: String) ->
  IO(M.Part):
  (f, r) = m
  +name = Send.base(path)
  do IO<M.Part>:
    File.close(f)
    bs : List<&2, U32> <- IO.pass(List<&2, U32>, r)
    IO.pure(M.Part, M.Part{name, M.Mime.ctype(name), bs})

# One attachment: its bytes (up to 25 MiB), name and type.
def Send.file(+path: String) -> IO(M.Part):
  do IO<M.Part>:
    f : File <- IO.try(File, File.open(path, "r"))
    m : File & Result<&1, &1, U32 & String, List<&2, U32>> <- File.read_bytes(f,
      26214400)
    Send.got(m, path)

def Send.files(ps: List<&2, String>) -> IO(List<&2, M.Part>):
  match ps:
    case Nil{}:
      IO.pure(List<&2, M.Part>, Nil{})
    case Con{p, t}:
      do IO<List<&2, M.Part>>:
        part : M.Part <- Send.file(p)
        rest : List<&2, M.Part> <- Send.files(t)
        IO.pure(List<&2, M.Part>, part <> rest)

def Send.labels.more(ms: List<&2, S.Mail>) -> List<&2, String>:
  match ms:
    case Nil{}:
      Nil{}
    case Con{m, rest}:
      String.join(A.Mbox.addrs(Send.to(m)), ", ") <> Send.labels.more(rest)

# The labels that tell the messages apart: each one's --to address, or
# one empty label for a single message.
def Send.labels(ms: List<&2, S.Mail>) -> List<&2, String>:
  match ms:
    case Nil{}:
      Nil{}
    case Con{m, Nil{}}:
      [""]
    case Con{m, rest}:
      String.join(A.Mbox.addrs(Send.to(m)), ", ") <> Send.labels.more(rest)

def Send.all(+o: S.Opts, +ms: List<&2, S.Mail>) -> IO(Unit):
  do IO<Unit>:
    b : S.Batch <- S.Smtp.send_many(o, ms)
    Send.report(Rep.of(Send.labels(ms), b))

def Send.go(+os: List<&2, Opt>, pass: String, token: String) -> IO(Unit):
  do IO<Unit>:
    text : String <- Send.text(Args.get(os, "--body-file"), Args.get(os, "--body"))
    page : String <- Send.text(Args.get(os, "--html-file"), Args.get(os, "--html"))
    files : List<&2, M.Part> <- Send.files(Args.all(os, "--attach"))
    Send.all(Send.opts(os, pass, token), Send.mails(os, Send.mail(os, text, page,
      files)))

def Send.usage() -> String:
  "usage: send --host H --from F (--to T | --cc C | --bcc B) [--reply-to R]"
    ++ " [--subject S] [--body B | --body-file P] [--html H | --html-file P]"
    ++ " [--attach P]... [--header \"Name: value\"]... [--individually]"
    ++ " [--tls starttls|tls|plain] [--port N] [--user U]"
    ++ " [--auth plain|login|cram-md5|xoauth2|oauthbearer] [--cafile P]"
    ++ " [--cert P --key P] [--helo NAME] [--proxy socks5://[U:P@]H:PORT]"
    ++ " [--notify never|success,failure,delay] [--ret full|hdrs] [--envid ID]"
    ++ " [--dkim-domain D --dkim-selector S --dkim-key P] [--lmtp]"
    ++ " [--no-pipelining] [--chunking] [--debug]"
    ++ "\nsecrets: SMTP_PASSWORD or SMTP_OAUTH_TOKEN"

def Send.creds.ok(problem: String, +os: List<&2, Opt>, pass: String,
  token: String) -> IO(Unit):
  match problem:
    case SNil{}:
      Send.go(os, pass, token)
    case SCon{h, t}:
      IO.die(Unit, 2, SCon{h, t})

def Send.secrets(+os: List<&2, Opt>, +pass: String, +token: String) -> IO(Unit):
  Send.creds.ok(Send.creds(Args.get(os, "--user"), Args.get(os, "--auth"), pass,
    token), os, pass, token)

def Send.start(+os: List<&2, Opt>) -> IO(Unit):
  do IO<Unit>:
    pass : String <- Send.env("SMTP_PASSWORD")
    token : String <- Send.env("SMTP_OAUTH_TOKEN")
    Send.secrets(os, pass, token)

def Send.run(problem: String, +os: List<&2, Opt>) -> IO(Unit):
  match problem:
    case SNil{}:
      Send.start(os)
    case SCon{h, t}:
      IO.die(Unit, 2, SCon{h, t} ++ "\n" ++ Send.usage())

def Send.args(+os: List<&2, Opt>) -> IO(Unit):
  Send.run(Send.problem(os), os)

def main() -> IO(Unit):
  do IO<Unit>:
    xs : List<String> <- IO.args()
    Send.args(Args.parse(Args.copy(xs)))
