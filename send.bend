# Send one message over SMTP.
#
#   bend send.bend -o send
#   SMTP_PASSWORD=... ./send --host smtp.example.com --user me@example.com \
#     --from "Me <me@example.com>" --to "Ana <ana@x.com>, bia@y.com" \
#     --cc c@z.com --bcc d@w.com --subject "Oi" --body "texto" \
#     --html-file corpo.html --attach relatorio.pdf --attach foto.jpg
#
# Address lists take "Name <addr>" or "addr", comma-separated (quote a
# name with a comma: "\"Silva, Ana\" <ana@x.com>"). --attach repeats.
# --tls starttls (default; port 587), tls (implicit; port 465) or plain
# (port 25); --port overrides. --auth plain, login, xoauth2 or
# oauthbearer (default: picked from what the server offers). Secrets
# come only from the environment: SMTP_PASSWORD, or SMTP_OAUTH_TOKEN (an
# OAuth 2 access token). --cafile trusts that CA instead of the
# system's; --helo names this host.
#
# Exit: 0 sent to everyone; 3 sent, but some recipients were refused
# (listed); 1 not sent; 2 bad usage.
import Base
import ./smtp.bend as S
import ./addr.bend as A
import ./mime.bend as M

type Args is Data:
  Args{host: String, port: String, tls: String, cafile: String,
    helo: String, user: String, auth: String, from: String, to: String,
    cc: String, bcc: String, reply: String, subject: String, body: String,
    file: String, html: String, hfile: String, attach: List<&2, String>,
    bad: String}

def Args.none() -> Args:
  Args{"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", Nil{},
    ""}

def Args.pick(+k: String, f: String, +v: String, old: String) -> String:
  Bool.pick(String, String.eq(k, f), v, old)

def Args.flags() -> List<&2, String>:
  ["--host", "--port", "--tls", "--cafile", "--helo", "--user", "--auth",
    "--from", "--to", "--cc", "--bcc", "--reply-to", "--subject", "--body",
    "--body-file", "--html", "--html-file", "--attach"]

def Args.set(+k: String, +v: String, a: Args) -> Args:
  Args{host, port, tls, cafile, helo, user, auth, from, to, cc, bcc, reply,
    subject, body, file, html, hfile, +attach, +bad} = a
  Args{Args.pick(k, "--host", v, host), Args.pick(k, "--port", v, port),
    Args.pick(k, "--tls", v, tls), Args.pick(k, "--cafile", v, cafile),
    Args.pick(k, "--helo", v, helo), Args.pick(k, "--user", v, user),
    Args.pick(k, "--auth", v, auth), Args.pick(k, "--from", v, from),
    Args.pick(k, "--to", v, to), Args.pick(k, "--cc", v, cc),
    Args.pick(k, "--bcc", v, bcc), Args.pick(k, "--reply-to", v, reply),
    Args.pick(k, "--subject", v, subject), Args.pick(k, "--body", v, body),
    Args.pick(k, "--body-file", v, file), Args.pick(k, "--html", v, html),
    Args.pick(k, "--html-file", v, hfile),
    Bool.pick(List<&2, String>, String.eq(k, "--attach"),
      List.append(&2, String, attach, [v]), attach),
    Bool.pick(String, List.contains(~String, ~String.eq, Args.flags(), k), bad,
      Bool.pick(String, String.is_empty(bad), "unknown option " ++ k, bad))}

def Args.missing(+k: String, a: Args) -> Args:
  Args{host, port, tls, cafile, helo, user, auth, from, to, cc, bcc, reply,
    subject, body, file, html, hfile, attach, _} = a
  Args{host, port, tls, cafile, helo, user, auth, from, to, cc, bcc, reply,
    subject, body, file, html, hfile, attach, "a value is missing after " ++ k}

def Args.parse(xs: List<&2, String>, a: Args) -> Args:
  match xs:
    case Nil{}:
      a
    case Con{k, Nil{}}:
      Args.missing(k, a)
    case Con{k, Con{v, rest}}:
      Args.parse(rest, Args.set(k, v, a))

def Args.copy(xs: List<String>) -> List<&2, String>:
  match xs:
    case Nil{}:
      Nil{}
    case Con{x, rest}:
      x <> Args.copy(rest)

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
  Bool.pick(S.Auth, String.eq(a, "xoauth2"), S.AXoauth2{},
  Bool.pick(S.Auth, String.eq(a, "oauthbearer"), S.ABearer{}, S.AAuto{}))))

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

def Send.problem(+a: Args) -> String:
  Args{+host, _, +tls, _, _, _, +auth, +from, +to, +cc, +bcc, _, _, +body, +file,
    +html, +hfile, _, +bad} = a
  Bool.pick(String, Bool.not(String.is_empty(bad)), bad,
  Bool.pick(String, String.is_empty(host), "--host is required",
  Bool.pick(String, String.is_empty(from), "--from is required",
  Bool.pick(String, String.is_empty(to) && String.is_empty(cc)
    && String.is_empty(bcc), "--to, --cc or --bcc is required",
  Bool.pick(String, Bool.not(List.contains(~String, ~String.eq,
    ["", "tls", "starttls", "plain"], tls)), "--tls takes starttls, tls or plain",
  Bool.pick(String, Bool.not(List.contains(~String, ~String.eq,
    ["", "plain", "login", "xoauth2", "oauthbearer"], auth)),
    "--auth takes plain, login, xoauth2 or oauthbearer",
  Bool.pick(String, Bool.not(String.is_empty(body)) && Bool.not(String.is_empty(file)),
    "--body and --body-file exclude each other",
  Bool.pick(String, Bool.not(String.is_empty(html)) && Bool.not(String.is_empty(hfile)),
    "--html and --html-file exclude each other", ""))))))))

def Send.opts(+a: Args, pass: String, token: String) -> S.Opts:
  Args{host, +port, +tls, cafile, helo, user, auth, _, _, _, _, _, _, _, _, _, _, _,
    _} = a
  +mode = Send.mode(tls, port)
  S.Opts{host, Send.port.or(U32.read(port), Send.port.dflt(mode)), mode, cafile,
    helo, user, pass, Send.auth(auth), token}

def Send.mail(+a: Args, text: String, html: String, files: List<&2, M.Part>) ->
  S.Mail:
  Args{_, _, _, _, _, _, _, from, to, cc, bcc, reply, subject, _, _, _, _, _, _} = a
  S.Mail{A.Mbox.parse(from), A.Mbox.list(to), A.Mbox.list(cc), A.Mbox.list(bcc),
    A.Mbox.list(reply), subject, text, html, files}

# What is missing for AUTH, or "": a password for PLAIN and LOGIN, a
# token for the OAuth mechanisms, one of the two otherwise.
def Send.creds(+user: String, +auth: String, +pass: String, +token: String) ->
  String:
  +oauth = String.eq(auth, "xoauth2") || String.eq(auth, "oauthbearer")
  +basic = String.eq(auth, "plain") || String.eq(auth, "login")
  Bool.pick(String, String.is_empty(user), "",
  Bool.pick(String, oauth && String.is_empty(token),
    "--auth " ++ auth ++ " needs the access token in SMTP_OAUTH_TOKEN",
  Bool.pick(String, basic && String.is_empty(pass),
    "--auth " ++ auth ++ " needs the password in SMTP_PASSWORD",
  Bool.pick(String, String.is_empty(pass) && String.is_empty(token),
    "--user needs SMTP_PASSWORD or SMTP_OAUTH_TOKEN", ""))))

# IO
# --

def Send.lines(xs: List<&2, String>) -> String:
  match xs:
    case Nil{}:
      ""
    case Con{x, t}:
      "\n  " ++ x ++ Send.lines(t)

def Send.report(r: S.Out()) -> IO(Unit):
  match r:
    case Done{Nil{}}:
      IO.print("sent")
    case Done{Con{x, t}}:
      IO.die(Unit, 3, "sent, but these recipients were refused:"
        ++ Send.lines(Con{x, t}))
    case Fail{e}:
      (code, msg) = e
      IO.die(Unit, 1, "failed (" ++ U32.show(code) ++ "): " ++ msg)

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

def Send.go(+a: Args, pass: String, token: String) -> IO(Unit):
  Args{_, _, _, _, _, _, _, _, _, _, _, _, _, body, file, html, hfile, attach,
    _} = a
  do IO<Unit>:
    text : String <- Send.text(file, body)
    page : String <- Send.text(hfile, html)
    files : List<&2, M.Part> <- Send.files(attach)
    r : S.Out() <- S.Smtp.send_mail(Send.opts(a, pass, token),
      Send.mail(a, text, page, files))
    Send.report(r)

def Send.usage() -> String:
  "usage: send --host H --from F (--to T | --cc C | --bcc B) [--reply-to R]"
    ++ " [--subject S] [--body B | --body-file P] [--html H | --html-file P]"
    ++ " [--attach P]... [--tls starttls|tls|plain] [--port N] [--user U]"
    ++ " [--auth plain|login|xoauth2|oauthbearer] [--cafile P] [--helo NAME]"
    ++ "\nsecrets: SMTP_PASSWORD or SMTP_OAUTH_TOKEN"

def Send.creds.ok(problem: String, +a: Args, pass: String, token: String) ->
  IO(Unit):
  match problem:
    case SNil{}:
      Send.go(a, pass, token)
    case SCon{h, t}:
      IO.die(Unit, 2, SCon{h, t})

def Send.secrets(+a: Args, +pass: String, +token: String) -> IO(Unit):
  Args{_, _, _, _, _, +user, +auth, _, _, _, _, _, _, _, _, _, _, _, _} = a
  Send.creds.ok(Send.creds(user, auth, pass, token), a, pass, token)

def Send.start(+a: Args) -> IO(Unit):
  do IO<Unit>:
    pass : String <- Send.env("SMTP_PASSWORD")
    token : String <- Send.env("SMTP_OAUTH_TOKEN")
    Send.secrets(a, pass, token)

def Send.run(problem: String, +a: Args) -> IO(Unit):
  match problem:
    case SNil{}:
      Send.start(a)
    case SCon{h, t}:
      IO.die(Unit, 2, SCon{h, t} ++ "\n" ++ Send.usage())

def Send.args(+a: Args) -> IO(Unit):
  Send.run(Send.problem(a), a)

def main() -> IO(Unit):
  do IO<Unit>:
    xs : List<String> <- IO.args()
    Send.args(Args.parse(Args.copy(xs), Args.none()))
