# The smallest use of the library: one message through a server.
#
#   bend examples/hello.bend -o hello
#   SMTP_PASSWORD=... ./hello smtp.example.com me@example.com you@example.com
import Base
import ../smtp.bend as S

def Hello.say(b: S.Batch) -> IO(Unit):
  S.Batch{sent, code, +error} = b
  IO.print(Bool.pick(String, String.is_empty(error), "sent to "
    ++ Nat.show(List.length(&2, S.Sent, sent)) ++ " message(s)",
    "failed (" ++ U32.show(code) ++ "): " ++ error))

def Hello.send(args: List<String>, pass: String) -> IO(Unit):
  match args:
    case Con{host, Con{+from, Con{to, Nil{}}}}:
      do IO<Unit>:
        b : S.Batch <- S.Smtp.send_mail(S.Opts.login(S.Opts.new(host), from, pass),
          S.Mail.html(S.Mail.new(from, to, "Hello from Bend 2", "It works."),
            "<p>It <b>works</b>.</p>"))
        Hello.say(b)
    case _:
      IO.print("usage: hello HOST FROM TO   (password in SMTP_PASSWORD)")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    pass : String <- IO.try(String, IO.get_env("SMTP_PASSWORD"))
    Hello.send(args, pass)
