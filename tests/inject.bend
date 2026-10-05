# A caller of the library, past the command line's own checks, trying
# the two injections a reviewer found: a DSN option and an attachment's
# content type that carry a line end.
#
#   inject PORT ret|ctype|more
#
# "ret" and "ctype" must be refused before anything is sent; "more"
# sends a valid message with the DSN options on, to show what a server
# gets.
import Base
import ../core.bend as C
import ../smtp.bend as S
import ../addr.bend as A
import ../mime.bend as M

def Inject.opts(port: U32) -> C.Opts:
  C.Opts.via(C.Opts.new("127.0.0.1"), port, C.Plain{})

def Inject.mail() -> C.Mail:
  C.Mail.new("me@example.com", "a@example.com", "s", "t")

# The message with an attachment whose type carries a header.
def Inject.bad() -> C.Mail:
  C.Mail{A.Mbox{"", "me@example.com"}, [A.Mbox{"", "a@example.com"}], Nil{}, Nil{},
    Nil{}, "s", "t", "", [M.Part{"a.txt", "text/plain\r\nX-Injected: yes", [104, 105]}],
    Nil{}}

def Inject.say(b: C.Batch) -> IO(Unit):
  C.Batch{sent, code, +error} = b
  IO.print(Bool.pick(String, String.is_empty(error), "went through", "refused: "
    ++ error))

def Inject.run(+what: String, +port: U32) -> IO(Unit):
  do IO<Unit>:
    b : C.Batch <- S.Smtp.send_mail(
      Bool.pick(C.Opts, String.eq(what, "ret"),
        C.Opts.with(Inject.opts(port), "ret", "full\r\nRSET"),
        C.Opts.with(C.Opts.with(Inject.opts(port), "ret", "HDRS"), "notify", "never")),
      Bool.pick(C.Mail, String.eq(what, "ctype"),
        Inject.bad(),
        Inject.mail()))
    Inject.say(b)

def Inject.port(m: Maybe<&2, U32>) -> U32:
  match m:
    case None{}:
      0
    case Some{p}:
      p

def Inject.args(args: List<String>) -> IO(Unit):
  match args:
    case Con{_, Con{port, Con{what, Nil{}}}}:
      Inject.run(what, Inject.port(U32.read(port)))
    case _:
      IO.print("usage: inject PORT ret|ctype|more")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    Inject.args(args)
