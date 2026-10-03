# Replies: a server answers each command with one or more lines, each a
# 3-digit code and a separator: "250-" means more lines follow, "250 "
# (or the bare code) ends the reply. RFC 5321, section 4.2.
import Base
import ./text.bend as T

# A whole reply: its code and its lines' text, joined by LF.
type Reply is Data:
  Reply{code: U32, text: String}

# A buffer cut at the end of its first reply, or kept whole until one
# arrives in full. A malformed line ends the reply with code 0.
type Split is Data:
  More{buf: String}
  Got{reply: Reply, rest: String}

# One reply line, read.
type Rl is Data:
  Bad{}
  Rl{code: U32, last: Bool, text: String}

# Lines
# -----

def Reply.digit(+c: U32) -> Bool:
  ((c >= 48) && (c <= 57) : U32)

def Reply.sep(code: U32, rest: String) -> Rl:
  match rest:
    case SNil{}:
      Rl{code, True{}, SNil{}}
    case SCon{Chr{45}, t}:
      Rl{code, False{}, t}
    case SCon{_, t}:
      Rl{code, True{}, t}

def Reply.ok(ok: Bool, code: U32, rest: String) -> Rl:
  match ok:
    case True{}:
      Reply.sep(code, rest)
    case False{}:
      Bad{}

def Reply.line(l: String) -> Rl:
  match l:
    case SCon{Chr{+a}, SCon{Chr{+b}, SCon{Chr{+c}, rest}}}:
      Reply.ok(Reply.digit(a) && Reply.digit(b) && Reply.digit(c),
        (a * 100 + b * 10 + c - 5328 : U32), rest)
    case _:
      Bad{}

# Scan
# ----

def Reply.end(last: Bool, code: U32, rest: String, text: String,
  more: String -> String -> Split) -> Split:
  match last:
    case True{}:
      Got{Reply{code, text}, rest}
    case False{}:
      more(rest, text ++ "\n")

def Reply.rl(rl: Rl, rest: String, text: String,
  more: String -> String -> Split) -> Split:
  match rl:
    case Bad{}:
      Got{Reply{0, text}, rest}
    case Rl{code, last, t}:
      Reply.end(last, code, rest, text ++ t, more)

def Reply.step(l: T.Line, text: String, more: String -> String -> Split) ->
  Split:
  match l:
    case T.Need{_}:
      More{SNil{}}
    case T.Line{line, rest}:
      Reply.rl(Reply.line(line), rest, text, more)

# Each line eats at least one byte, so fuel = length + 1 always lasts.
def Reply.scan(fuel: Nat, s: String, text: String) -> Split:
  match fuel:
    case 0n:
      More{SNil{}}
    case 1n+p:
      Reply.step(T.Text.line(s, SNil{}), text, r => t => Reply.scan(p, r, t))

def Reply.fin(sp: Split, buf: String) -> Split:
  match sp:
    case More{_}:
      More{buf}
    case Got{r, rest}:
      Got{r, rest}

# The first complete reply in buf, or More{buf}.
def Reply.split(+buf: String) -> Split:
  Reply.fin(Reply.scan(1n+String.length(buf), buf, SNil{}), buf)

# The reply's class: 2 done, 3 go on, 4 try later, 5 refused.
def Reply.class(r: Reply) -> U32:
  Reply{code, _} = r
  (code / 100 : U32)

def Reply.code(r: Reply) -> U32:
  Reply{code, _} = r
  code

def Reply.text(r: Reply) -> String:
  Reply{_, text} = r
  text
