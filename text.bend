# Text: lines out of a byte stream, and header-safe strings. SMTP is a
# line protocol: every command and reply line ends in CRLF, and a CR or
# LF smuggled into a field would start a new command or header.
import Base

# A cut of a buffer: the first complete line and the rest, or the
# whole buffer back when no line is complete yet.
type Line is Data:
  Need{buf: String}
  Line{line: String, rest: String}

# Lines
# -----

# A line read backwards, its CR dropped, put back in order.
def Text.done(acc: String) -> String:
  match acc:
    case SNil{}:
      SNil{}
    case SCon{Chr{13}, t}:
      String.reverse(t)
    case SCon{c, t}:
      String.reverse(SCon{c, t})

# The first LF-terminated line of s; Need{""} when there is none.
def Text.line(s: String, acc: String) -> Line:
  match s:
    case SNil{}:
      Need{SNil{}}
    case SCon{Chr{10}, t}:
      Line{Text.done(acc), t}
    case SCon{c, t}:
      Text.line(t, SCon{c, acc})

def Text.cut.fin(l: Line, buf: String) -> Line:
  match l:
    case Need{_}:
      Need{buf}
    case Line{a, b}:
      Line{a, b}

# The first line of buf and the rest, or Need{buf}.
def Text.cut(+buf: String) -> Line:
  Text.cut.fin(Text.line(buf, SNil{}), buf)

# Safe fields
# -----------

def Text.is_nl(c: Char) -> Bool:
  match c:
    case Chr{+n}:
      U32.is_eq(n, 10) || U32.is_eq(n, 13)

def Text.clean.put(nl: Bool, c: Char, rest: String) -> String:
  match nl:
    case True{}:
      rest
    case False{}:
      SCon{c, rest}

# s without its CRs and LFs: safe inside one command or header line.
def Text.clean(s: String) -> String:
  match s:
    case SNil{}:
      SNil{}
    case SCon{+c, t}:
      Text.clean.put(Text.is_nl(c), c, Text.clean(t))

# Whether s holds a CR or an LF.
def Text.has_nl(s: String) -> Bool:
  match s:
    case SNil{}:
      False{}
    case SCon{+c, t}:
      Text.is_nl(c) || Text.has_nl(t)

# acc reversed in front of tail: the last step of a tail-recursive
# builder (a non-tail recursion costs a frame per char in Bend).
def Text.onto(acc: String, tail: String) -> String:
  match acc:
    case SNil{}:
      tail
    case SCon{c, t}:
      Text.onto(t, SCon{c, tail})
