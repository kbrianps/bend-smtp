# Addresses and mailboxes. An address is local@domain, a dot-atom (RFC
# 5321 4.1.2; RFC 6531 3.3 for UTF-8); a mailbox is an address with an
# optional display name, "Maria Silva <maria@example.com>" (RFC 5322
# 3.4). Lists are read the way people write them, commas inside quotes
# or angle brackets included, and written back as header values.
import Base
import ./text.bend as T
import ./mime.bend as M
import ./idna.bend as I

type Mbox is Data:
  Mbox{name: String, addr: String}

# Addresses
# ---------

# atext (RFC 5322 3.2.3): letters, digits and !#$%&'*+-/=?^_`{|}~.
def Addr.atext(+c: U32) -> Bool:
  (c >= 97 && c <= 122 || c >= 65 && c <= 90 || c >= 48 && c <= 57 : U32)
    || U32.is_eq(c, 33) || (c >= 35 && c <= 39 : U32) || U32.is_eq(c, 42)
    || U32.is_eq(c, 43) || U32.is_eq(c, 45) || U32.is_eq(c, 47)
    || U32.is_eq(c, 61) || U32.is_eq(c, 63) || (c >= 94 && c <= 96 : U32)
    || (c >= 123 && c <= 126 : U32)

# Local part chars: atext, ".", and any non-ASCII (RFC 6531 3.3).
def Addr.local.ok(s: String) -> Bool:
  match s:
    case SNil{}:
      True{}
    case SCon{Chr{+c}, t}:
      (Addr.atext(c) || U32.is_eq(c, 46) || (c >= 128 : U32)) && Addr.local.ok(t)

# Domain chars: letters, digits, "-", "." and non-ASCII (a U-label).
def Addr.domain.ok(s: String) -> Bool:
  match s:
    case SNil{}:
      True{}
    case SCon{Chr{+c}, t}:
      ((c >= 97 && c <= 122 || c >= 65 && c <= 90 || c >= 48 && c <= 57 : U32)
        || U32.is_eq(c, 45) || U32.is_eq(c, 46) || (c >= 128 : U32))
        && Addr.domain.ok(t)

# Dots only between other chars.
def Addr.dots(+s: String) -> Bool:
  Bool.not(String.is_empty(s)) && Bool.not(String.starts_with(s, "."))
    && Bool.not(String.ends_with(s, ".")) && Bool.not(String.contains(s, ".."))

def Addr.parts(parts: List<&2, String>) -> Bool:
  match parts:
    case Con{+l, Con{+d, Nil{}}}:
      Addr.dots(l) && Addr.dots(d) && Addr.local.ok(l) && Addr.domain.ok(d)
        && Nat.is_le(List.length(&2, U32, M.Utf8.bytes(l)), 64n)
    case _:
      False{}

# A dot-atom address: no quoting, no route, local part up to 64 octets,
# all up to 254.
def Addr.ok(+a: String) -> Bool:
  Nat.is_le(List.length(&2, U32, M.Utf8.bytes(a)), 254n)
    && Addr.parts(String.split(a, '@'))

def Addr.domain.of(parts: List<&2, String>) -> String:
  match parts:
    case Con{_, Con{d, _}}:
      d
    case _:
      "localhost"

def Addr.domain(a: String) -> String:
  Addr.domain.of(String.split(a, '@'))

def Addr.local(parts: List<&2, String>) -> String:
  match parts:
    case Con{l, _}:
      l
    case _:
      ""

def Addr.ascii.of(parts: List<&2, String>) -> String:
  match parts:
    case Con{l, Con{d, Nil{}}}:
      l ++ "@" ++ I.Idna.domain(d)
    case _:
      ""

# The address with its domain as A-labels (RFC 5890).
def Addr.ascii(a: String) -> String:
  Addr.ascii.of(String.split(a, '@'))

# Whether a local part has non-ASCII, which only SMTPUTF8 can carry.
def Addr.utf8(a: String) -> Bool:
  Bool.not(I.Idna.ascii(Addr.local(String.split(a, '@'))))

# Mailboxes
# ---------

def Mbox.addr(m: Mbox) -> String:
  Mbox{_, a} = m
  a

def Mbox.addrs(ms: List<&2, Mbox>) -> List<&2, String>:
  match ms:
    case Nil{}:
      Nil{}
    case Con{m, t}:
      Mbox.addr(m) <> Mbox.addrs(t)

def Mbox.all.ok(ms: List<&2, Mbox>) -> Bool:
  match ms:
    case Nil{}:
      True{}
    case Con{m, t}:
      Addr.ok(Mbox.addr(m)) && Mbox.all.ok(t)

# The first bad address of a list, or "" when all are good.
def Mbox.bad(ms: List<&2, Mbox>) -> String:
  match ms:
    case Nil{}:
      ""
    case Con{m, t}:
      +a = Mbox.addr(m)
      Bool.pick(String, Addr.ok(a), Mbox.bad(t), Bool.pick(String,
        String.is_empty(a), "(empty)", a))

def Mbox.any.utf8(ms: List<&2, Mbox>) -> Bool:
  match ms:
    case Nil{}:
      False{}
    case Con{m, t}:
      Addr.utf8(Mbox.addr(m)) || Mbox.any.utf8(t)

def Mbox.ascii(m: Mbox) -> Mbox:
  Mbox{n, a} = m
  Mbox{n, Addr.ascii(a)}

def Mbox.asciis(ms: List<&2, Mbox>) -> List<&2, Mbox>:
  match ms:
    case Nil{}:
      Nil{}
    case Con{m, t}:
      Mbox.ascii(m) <> Mbox.asciis(t)

# Reading
# -------

# Where a list split is: inside quotes, after a backslash in them, inside
# angle brackets; the item so far (reversed) and the items (reversed).
type Cut is Data:
  Cut{q: Bool, esc: Bool, a: Bool, cur: String, acc: List<&2, String>}

def Mbox.flush(cur: String, acc: List<&2, String>) -> List<&2, String>:
  String.trim(String.reverse(cur)) <> acc

def Mbox.cut.ch(st: Cut, +c: U32) -> Cut:
  Cut{+q, +esc, +a, +cur, +acc} = st
  +ch = {SCon{Chr{c}, cur} : String}
  Bool.pick(Cut, esc, Cut{q, False{}, a, ch, acc},
  Bool.pick(Cut, q && U32.is_eq(c, 92), Cut{q, True{}, a, ch, acc},
  Bool.pick(Cut, Bool.not(a) && U32.is_eq(c, 34), Cut{Bool.not(q), False{}, a, ch, acc},
  Bool.pick(Cut, Bool.not(q) && U32.is_eq(c, 60), Cut{q, False{}, True{}, ch, acc},
  Bool.pick(Cut, Bool.not(q) && U32.is_eq(c, 62), Cut{q, False{}, False{}, ch, acc},
  Bool.pick(Cut, Bool.not(q) && Bool.not(a) && U32.is_eq(c, 44),
    Cut{q, False{}, a, "", Mbox.flush(cur, acc)},
    Cut{q, False{}, a, ch, acc}))))))

def Mbox.cut.go(s: String, st: Cut) -> Cut:
  match s:
    case SNil{}:
      st
    case SCon{Chr{c}, t}:
      Mbox.cut.go(t, Mbox.cut.ch(st, c))

def Mbox.keep(empty: Bool, x: String, rest: List<&2, String>) -> List<&2, String>:
  match empty:
    case True{}:
      rest
    case False{}:
      x <> rest

def Mbox.nonempty(xs: List<&2, String>) -> List<&2, String>:
  match xs:
    case Nil{}:
      Nil{}
    case Con{+x, t}:
      Mbox.keep(String.is_empty(x), x, Mbox.nonempty(t))

def Mbox.cut.fin(st: Cut) -> List<&2, String>:
  Cut{_, _, _, cur, acc} = st
  Mbox.nonempty(List.reverse(&2, String, Mbox.flush(cur, acc)))

# The items of a comma-separated list; commas in quotes or <...> stay.
def Mbox.items(s: String) -> List<&2, String>:
  Mbox.cut.fin(Mbox.cut.go(s, Cut{False{}, False{}, False{}, "", Nil{}}))

def Mbox.unescape(s: String) -> String:
  match s:
    case SNil{}:
      SNil{}
    case SCon{Chr{92}, SCon{c, t}}:
      SCon{c, Mbox.unescape(t)}
    case SCon{c, t}:
      SCon{c, Mbox.unescape(t)}

# A display name as written: its quotes taken off.
def Mbox.unquote(+s: String) -> String:
  Bool.pick(String, String.starts_with(s, "\"") && String.ends_with(s, "\"")
    && Nat.is_le(2n, String.length(s)),
    Mbox.unescape(String.drop(String.take(s, Nat.sub(String.length(s), 1n)), 1n)), s)

def Mbox.head(xs: List<&2, String>) -> String:
  match xs:
    case Nil{}:
      ""
    case Con{x, _}:
      x

def Mbox.angled(+parts: List<&2, String>) -> Mbox:
  +n = Nat.sub(List.length(&2, String, parts), 1n)
  Mbox{Mbox.unquote(String.trim(String.join(List.take(&2, String, parts, n), "<"))),
    String.trim(Mbox.head(String.split(Mbox.head(List.drop(&2, String, parts, n)),
      '>')))}

def Mbox.parse.at(plain: Bool, item: String) -> Mbox:
  match plain:
    case True{}:
      Mbox{"", String.trim(item)}
    case False{}:
      Mbox.angled(String.split(item, '<'))

# One mailbox: "name <addr>", "<addr>" or "addr".
def Mbox.parse(+item: String) -> Mbox:
  Mbox.parse.at(Bool.not(String.contains(item, "<")), item)

def Mbox.parses(xs: List<&2, String>) -> List<&2, Mbox>:
  match xs:
    case Nil{}:
      Nil{}
    case Con{x, t}:
      Mbox.parse(x) <> Mbox.parses(t)

# The mailboxes of a list as people write it.
def Mbox.list(s: String) -> List<&2, Mbox>:
  Mbox.parses(Mbox.items(s))

# Writing
# -------

def Mbox.atoms(s: String) -> Bool:
  match s:
    case SNil{}:
      True{}
    case SCon{Chr{+c}, t}:
      (Addr.atext(c) || U32.is_eq(c, 32)) && Mbox.atoms(t)

def Mbox.esc(yes: Bool, c: U32, rest: String) -> String:
  match yes:
    case True{}:
      SCon{'\\', SCon{Chr{c}, rest}}
    case False{}:
      SCon{Chr{c}, rest}

def Mbox.quote(s: String) -> String:
  match s:
    case SNil{}:
      SNil{}
    case SCon{Chr{+c}, t}:
      Mbox.esc(U32.is_eq(c, 34) || U32.is_eq(c, 92), c, Mbox.quote(t))

# A display name as a phrase (RFC 5322 3.2.5): atoms as they are, other
# printable ASCII as a quoted string, the rest (and anything that could
# read as an encoded word) as RFC 2047 words.
def Mbox.phrase(+s: String) -> String:
  Bool.pick(String, Bool.not(M.Mime.printable(s)) || String.contains(s, "=?"),
    M.Mime.encoded(s),
  Bool.pick(String, Mbox.atoms(s), s, "\"" ++ Mbox.quote(s) ++ "\""))

def Mbox.show.at(none: Bool, name: String, addr: String) -> String:
  match none:
    case True{}:
      addr
    case False{}:
      Mbox.phrase(name) ++ " <" ++ addr ++ ">"

# A mailbox in a header: "name <addr>", or the bare address.
def Mbox.show(m: Mbox) -> String:
  Mbox{n, a} = m
  +name = String.trim(T.Text.clean(n))
  Mbox.show.at(String.is_empty(name), name, T.Text.clean(a))

def Mbox.shows.more(ms: List<&2, Mbox>) -> String:
  match ms:
    case Nil{}:
      SNil{}
    case Con{m, t}:
      ",\r\n " ++ Mbox.show(m) ++ Mbox.shows.more(t)

# A list header's value: one mailbox per (folded) line.
def Mbox.shows(ms: List<&2, Mbox>) -> String:
  match ms:
    case Nil{}:
      SNil{}
    case Con{m, t}:
      Mbox.show(m) ++ Mbox.shows.more(t)
