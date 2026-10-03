# Punycode (RFC 3492) and A-labels (RFC 5890): a domain with non-ASCII
# labels written as "xn--" ASCII, so it can travel where only ASCII may
# (an SMTP session without SMTPUTF8).
#
# Not done: the IDNA2008 mapping and checks (Unicode normalization, case
# folding of non-ASCII letters, the disallowed code points). A label is
# converted as written; ASCII letters are lower-cased.
import Base

# The state of an encoding: delta, bias, the code points handled (h),
# the basic ones (b), the next code point to place (n), the output.
type Pc is Data:
  Pc{delta: U32, bias: U32, h: U32, b: U32, n: U32, out: String}

def Puny.pick(c: Bool, a: U32, b: U32) -> U32:
  match c:
    case True{}:
      a
    case False{}:
      b

# Digit d (0..35) as a..z, 0..9.
def Puny.digit(+d: U32) -> Char:
  Chr{Puny.pick((d < 26 : U32), (d + 97 : U32), (d + 22 : U32))}

# The threshold t for position k (tmin 1, tmax 26).
def Puny.t(+k: U32, +bias: U32) -> U32:
  Puny.pick((k <= bias : U32), 1, Puny.pick((k >= bias + 26 : U32), 26,
    (k - bias : U32)))

def Puny.vli.at(stop: Bool, +q: U32, +t: U32, more: U32 -> String) -> String:
  match stop:
    case True{}:
      SCon{Puny.digit(q), SNil{}}
    case False{}:
      SCon{Puny.digit((t + (q - t) % (36 - t) : U32)), more(((q - t) / (36 - t) : U32))}

# q as a generalized variable-length integer (RFC 3492 3.3).
def Puny.vli(fuel: Nat, +q: U32, +k: U32, +bias: U32) -> String:
  match fuel:
    case 0n:
      SNil{}
    case 1n+p:
      Puny.vli.at((q < Puny.t(k, bias) : U32), q, Puny.t(k, bias),
        q2 => Puny.vli(p, q2, (k + 36 : U32), bias))

def Puny.adapt.go(fuel: Nat, +d: U32, +k: U32) -> U32:
  match fuel:
    case 0n:
      (k + 36 * d / (d + 38) : U32)
    case 1n+p:
      Puny.pick((d > 455 : U32), Puny.adapt.go(p, (d / 35 : U32), (k + 36 : U32)),
        (k + 36 * d / (d + 38) : U32))

# The bias adaptation (RFC 3492 6.1).
def Puny.adapt(+delta: U32, +num: U32, first: Bool) -> U32:
  +d = Puny.pick(first, (delta / 700 : U32), (delta / 2 : U32))
  Puny.adapt.go(16n, (d + d / num : U32), 0)

def Puny.char(+c: U32, +n: U32, st: Pc) -> Pc:
  Pc{+delta, +bias, +h, +b, +nn, +out} = st
  Bool.pick(Pc, (c < n : U32), Pc{(delta + 1 : U32), bias, h, b, nn, out},
  Bool.pick(Pc, U32.is_eq(c, n),
    Pc{0, Puny.adapt(delta, (h + 1 : U32), U32.is_eq(h, b)), (h + 1 : U32), b, nn,
      out ++ Puny.vli(32n, delta, 36, bias)},
    Pc{delta, bias, h, b, nn, out}))

def Puny.chars(cs: List<&2, U32>, +n: U32, st: Pc) -> Pc:
  match cs:
    case Nil{}:
      st
    case Con{c, t}:
      Puny.chars(t, n, Puny.char(c, n, st))

# The smallest code point >= n.
def Puny.min(cs: List<&2, U32>, +n: U32, +best: U32) -> U32:
  match cs:
    case Nil{}:
      best
    case Con{+c, t}:
      Puny.min(t, n, Puny.pick((c >= n && c < best : U32), c, best))

def Puny.next(st: Pc, +m: U32) -> Pc:
  Pc{dd, bb, hh, b2, _, oo} = st
  Pc{(dd + 1 : U32), bb, hh, b2, (m + 1 : U32), oo}

# One round: the next code point placed at every position.
def Puny.round(+cs: List<&2, U32>, st: Pc) -> Pc:
  Pc{+delta, bias, +h, b, +n, out} = st
  +m = Puny.min(cs, n, 4294967295)
  Puny.next(Puny.chars(cs, m,
    Pc{(delta + (m - n) * (h + 1) : U32), bias, h, b, m, out}), m)

def Puny.more(done: Bool, st: Pc, next: Pc -> String) -> String:
  match done:
    case True{}:
      Pc{_, _, _, _, _, out} = st
      out
    case False{}:
      next(st)

def Puny.go(fuel: Nat, +cs: List<&2, U32>, +len: U32, +st: Pc) -> String:
  match fuel:
    case 0n:
      Pc{_, _, _, _, _, out} = st
      out
    case 1n+p:
      Pc{_, _, h, _, _, _} = st
      Puny.more((h >= len : U32), st, s => Puny.go(p, cs, len, Puny.round(cs, s)))

def Puny.keep(yes: Bool, c: U32, rest: String) -> String:
  match yes:
    case True{}:
      SCon{Chr{c}, rest}
    case False{}:
      rest

def Puny.basic(cs: List<&2, U32>) -> String:
  match cs:
    case Nil{}:
      SNil{}
    case Con{+c, t}:
      Puny.keep((c < 128 : U32), c, Puny.basic(t))

def Puny.count(cs: List<&2, U32>) -> U32:
  match cs:
    case Nil{}:
      0
    case Con{+c, t}:
      (Puny.pick((c < 128 : U32), 1, 0) + Puny.count(t) : U32)

# The Punycode of a list of code points.
def Puny.encode(+cs: List<&2, U32>) -> String:
  +b   = Puny.count(cs)
  +len = U32.from_nat(List.length(&2, U32, cs))
  Puny.go(1n+List.length(&2, U32, cs), cs, len,
    Pc{0, 72, b, b, 128, Puny.basic(cs) ++ Bool.pick(String, U32.is_zero(b), "", "-")})

# Labels
# ------

def Idna.codes(s: String) -> List<&2, U32>:
  match s:
    case SNil{}:
      Nil{}
    case SCon{Chr{+c}, t}:
      Puny.pick((c >= 65 && c <= 90 : U32), (c + 32 : U32), c) <> Idna.codes(t)

def Idna.ascii(s: String) -> Bool:
  match s:
    case SNil{}:
      True{}
    case SCon{Chr{+c}, t}:
      (c < 128 : U32) && Idna.ascii(t)

def Idna.label.at(ascii: Bool, l: String) -> String:
  match ascii:
    case True{}:
      l
    case False{}:
      "xn--" ++ Puny.encode(Idna.codes(l))

# A label as an A-label when it has non-ASCII, else as it is.
def Idna.label(+l: String) -> String:
  Idna.label.at(Idna.ascii(l), l)

def Idna.labels(ls: List<&2, String>) -> List<&2, String>:
  match ls:
    case Nil{}:
      Nil{}
    case Con{+l, t}:
      Idna.label(l) <> Idna.labels(t)

# A domain with every non-ASCII label as an A-label.
def Idna.domain(d: String) -> String:
  String.join(Idna.labels(String.split(d, '.')), ".")
