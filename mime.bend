# MIME and message format: UTF-8 bytes, base64 (RFC 4648), the Date
# header (RFC 5322 3.3), encoded words for non-ASCII subjects (RFC 2047)
# and a transfer encoding that keeps every line legal (RFC 2045, RFC
# 5322 2.1.1). The whole message comes out 7-bit ASCII, so it needs no
# 8BITMIME or SMTPUTF8 from the server.
import Base
import ./text.bend as T

def Word.pick(c: Bool, a: U32, b: U32) -> U32:
  match c:
    case True{}:
      a
    case False{}:
      b

# UTF-8
# -----

def Utf8.cont(+c: U32, n: Nat) -> U32:
  U32.or(128, U32.and(U32.shrn(c, n), 63))

# How many bytes a code point takes.
def Utf8.size(+c: U32) -> Nat:
  Bool.pick(Nat, (c < 128 : U32), 1n,
  Bool.pick(Nat, (c < 2048 : U32), 2n,
  Bool.pick(Nat, (c < 65536 : U32), 3n, 4n)))

def Utf8.put.k(k: Nat, +c: U32, rest: List<&2, U32>) -> List<&2, U32>:
  match k:
    case 1n:
      c <> rest
    case 2n:
      U32.or(192, U32.shrn(c, 6n)) <> Utf8.cont(c, 0n) <> rest
    case 3n:
      U32.or(224, U32.shrn(c, 12n)) <> Utf8.cont(c, 6n) <> Utf8.cont(c, 0n)
        <> rest
    case _:
      U32.or(240, U32.shrn(c, 18n)) <> Utf8.cont(c, 12n) <> Utf8.cont(c, 6n)
        <> Utf8.cont(c, 0n) <> rest

# One code point's bytes, put in front of rest.
def Utf8.put(+c: U32, rest: List<&2, U32>) -> List<&2, U32>:
  Utf8.put.k(Utf8.size(c), c, rest)

def Utf8.bytes(s: String) -> List<&2, U32>:
  match s:
    case SNil{}:
      Nil{}
    case SCon{Chr{c}, t}:
      Utf8.put(c, Utf8.bytes(t))

# Base64
# ------

# The base64 digit for 0..63.
def B64.ch(+i: U32) -> Char:
  Chr{Word.pick((i < 26 : U32), (i + 65 : U32),
    Word.pick((i < 52 : U32), (i + 71 : U32),
    Word.pick((i < 62 : U32), (i - 4 : U32),
    Word.pick(U32.is_eq(i, 62), 43, 47))))}

def B64.at(+x: U32, n: Nat) -> Char:
  B64.ch(U32.and(U32.shrn(x, n), 63))

# A group of 4 digits, the last `pad` of them "=".
def B64.quad(+x: U32, pad: Nat, rest: String) -> String:
  match pad:
    case 0n:
      SCon{B64.at(x, 18n), SCon{B64.at(x, 12n), SCon{B64.at(x, 6n),
        SCon{B64.at(x, 0n), rest}}}}
    case 1n:
      SCon{B64.at(x, 18n), SCon{B64.at(x, 12n), SCon{B64.at(x, 6n),
        SCon{'=', rest}}}}
    case _:
      SCon{B64.at(x, 18n), SCon{B64.at(x, 12n), SCon{'=', SCon{'=', rest}}}}

def B64.word(+a: U32, +b: U32, +c: U32) -> U32:
  U32.or(U32.shln(a, 16n), U32.or(U32.shln(b, 8n), c))

def B64.onto(acc: String, tail: String) -> String:
  match acc:
    case SNil{}:
      tail
    case SCon{c, t}:
      B64.onto(t, SCon{c, tail})

# The 4 digits of a group, reversed, on acc; pad of them "=".
def B64.quad.rev(+x: U32, pad: Nat, acc: String) -> String:
  match pad:
    case 0n:
      SCon{B64.at(x, 0n), SCon{B64.at(x, 6n), SCon{B64.at(x, 12n),
        SCon{B64.at(x, 18n), acc}}}}
    case 1n:
      SCon{'=', SCon{B64.at(x, 6n), SCon{B64.at(x, 12n), SCon{B64.at(x, 18n), acc}}}}
    case _:
      SCon{'=', SCon{'=', SCon{B64.at(x, 12n), SCon{B64.at(x, 18n), acc}}}}

# A CRLF (reversed) before the group when `wrap` groups fill the line.
def B64.brk(full: Bool, acc: String) -> String:
  match full:
    case True{}:
      SCon{Chr{10}, SCon{Chr{13}, acc}}
    case False{}:
      acc

# The digits of bs, in front of tail; k groups are on the current line,
# and a line takes `wrap` groups (0: one line). acc holds the digits so
# far, reversed: one tail call per group, then one pass onto the tail.
def B64.go(bs: List<&2, U32>, +k: U32, +wrap: U32, acc: String, tail: String) ->
  String:
  match bs:
    case Nil{}:
      B64.onto(acc, tail)
    case Con{a, Con{b, Con{c, rest}}}:
      +full = (wrap > 0 && k >= wrap : U32)
      B64.go(rest, Word.pick(full, 1, (k + 1 : U32)), wrap,
        B64.quad.rev(B64.word(a, b, c), 0n, B64.brk(full, acc)), tail)
    case Con{a, Con{b, Nil{}}}:
      B64.onto(B64.quad.rev(B64.word(a, b, 0), 1n,
        B64.brk((wrap > 0 && k >= wrap : U32), acc)), tail)
    case Con{a, Nil{}}:
      B64.onto(B64.quad.rev(B64.word(a, 0, 0), 2n,
        B64.brk((wrap > 0 && k >= wrap : U32), acc)), tail)

def B64.encode(bs: List<&2, U32>) -> String:
  B64.go(bs, 0, 0, SNil{}, SNil{})

# Base64 in lines of 76 digits (19 groups), as MIME bodies need, then
# tail.
def B64.lines(bs: List<&2, U32>, tail: String) -> String:
  B64.go(bs, 0, 19, SNil{}, tail)

def B64.text(s: String) -> String:
  B64.encode(Utf8.bytes(s))

# Date
# ----

def Date.pad(+n: U32) -> String:
  Bool.pick(String, (n < 10 : U32), "0" ++ U32.show(n), U32.show(n))

def Date.day(+w: U32) -> String:
  Bool.pick(String, U32.is_eq(w, 0), "Sun",
  Bool.pick(String, U32.is_eq(w, 1), "Mon",
  Bool.pick(String, U32.is_eq(w, 2), "Tue",
  Bool.pick(String, U32.is_eq(w, 3), "Wed",
  Bool.pick(String, U32.is_eq(w, 4), "Thu",
  Bool.pick(String, U32.is_eq(w, 5), "Fri", "Sat"))))))

def Date.month(+m: U32) -> String:
  Bool.pick(String, U32.is_eq(m, 1), "Jan",
  Bool.pick(String, U32.is_eq(m, 2), "Feb",
  Bool.pick(String, U32.is_eq(m, 3), "Mar",
  Bool.pick(String, U32.is_eq(m, 4), "Apr",
  Bool.pick(String, U32.is_eq(m, 5), "May",
  Bool.pick(String, U32.is_eq(m, 6), "Jun",
  Bool.pick(String, U32.is_eq(m, 7), "Jul",
  Bool.pick(String, U32.is_eq(m, 8), "Aug",
  Bool.pick(String, U32.is_eq(m, 9), "Sep",
  Bool.pick(String, U32.is_eq(m, 10), "Oct",
  Bool.pick(String, U32.is_eq(m, 11), "Nov", "Dec")))))))))))

# Year, month and day of a day count since 1970-01-01 (H. Hinnant's
# civil_from_days, for days >= 0), as "DD Mon YYYY".
def Date.civil(+days: U32) -> String:
  +z   = (days + 719468 : U32)
  +era = (z / 146097 : U32)
  +doe = (z - era * 146097 : U32)
  +yoe = ((doe - doe / 1460 + doe / 36524 - doe / 146096) / 365 : U32)
  +doy = (doe - (365 * yoe + yoe / 4 - yoe / 100) : U32)
  +mp  = ((5 * doy + 2) / 153 : U32)
  +d   = (doy - (153 * mp + 2) / 5 + 1 : U32)
  +m   = Word.pick((mp < 10 : U32), (mp + 3 : U32), (mp - 9 : U32))
  +y   = (yoe + era * 400 + Word.pick((m <= 2 : U32), 1, 0) : U32)
  Date.pad(d) ++ " " ++ Date.month(m) ++ " " ++ U32.show(y)

# The Date header's value for t seconds since 1970, in UTC.
def Date.fmt(+t: U32) -> String:
  +days = (t / 86400 : U32)
  +secs = (t % 86400 : U32)
  Date.day(((days + 4) % 7 : U32)) ++ ", " ++ Date.civil(days) ++ " "
    ++ Date.pad((secs / 3600 : U32)) ++ ":"
    ++ Date.pad(((secs % 3600) / 60 : U32)) ++ ":"
    ++ Date.pad((secs % 60 : U32)) ++ " +0000"

# Subject (RFC 2047)
# -------

# Whether every char is printable ASCII (space to tilde).
def Mime.printable(s: String) -> Bool:
  match s:
    case SNil{}:
      True{}
    case SCon{Chr{+c}, t}:
      (c >= 32 && c <= 126 : U32) && Mime.printable(t)

# Encoded words built so far, the bytes of the current one and its size.
type Words is Data:
  Words{out: String, cur: List<&2, U32>, n: U32}

def Mime.word(cur: List<&2, U32>) -> String:
  "=?UTF-8?B?" ++ B64.encode(cur) ++ "?="

# 39 bytes make 52 digits: "Subject: " plus one word is 73 columns.
def Mime.add.at(full: Bool, out: String, cur: List<&2, U32>, +n: U32,
  bc: List<&2, U32>, +k: U32) -> Words:
  match full:
    case True{}:
      Words{out ++ Mime.word(cur) ++ "\r\n ", bc, k}
    case False{}:
      Words{out, List.append(&2, U32, cur, bc), (n + k : U32)}

def Mime.add(w: Words, +c: U32) -> Words:
  Words{out, cur, +n} = w
  +k = U32.from_nat(Utf8.size(c))
  Mime.add.at((n > 0 && n + k > 39 : U32), out, cur, n, Utf8.put(c, Nil{}), k)

def Mime.words(s: String, w: Words) -> String:
  match s:
    case SNil{}:
      Words{out, cur, _} = w
      out ++ Mime.word(cur)
    case SCon{Chr{c}, t}:
      Mime.words(t, Mime.add(w, c))

# s as RFC 2047 encoded words of at most 39 bytes each, folded.
def Mime.encoded(s: String) -> String:
  Mime.words(s, Words{"", Nil{}, 0})

def Mime.subject.at(plain: Bool, s: String) -> String:
  match plain:
    case True{}:
      s
    case False{}:
      Mime.encoded(s)

# A Subject value: as is when it is printable ASCII that fits one line
# and cannot read as an encoded word, else encoded words, folded.
def Mime.subject(+s: String) -> String:
  Mime.subject.at(Mime.printable(s) && Bool.not(String.contains(s, "=?"))
    && Nat.is_le(String.length(s), 69n), s)

# Body
# ----

# Line breaks as CRLF, bare CRs dropped.
def Mime.crlf(s: String) -> String:
  match s:
    case SNil{}:
      SNil{}
    case SCon{Chr{13}, t}:
      Mime.crlf(t)
    case SCon{Chr{10}, t}:
      SCon{Chr{13}, SCon{Chr{10}, Mime.crlf(t)}}
    case SCon{c, t}:
      SCon{c, Mime.crlf(t)}

# Whether the body can go as 7bit: ASCII without NUL, and no line past
# 998 chars (RFC 5322 2.1.1); col counts the current line.
def Mime.seven(s: String, +col: U32) -> Bool:
  match s:
    case SNil{}:
      True{}
    case SCon{Chr{10}, t}:
      Mime.seven(t, 0)
    case SCon{Chr{13}, t}:
      Mime.seven(t, col)
    case SCon{Chr{+c}, t}:
      (c >= 1 && c <= 127 && col < 998 : U32) && Mime.seven(t, (col + 1 : U32))

# The body's transfer encoding and its text: 7bit as written, else
# base64 of its UTF-8 (CRLF line breaks first, RFC 2045 6.8).
type Body is Data:
  Body{encoding: String, text: String}

def Mime.body.at(seven: Bool, s: String) -> Body:
  match seven:
    case True{}:
      Body{"7bit", Mime.crlf(s)}
    case False{}:
      Body{"base64", B64.lines(Utf8.bytes(Mime.crlf(s)), "\r\n")}

# Text goes 7bit only if it cannot hold a part boundary (Mime.boundary).
def Mime.body(+s: String) -> Body:
  Mime.body.at(Mime.seven(s, 0) && Bool.not(String.contains(s, "=_bend_")), s)

# Base64 decoding
# ---------------

# A base64 digit's value, or 64 for anything else.
def B64.val(+c: U32) -> U32:
  Word.pick((c >= 65 && c <= 90 : U32), (c - 65 : U32),
  Word.pick((c >= 97 && c <= 122 : U32), (c - 71 : U32),
  Word.pick((c >= 48 && c <= 57 : U32), (c + 4 : U32),
  Word.pick(U32.is_eq(c, 43), 62, Word.pick(U32.is_eq(c, 47), 63, 64)))))

def B64.keep(ok: Bool, v: U32, rest: List<&2, U32>) -> List<&2, U32>:
  match ok:
    case True{}:
      v <> rest
    case False{}:
      rest

def B64.vals(s: String) -> List<&2, U32>:
  match s:
    case SNil{}:
      Nil{}
    case SCon{Chr{c}, t}:
      +v = B64.val(c)
      B64.keep((v < 64 : U32), v, B64.vals(t))

def B64.byte(+x: U32, n: Nat) -> U32:
  U32.and(U32.shrn(x, n), 255)

def B64.group(+a: U32, +b: U32, +c: U32, +d: U32) -> U32:
  U32.or(U32.or(U32.shln(a, 18n), U32.shln(b, 12n)), U32.or(U32.shln(c, 6n), d))

def B64.bytes(vs: List<&2, U32>) -> List<&2, U32>:
  match vs:
    case Con{a, Con{b, Con{c, Con{d, rest}}}}:
      +x = B64.group(a, b, c, d)
      B64.byte(x, 16n) <> B64.byte(x, 8n) <> B64.byte(x, 0n) <> B64.bytes(rest)
    case Con{a, Con{b, Con{c, Nil{}}}}:
      +x = B64.group(a, b, c, 0)
      [B64.byte(x, 16n), B64.byte(x, 8n)]
    case Con{a, Con{b, Nil{}}}:
      [B64.byte(B64.group(a, b, 0, 0), 16n)]
    case _:
      Nil{}

# The bytes of base64 text; padding and anything off the alphabet skipped.
def B64.decode(s: String) -> List<&2, U32>:
  B64.bytes(B64.vals(s))

# Bytes as text: ASCII as is, any other byte as "?" (for error messages).
def B64.ascii(bs: List<&2, U32>) -> String:
  match bs:
    case Nil{}:
      SNil{}
    case Con{+b, t}:
      SCon{Chr{Word.pick((b < 128 : U32), b, 63)}, B64.ascii(t)}

# Parts
# -----

# An attachment: its file name, content type and bytes.
type Part is Data:
  Part{name: String, ctype: String, data: List<&2, U32>}

def Mime.ext.is(+name: String, e: String) -> Bool:
  String.ends_with(String.to_lower(name), e)

# A content type from the file name's extension (application/octet-stream
# when unknown). message/rfc822 is never used: it may not be base64.
def Mime.ctype(+n: String) -> String:
  Bool.pick(String, Mime.ext.is(n, ".pdf"), "application/pdf",
  Bool.pick(String, Mime.ext.is(n, ".png"), "image/png",
  Bool.pick(String, Mime.ext.is(n, ".jpg") || Mime.ext.is(n, ".jpeg"), "image/jpeg",
  Bool.pick(String, Mime.ext.is(n, ".gif"), "image/gif",
  Bool.pick(String, Mime.ext.is(n, ".webp"), "image/webp",
  Bool.pick(String, Mime.ext.is(n, ".svg"), "image/svg+xml",
  Bool.pick(String, Mime.ext.is(n, ".txt"), "text/plain",
  Bool.pick(String, Mime.ext.is(n, ".md"), "text/markdown",
  Bool.pick(String, Mime.ext.is(n, ".csv"), "text/csv",
  Bool.pick(String, Mime.ext.is(n, ".html") || Mime.ext.is(n, ".htm"), "text/html",
  Bool.pick(String, Mime.ext.is(n, ".json"), "application/json",
  Bool.pick(String, Mime.ext.is(n, ".xml"), "application/xml",
  Bool.pick(String, Mime.ext.is(n, ".zip"), "application/zip",
  Bool.pick(String, Mime.ext.is(n, ".gz"), "application/gzip",
  Bool.pick(String, Mime.ext.is(n, ".mp3"), "audio/mpeg",
  Bool.pick(String, Mime.ext.is(n, ".wav"), "audio/wav",
  Bool.pick(String, Mime.ext.is(n, ".mp4"), "video/mp4",
  Bool.pick(String, Mime.ext.is(n, ".docx"),
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  Bool.pick(String, Mime.ext.is(n, ".xlsx"),
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  Bool.pick(String, Mime.ext.is(n, ".pptx"),
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
  Bool.pick(String, Mime.ext.is(n, ".odt"), "application/vnd.oasis.opendocument.text",
    "application/octet-stream")))))))))))))))))))))

# attr-char (RFC 2231 7): ALPHA DIGIT !#$&+-.^_`|~.
def Mime.attr(+c: U32) -> Bool:
  (c >= 97 && c <= 122 || c >= 65 && c <= 90 || c >= 48 && c <= 57 : U32)
    || U32.is_eq(c, 33) || U32.is_eq(c, 35) || U32.is_eq(c, 36)
    || U32.is_eq(c, 38) || U32.is_eq(c, 43) || U32.is_eq(c, 45)
    || U32.is_eq(c, 46) || U32.is_eq(c, 94) || U32.is_eq(c, 95)
    || U32.is_eq(c, 96) || U32.is_eq(c, 124) || U32.is_eq(c, 126)

def Mime.hex(+d: U32) -> Char:
  Chr{Word.pick((d < 10 : U32), (d + 48 : U32), (d + 55 : U32))}

def Mime.pct.at(keep: Bool, +b: U32, rest: String) -> String:
  match keep:
    case True{}:
      SCon{Chr{b}, rest}
    case False{}:
      SCon{'%', SCon{Mime.hex(U32.shrn(b, 4n)), SCon{Mime.hex(U32.and(b, 15)), rest}}}

# Bytes percent-encoded outside attr-char (RFC 2231 4).
def Mime.pct(bs: List<&2, U32>) -> String:
  match bs:
    case Nil{}:
      SNil{}
    case Con{+b, t}:
      Mime.pct.at(Mime.attr(b), b, Mime.pct(t))

def Mime.safe(s: String) -> Bool:
  match s:
    case SNil{}:
      True{}
    case SCon{Chr{+c}, t}:
      (c >= 32 && c <= 126 : U32) && Bool.not(U32.is_eq(c, 34))
        && Bool.not(U32.is_eq(c, 92)) && Mime.safe(t)

def Mime.param.at(safe: Bool, +key: String, +n: String) -> String:
  match safe:
    case True{}:
      ";\r\n " ++ key ++ "=\"" ++ n ++ "\""
    case False{}:
      ";\r\n " ++ key ++ "*=UTF-8''" ++ Mime.pct(Utf8.bytes(n))

# A file name parameter: quoted when the name is safe ASCII, else only
# in RFC 2231's extended form (as Python's email package writes it: a
# second, ASCII form would be read first by some parsers).
def Mime.param(+key: String, +n: String) -> String:
  Mime.param.at(Mime.safe(n), key, n)

# Entities
# --------

# A text leaf: its headers, a blank line, its body.
def Mime.leaf.with(ctype: String, b: Body) -> String:
  Body{enc, text} = b
  "Content-Type: " ++ ctype ++ "; charset=UTF-8\r\n"
    ++ "Content-Transfer-Encoding: " ++ enc ++ "\r\n\r\n" ++ text

def Mime.leaf(ctype: String, +s: String) -> String:
  Mime.leaf.with(ctype, Mime.body(s))

# token chars (RFC 2045 5.1): printable ASCII but space and the
# tspecials ()<>@,;:\"/[]?=.
def Mime.token.ch(+c: U32) -> Bool:
  (c > 32 && c < 127 : U32) && Bool.not(U32.is_eq(c, 40) || U32.is_eq(c, 41)
    || U32.is_eq(c, 60) || U32.is_eq(c, 62) || U32.is_eq(c, 64) || U32.is_eq(c, 44)
    || U32.is_eq(c, 59) || U32.is_eq(c, 58) || U32.is_eq(c, 92) || U32.is_eq(c, 34)
    || U32.is_eq(c, 47) || U32.is_eq(c, 91) || U32.is_eq(c, 93) || U32.is_eq(c, 63)
    || U32.is_eq(c, 61))

def Mime.token(s: String) -> Bool:
  match s:
    case SNil{}:
      True{}
    case SCon{Chr{c}, t}:
      Mime.token.ch(c) && Mime.token(t)

def Mime.ctype.parts(ps: List<&2, String>) -> Bool:
  match ps:
    case Con{+a, Con{+b, Nil{}}}:
      Bool.not(String.is_empty(a)) && Bool.not(String.is_empty(b)) && Mime.token(a)
        && Mime.token(b)
    case _:
      False{}

# Whether s is a bare content type, "type/subtype" in tokens: no
# parameters, no spaces, nothing that could end the header line.
def Mime.ctype.ok(s: String) -> Bool:
  Mime.ctype.parts(String.split(s, '/'))

# The type as it goes in the header: itself when it is a bare content
# type, else application/octet-stream; and no CR or LF either way.
def Mime.ctype.safe(+s: String) -> String:
  T.Text.clean(Bool.pick(String, Mime.ctype.ok(s), s, "application/octet-stream"))

# The first attachment type that is not a bare content type, or "".
def Mime.ctype.bad(fs: List<&2, Part>) -> String:
  match fs:
    case Nil{}:
      ""
    case Con{f, t}:
      Part{_, +ctype, _} = f
      Bool.pick(String, Mime.ctype.ok(ctype), Mime.ctype.bad(t),
        Bool.pick(String, String.is_empty(ctype), "(empty)", T.Text.clean(ctype)))

# An attachment leaf, always base64, in front of rest.
def Mime.attach(p: Part, rest: String) -> String:
  Part{+name, ctype, data} = p
  "Content-Type: " ++ Mime.ctype.safe(ctype) ++ Mime.param("name", name) ++ "\r\n"
    ++ "Content-Disposition: attachment" ++ Mime.param("filename", name) ++ "\r\n"
    ++ "Content-Transfer-Encoding: base64\r\n\r\n" ++ B64.lines(data, "\r\n" ++ rest)

def Mime.parts(+b: String, ps: List<&2, String>) -> String:
  match ps:
    case Nil{}:
      "\r\n--" ++ b ++ "--\r\n"
    case Con{p, t}:
      "\r\n--" ++ b ++ "\r\n" ++ p ++ Mime.parts(b, t)

def Mime.preamble() -> String:
  "This is a multi-part message in MIME format."

# A multipart entity (RFC 2046 5.1): a boundary that no part can hold,
# then each part after a delimiter line, then the close delimiter.
def Mime.multi(sub: String, +b: String, ps: List<&2, String>) -> String:
  "Content-Type: multipart/" ++ sub ++ ";\r\n boundary=\"" ++ b ++ "\"\r\n\r\n"
    ++ Mime.preamble() ++ Mime.parts(b, ps)

# The files as parts, each after its delimiter, then the close one.
def Mime.attaches(fs: List<&2, Part>, +b: String) -> String:
  match fs:
    case Nil{}:
      "\r\n--" ++ b ++ "--\r\n"
    case Con{f, t}:
      "\r\n--" ++ b ++ "\r\n" ++ Mime.attach(f, Mime.attaches(t, b))

def Mime.alt.at(none: Bool, text: String, html: String, +b: String) -> String:
  match none:
    case True{}:
      Mime.leaf("text/plain", text)
    case False{}:
      Mime.multi("alternative", b ++ "_a", [Mime.leaf("text/plain", text),
        Mime.leaf("text/html", html)])

def Mime.mixed.at(none: Bool, alt: String, files: List<&2, Part>, +b: String) ->
  String:
  match none:
    case True{}:
      alt
    case False{}:
      +bm = b ++ "_m"
      "Content-Type: multipart/mixed;\r\n boundary=\"" ++ bm ++ "\"\r\n\r\n"
        ++ Mime.preamble() ++ "\r\n--" ++ bm ++ "\r\n" ++ alt
        ++ Mime.attaches(files, bm)

# The message's entity: text alone; text and HTML as alternatives
# (plain first, RFC 2046 5.1.4); either one with files as mixed. b is
# the boundary stem: base64 and the 7bit texts (Mime.body) cannot hold it.
def Mime.entity(text: String, +html: String, +files: List<&2, Part>, +b: String) ->
  String:
  Mime.mixed.at(List.is_empty(&2, Part, files),
    Mime.alt.at(String.is_empty(html), text, html, b), files, b)

# A boundary stem from random words: "=_bend_" and hex.
def Mime.boundary(+hex: String) -> String:
  "=_bend_" ++ hex
