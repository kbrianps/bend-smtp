# DKIM signing (RFC 6376; Ed25519 by RFC 8463): the header fields and
# the body are put in a canonical form, the body's SHA-256 goes in bh=,
# and the signature over the canonical fields (the DKIM-Signature itself
# last, with b= empty) goes in b=. The relaxed forms survive the
# rewrapping and trailing-space changes relays make; the simple ones
# take the text as it is. Fields are oversigned on request: named once
# more than they occur, so one added on the way breaks the signature.
#
# Not done, on purpose: the l= tag (a body length), which lets anyone
# append to a signed message (RFC 6376 8.2).
#
# The pure part (canonical forms, the field) is what LAWS.bend pins; the
# hash and the signature come from OpenSSL (net.c).
import Base
import ./text.bend as T

# The SHA-256 of a text's bytes, in base64.
def Dkim.sha256(data: String) -> IO(Result<&1, &1, U32 & String, String>):
  import "./net.c"
  import "./net.js"

# "rsa-sha256" or "ed25519-sha256", by the kind of the PEM private key.
def Dkim.alg(keyfile: String) -> IO(Result<&1, &1, U32 & String, String>):
  import "./net.c"
  import "./net.js"

# The signature of a text's bytes with the PEM private key, in base64.
def Dkim.sign(keyfile: String, data: String) ->
  IO(Result<&1, &1, U32 & String, String>):
  import "./net.c"
  import "./net.js"

# A header field: its name and its value as written (folds included).
type Field is Data:
  Field{name: String, value: String}

# A message cut at its first empty line.
type Cut is Data:
  Cut{head: String, body: String}

# Reading the message
# -------------------

# The header block (its last CRLF kept) and the body after the empty
# line; acc: the header so far, reversed.
def Dkim.cut(s: String, acc: String) -> Cut:
  match s:
    case SNil{}:
      Cut{T.Text.onto(acc, SNil{}), SNil{}}
    case SCon{Chr{13}, SCon{Chr{10}, SCon{Chr{13}, SCon{Chr{10}, rest}}}}:
      Cut{T.Text.onto(acc, "\r\n"), rest}
    case SCon{c, t}:
      Dkim.cut(t, SCon{c, acc})

def Dkim.field.of(parts: List<&2, String>) -> Field:
  match parts:
    case Con{n, rest}:
      Field{n, String.join(rest, ":")}
    case Nil{}:
      Field{"", ""}

def Dkim.wsp(+l: String) -> Bool:
  String.starts_with(l, " ") || String.starts_with(l, "\t")

def Dkim.fields.put(+cur: String, +acc: List<&2, Field>) -> List<&2, Field>:
  Bool.pick(List<&2, Field>, String.is_empty(cur), acc,
    Dkim.field.of(String.split(cur, ':')) <> acc)

# The lines of a header block as fields, last first: a line that starts
# with a space or a tab continues the field before it.
def Dkim.fields.go(ls: List<&2, String>, +cur: String, +acc: List<&2, Field>) ->
  List<&2, Field>:
  match ls:
    case Nil{}:
      Dkim.fields.put(cur, acc)
    case Con{+l, t}:
      Dkim.fields.go(t, Bool.pick(String, Dkim.wsp(l), cur ++ "\r\n" ++ l, l),
        Bool.pick(List<&2, Field>, Dkim.wsp(l), acc, Dkim.fields.put(cur, acc)))

def Dkim.uncr(s: String) -> String:
  match s:
    case SNil{}:
      SNil{}
    case SCon{Chr{13}, t}:
      Dkim.uncr(t)
    case SCon{c, t}:
      SCon{c, Dkim.uncr(t)}

# The fields of a header block, the last one first (the order DKIM
# signs repeated fields in, RFC 6376 5.4.2).
def Dkim.fields(head: String) -> List<&2, Field>:
  Dkim.fields.go(String.split(Dkim.uncr(head), '\n'), "", Nil{})

# Canonical forms (RFC 6376 3.4)
# ---------------

def Dkim.sp(yes: Bool, rest: String) -> String:
  match yes:
    case True{}:
      SCon{' ', rest}
    case False{}:
      rest

# A value unfolded, each run of spaces and tabs as one space, none at
# the start or the end; ws: a run is pending; start: nothing written yet.
def Dkim.value(s: String, ws: Bool, start: Bool) -> String:
  match s:
    case SNil{}:
      SNil{}
    case SCon{Chr{13}, t}:
      Dkim.value(t, ws, start)
    case SCon{Chr{10}, t}:
      Dkim.value(t, ws, start)
    case SCon{Chr{32}, t}:
      Dkim.value(t, True{}, start)
    case SCon{Chr{9}, t}:
      Dkim.value(t, True{}, start)
    case SCon{c, t}:
      Dkim.sp(ws && Bool.not(start), SCon{c, Dkim.value(t, False{}, False{})})

# A field in relaxed form: the name in lower case, a colon, the value.
def Dkim.relaxed(f: Field) -> String:
  Field{n, v} = f
  String.to_lower(String.trim(n)) ++ ":" ++ Dkim.value(v, False{}, True{})

# A field in simple form: as it is in the message (RFC 6376 3.4.1).
def Dkim.simple(f: Field) -> String:
  Field{n, v} = f
  n ++ ":" ++ v

def Dkim.field(relaxed: Bool, f: Field) -> String:
  match relaxed:
    case True{}:
      Dkim.relaxed(f)
    case False{}:
      Dkim.simple(f)

def Dkim.nls(n: Nat, acc: String) -> String:
  match n:
    case 0n:
      acc
    case 1n+p:
      Dkim.nls(p, SCon{Chr{10}, SCon{Chr{13}, acc}})

def Dkim.space(yes: Bool, acc: String) -> String:
  match yes:
    case True{}:
      SCon{' ', acc}
    case False{}:
      acc

def Dkim.body.end(acc: String) -> String:
  match acc:
    case SNil{}:
      SNil{}
    case SCon{c, t}:
      T.Text.onto(SCon{c, t}, "\r\n")

# A body in relaxed form: runs of spaces and tabs as one space, none at
# a line's end, no empty lines at the end, and a final CRLF (an empty
# body stays empty). ws: a run is pending; nl: line ends pending; acc:
# the output so far, reversed (a tail call per char).
def Dkim.body(s: String, ws: Bool, nl: Nat, acc: String) -> String:
  match s:
    case SNil{}:
      Dkim.body.end(acc)
    case SCon{Chr{13}, t}:
      Dkim.body(t, ws, nl, acc)
    case SCon{Chr{10}, t}:
      Dkim.body(t, False{}, 1n+nl, acc)
    case SCon{Chr{32}, t}:
      Dkim.body(t, True{}, nl, acc)
    case SCon{Chr{9}, t}:
      Dkim.body(t, True{}, nl, acc)
    case SCon{c, t}:
      Dkim.body(t, False{}, 0n, SCon{c, Dkim.space(ws, Dkim.nls(nl, acc))})

# A body in simple form (RFC 6376 3.4.3): as it is, but with no empty
# lines at the end and one final CRLF (an empty body is one CRLF). nl:
# line ends pending; acc: the output so far, reversed.
def Dkim.body.simple(s: String, nl: Nat, acc: String) -> String:
  match s:
    case SNil{}:
      T.Text.onto(acc, "\r\n")
    case SCon{Chr{13}, t}:
      Dkim.body.simple(t, nl, acc)
    case SCon{Chr{10}, t}:
      Dkim.body.simple(t, 1n+nl, acc)
    case SCon{c, t}:
      Dkim.body.simple(t, 0n, SCon{c, Dkim.nls(nl, acc)})

def Dkim.body.of(relaxed: Bool, s: String) -> String:
  match relaxed:
    case True{}:
      Dkim.body(s, False{}, 0n, SNil{})
    case False{}:
      Dkim.body.simple(s, 0n, SNil{})

# The field
# ---------

def Dkim.names.more(ns: List<&2, String>, +col: U32) -> String:
  match ns:
    case Nil{}:
      SNil{}
    case Con{+name, t}:
      +len = U32.from_nat(String.length(name))
      +wrap = (col + len > 68 : U32)
      ":" ++ Bool.pick(String, wrap, "\r\n ", "") ++ name
        ++ Dkim.names.more(t, U32.add(Bool.pick(U32, wrap, 1, col), U32.add(len, 1)))

# The h= tag's names, colon-separated, folded before column 70.
def Dkim.names(ns: List<&2, String>) -> String:
  match ns:
    case Nil{}:
      SNil{}
    case Con{+name, t}:
      name ++ Dkim.names.more(t, U32.add(U32.from_nat(String.length(name)), 3))

# Each field's name, in lower case.
def Dkim.named(fs: List<&2, Field>) -> List<&2, String>:
  match fs:
    case Nil{}:
      Nil{}
    case Con{f, t}:
      Field{n, _} = f
      String.to_lower(String.trim(n)) <> Dkim.named(t)

# The fields an added copy of which would mislead a reader: each is
# named once more in h= than it occurs (RFC 6376 5.4), present or not.
def Dkim.over() -> List<&2, String>:
  ["from", "to", "cc", "subject", "date", "reply-to", "message-id"]

def Dkim.c(relaxed: Bool) -> String:
  match relaxed:
    case True{}:
      "relaxed"
    case False{}:
      "simple"

# The DKIM-Signature's value up to "b=", its signature still to come.
# hr, br: relaxed header and body forms; over: the oversigned names.
def Dkim.tags(alg: String, hr: Bool, br: Bool, domain: String, selector: String,
  +t: U32, fs: List<&2, Field>, over: List<&2, String>, bh: String) -> String:
  "v=1; a=" ++ alg ++ "; c=" ++ Dkim.c(hr) ++ "/" ++ Dkim.c(br) ++ "; d="
    ++ T.Text.clean(domain) ++ "; s=" ++ T.Text.clean(selector) ++ ";\r\n t="
    ++ U32.show(t) ++ "; h=" ++ Dkim.names(List.append(&2, String, Dkim.named(fs), over))
    ++ ";\r\n bh=" ++ bh ++ ";\r\n b="

def Dkim.canon(+hr: Bool, fs: List<&2, Field>) -> String:
  match fs:
    case Nil{}:
      SNil{}
    case Con{f, t}:
      Dkim.field(hr, f) ++ "\r\n" ++ Dkim.canon(hr, t)

# What is signed: each field in canonical form with its CRLF, then the
# DKIM-Signature itself, b= empty and no CRLF (RFC 6376 3.7). An
# oversigned name with no field left adds nothing (5.4).
def Dkim.data(+hr: Bool, fs: List<&2, Field>, tags: String) -> String:
  Dkim.canon(hr, fs) ++ Dkim.field(hr, Field{"DKIM-Signature", " " ++ tags})

# The signature in lines of at most 72 digits.
def Dkim.fold(s: String, +col: U32) -> String:
  match s:
    case SNil{}:
      SNil{}
    case SCon{c, t}:
      +wrap = U32.is_eq(col, 72)
      Bool.pick(String, wrap, "\r\n ", "") ++ SCon{c, Dkim.fold(t, U32.add(
        Bool.pick(U32, wrap, 0, col), 1))}

# The whole field, ready to go in front of the message.
def Dkim.header(tags: String, sig: String) -> String:
  "DKIM-Signature: " ++ tags ++ Dkim.fold(sig, 2) ++ "\r\n"
