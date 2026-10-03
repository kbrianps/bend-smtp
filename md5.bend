# MD5 (RFC 1321) and HMAC-MD5 (RFC 2104), for AUTH CRAM-MD5 (RFC 2195)
# only: MD5 is broken as a hash, and CRAM-MD5 is kept for old servers.
# Bytes are U32s below 256; a block is 16 little-endian words.
import Base

def Md5.pick(c: Bool, a: U32, b: U32) -> U32:
  match c:
    case True{}:
      a
    case False{}:
      b

# x rotated left by n bits (0 < n < 32).
def Md5.rotl(+x: U32, +n: U32) -> U32:
  U32.or(U32.shln(x, U32.to_nat(n)), U32.shrn(x, U32.to_nat((32 - n : U32))))

# The round constants: floor(2^32 * abs(sin(i + 1))).
def Md5.k() -> List<&2, U32>:
  [3614090360, 3905402710, 606105819, 3250441966, 4118548399, 1200080426,
    2821735955, 4249261313, 1770035416, 2336552879, 4294925233, 2304563134,
    1804603682, 4254626195, 2792965006, 1236535329, 4129170786, 3225465664,
    643717713, 3921069994, 3593408605, 38016083, 3634488961, 3889429448,
    568446438, 3275163606, 4107603335, 1163531501, 2850285829, 4243563512,
    1735328473, 2368359562, 4294588738, 2272392833, 1839030562, 4259657740,
    2763975236, 1272893353, 4139469664, 3200236656, 681279174, 3936430074,
    3572445317, 76029189, 3654602809, 3873151461, 530742520, 3299628645,
    4096336452, 1126891415, 2878612391, 4237533241, 1700485571, 2399980690,
    4293915773, 2240044497, 1873313359, 4264355552, 2734768916, 1309151649,
    4149444226, 3174756917, 718787259, 3951481745]

# The shift of step i.
def Md5.s(+i: U32) -> U32:
  +r = (i % 4 : U32)
  Md5.pick((i < 16 : U32),
    Md5.pick(U32.is_eq(r, 0), 7, Md5.pick(U32.is_eq(r, 1), 12, Md5.pick(U32.is_eq(r, 2), 17, 22))),
  Md5.pick((i < 32 : U32),
    Md5.pick(U32.is_eq(r, 0), 5, Md5.pick(U32.is_eq(r, 1), 9, Md5.pick(U32.is_eq(r, 2), 14, 20))),
  Md5.pick((i < 48 : U32),
    Md5.pick(U32.is_eq(r, 0), 4, Md5.pick(U32.is_eq(r, 1), 11, Md5.pick(U32.is_eq(r, 2), 16, 23))),
    Md5.pick(U32.is_eq(r, 0), 6, Md5.pick(U32.is_eq(r, 1), 10, Md5.pick(U32.is_eq(r, 2), 15, 21))))))

# The index of the message word step i reads.
def Md5.g(+i: U32) -> U32:
  Md5.pick((i < 16 : U32), i,
  Md5.pick((i < 32 : U32), ((5 * i + 1) % 16 : U32),
  Md5.pick((i < 48 : U32), ((3 * i + 5) % 16 : U32), ((7 * i) % 16 : U32))))

# The round function of step i.
def Md5.f(+i: U32, +b: U32, +c: U32, +d: U32) -> U32:
  Md5.pick((i < 16 : U32), U32.or(U32.and(b, c), U32.and(U32.not(b), d)),
  Md5.pick((i < 32 : U32), U32.or(U32.and(d, b), U32.and(U32.not(d), c)),
  Md5.pick((i < 48 : U32), U32.xor(b, U32.xor(c, d)),
    U32.xor(c, U32.or(b, U32.not(d))))))

def Md5.at.or(m: Maybe<&2, U32>) -> U32:
  match m:
    case None{}:
      0
    case Some{x}:
      x

def Md5.at(xs: List<&2, U32>, i: U32) -> U32:
  Md5.at.or(List.get(&2, U32, xs, U32.to_nat(i)))

# The four words of the state.
type Md5 is Data:
  Md5{a: U32, b: U32, c: U32, d: U32}

# The 64 steps over one block; ks: the constants still to use.
def Md5.steps(ks: List<&2, U32>, +i: U32, +m: List<&2, U32>, st: Md5) -> Md5:
  match ks:
    case Nil{}:
      st
    case Con{k, rest}:
      Md5{+a, +b, +c, +d} = st
      Md5.steps(rest, (i + 1 : U32), m, Md5{d,
        (b + Md5.rotl((a + Md5.f(i, b, c, d) + k + Md5.at(m, Md5.g(i)) : U32), Md5.s(i))
          : U32), b, c})

def Md5.sum(x: Md5, y: Md5) -> Md5:
  Md5{a, b, c, d} = x
  Md5{e, f, g, h} = y
  Md5{(a + e : U32), (b + f : U32), (c + g : U32), (d + h : U32)}

# The first 16 words of a byte list, and the bytes after them.
def Md5.words(n: Nat, bs: List<&2, U32>) -> List<&2, U32>:
  match n bs:
    case 1n+p Con{a, Con{b, Con{c, Con{d, rest}}}}:
      U32.or(U32.or(a, U32.shln(b, 8n)), U32.or(U32.shln(c, 16n), U32.shln(d, 24n)))
        <> Md5.words(p, rest)
    case _ _:
      Nil{}

# Every 64-byte block folded into the state; fuel: the block count.
def Md5.blocks(fuel: Nat, +bs: List<&2, U32>, +st: Md5) -> Md5:
  match fuel:
    case 0n:
      st
    case 1n+p:
      Md5.blocks(p, List.drop(&2, U32, bs, 64n),
        Md5.sum(st, Md5.steps(Md5.k(), 0, Md5.words(16n, bs), st)))

def Md5.zeros(n: Nat) -> List<&2, U32>:
  match n:
    case 0n:
      Nil{}
    case 1n+p:
      0 <> Md5.zeros(p)

# A word's four bytes, little-endian.
def Md5.le(+x: U32) -> List<&2, U32>:
  [U32.and(x, 255), U32.and(U32.shrn(x, 8n), 255), U32.and(U32.shrn(x, 16n), 255),
    U32.shrn(x, 24n)]

# The message padded: a 1 bit, zeros up to 56 mod 64, the bit length in
# 64 bits (messages here are far below 512 MB, so its high word is 0).
def Md5.pad(+bs: List<&2, U32>) -> List<&2, U32>:
  +n = U32.from_nat(List.length(&2, U32, bs))
  +z = ((119 - n % 64) % 64 : U32)
  List.append(&2, U32, bs, 128 <> List.append(&2, U32, Md5.zeros(U32.to_nat(z)),
    List.append(&2, U32, Md5.le((n * 8 : U32)), [0, 0, 0, 0])))

def Md5.out(st: Md5) -> List<&2, U32>:
  Md5{a, b, c, d} = st
  List.append(&2, U32, Md5.le(a), List.append(&2, U32, Md5.le(b),
    List.append(&2, U32, Md5.le(c), Md5.le(d))))

def Md5.run(+p: List<&2, U32>) -> List<&2, U32>:
  Md5.out(Md5.blocks(U32.to_nat((U32.from_nat(List.length(&2, U32, p)) / 64 : U32)),
    p, Md5{1732584193, 4023233417, 2562383102, 271733878}))

# The 16 bytes of the MD5 of bs.
def Md5.hash(bs: List<&2, U32>) -> List<&2, U32>:
  Md5.run(Md5.pad(bs))

# HMAC
# ----

def Md5.xors(bs: List<&2, U32>, +x: U32) -> List<&2, U32>:
  match bs:
    case Nil{}:
      Nil{}
    case Con{b, t}:
      U32.xor(b, x) <> Md5.xors(t, x)

# The key as one 64-byte block: hashed if longer, zero-filled if shorter.
def Md5.key(+k: List<&2, U32>) -> List<&2, U32>:
  +long = Nat.is_lt(64n, List.length(&2, U32, k))
  +k2 = Bool.pick(List<&2, U32>, long, Md5.hash(k), k)
  List.append(&2, U32, k2, Md5.zeros(Nat.sub(64n, List.length(&2, U32, k2))))

# HMAC-MD5 (RFC 2104): H((K xor opad) + H((K xor ipad) + text)).
def Md5.hmac(key: List<&2, U32>, text: List<&2, U32>) -> List<&2, U32>:
  +k = Md5.key(key)
  Md5.hash(List.append(&2, U32, Md5.xors(k, 92),
    Md5.hash(List.append(&2, U32, Md5.xors(k, 54), text))))

def Md5.digit(+d: U32) -> Char:
  Chr{Md5.pick((d < 10 : U32), (d + 48 : U32), (d + 87 : U32))}

# Bytes as lower-case hex.
def Md5.hex(bs: List<&2, U32>) -> String:
  match bs:
    case Nil{}:
      SNil{}
    case Con{+b, t}:
      SCon{Md5.digit(U32.shrn(b, 4n)), SCon{Md5.digit(U32.and(b, 15)), Md5.hex(t)}}
