"""Verifies a message's DKIM-Signature against a private key's public half.

  dkim_verify.py MESSAGE KEY.pem

Uses dkimpy when it is installed; else its own reading of RFC 6376
(relaxed/relaxed only) over the `cryptography` package. Exit 0 if valid.
"""
import base64, hashlib, re, subprocess, sys

raw = open(sys.argv[1], "rb").read()
keyfile = sys.argv[2]
pub_der = subprocess.run(["openssl", "pkey", "-in", keyfile, "-pubout", "-outform", "DER"],
                         capture_output=True, check=True).stdout


def own():
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
    head, _, body = raw.partition(b"\r\n\r\n")
    fields = []
    for l in head.split(b"\r\n"):
        if l[:1] in (b" ", b"\t"):
            fields[-1] += b"\r\n" + l
        else:
            fields.append(l)

    def relax(f):
        n, v = f.split(b":", 1)
        v = re.sub(rb"[ \t]+", b" ", v.replace(b"\r\n", b"")).strip(b" ")
        return n.strip().lower() + b":" + v

    sig = next(f for f in fields if f.lower().startswith(b"dkim-signature:"))
    tags = dict(t.strip().split("=", 1) for t in
                re.sub(r"\s+", " ", sig.split(b":", 1)[1].decode()).split(";") if "=" in t)
    assert tags["c"] == "relaxed/relaxed", tags["c"]
    lines = [re.sub(rb"[ \t]+", b" ", l).rstrip(b" ") for l in body.split(b"\r\n")]
    while lines and lines[-1] == b"":
        lines.pop()
    cbody = b"".join(l + b"\r\n" for l in lines)
    bh = base64.b64encode(hashlib.sha256(cbody).digest()).decode()
    if bh != tags["bh"].replace(" ", ""):
        return False
    pool = [f for f in fields if f is not sig]
    data = b""
    for name in tags["h"].replace(" ", "").split(":"):
        for i in range(len(pool) - 1, -1, -1):
            if pool[i].split(b":", 1)[0].strip().lower() == name.lower().encode():
                data += relax(pool.pop(i)) + b"\r\n"
                break
    data += relax(re.sub(rb"b=[^;]*$", b"b=", sig, flags=re.S))
    signature = base64.b64decode(tags["b"].replace(" ", ""))
    key = serialization.load_der_public_key(pub_der)
    try:
        if isinstance(key, rsa.RSAPublicKey):
            assert tags["a"] == "rsa-sha256"
            key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        elif isinstance(key, ed25519.Ed25519PublicKey):
            assert tags["a"] == "ed25519-sha256"
            key.verify(signature, hashlib.sha256(data).digest())
        else:
            return False
    except Exception:
        return False
    return True


def third_party():
    import dkim
    kind = "ed25519" if len(pub_der) == 44 else "rsa"
    p = base64.b64encode(pub_der[-32:] if kind == "ed25519" else pub_der).decode()
    txt = ("v=DKIM1; k=%s; p=%s" % (kind, p)).encode()
    return dkim.verify(raw, dnsfunc=lambda name, timeout=5: txt)


ran, ok = 0, True
for check in (own, third_party):
    try:
        ok = check() and ok
        ran += 1
    except ImportError:
        pass
if ran == 0:
    sys.exit("dkim_verify: neither cryptography nor dkimpy is installed")
sys.exit(0 if ok else 1)
