"""Checks a multipart message: structure, Bcc absent, attachments intact.

  check_parts.py FILE ATTACHMENT...
"""
import email, email.policy, hashlib, os, sys

raw = open(sys.argv[1], "rb").read()
files = sys.argv[2:]
for pol in (email.policy.strict, email.policy.compat32):
    m = email.message_from_bytes(raw, policy=pol)
    assert m.get_content_type() == "multipart/mixed", m.get_content_type()
    assert m["Bcc"] is None, "Bcc leaked into the headers"
    kinds = [p.get_content_type() for p in m.walk()]
    assert kinds[:4] == ["multipart/mixed", "multipart/alternative", "text/plain",
                         "text/html"], kinds
    got = {p.get_filename(): p.get_payload(decode=True) for p in m.walk()
           if p.get_filename()}
    for f in files:
        name = os.path.basename(f)
        assert name in got, "missing %r in %r" % (name, list(got))
        assert hashlib.sha256(got[name]).digest() == hashlib.sha256(open(f, "rb").read()).digest(), name
assert all(len(l) <= 998 for l in raw.split(b"\r\n"))
assert not m.defects
