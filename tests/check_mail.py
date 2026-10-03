"""Parses a received message strictly and checks it against expectations.

  check_mail.py FILE SUBJECT BODY CTE
"""
import email, email.policy, sys

path, subject, body, cte = sys.argv[1:5]
raw = open(path, "rb").read()
m = email.message_from_bytes(raw, policy=email.policy.strict)
lines = raw.split(b"\r\n")
assert all(len(l) <= 998 for l in lines), "a line is longer than 998 octets"
assert b"\n" not in raw.replace(b"\r\n", b""), "a bare LF"
assert all(b < 128 for b in raw), "the message is not 7-bit"
for h in ["Date", "From", "To", "Subject", "Message-ID", "MIME-Version"]:
    assert m[h] is not None, "no " + h
assert m["date"].datetime is not None, "a bad Date"
assert str(m["subject"]) == subject, "subject %r" % str(m["subject"])
assert m["content-transfer-encoding"] == cte, "CTE %s" % m["content-transfer-encoding"]
got = m.get_content().replace("\r\n", "\n").rstrip("\n")
assert got == body.rstrip("\n"), "body %r" % got
assert not m.defects and not any(getattr(m[h], "defects", None) for h in m.keys())
