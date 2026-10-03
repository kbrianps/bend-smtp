# The laws of bend-smtp: the claims PROOF.bend must prove. The human
# writes these; `bend PROOF.bend` fails while any is open or false.
import Base
import ./text.bend as T
import ./reply.bend as R
import ./smtp.bend as S
import ./sink.bend as K
import ./mime.bend as M
import ./idna.bend as I
import ./addr.bend as A

# Injection
# ---------

# LAW: a cleaned field holds no CR or LF, for every string. Every
# address and header goes through Text.clean, so no field can start a
# new SMTP command or a new header line.
law clean_safe:
  for s: String
  {T.Text.has_nl(T.Text.clean(s)) == False{} : Bool}

# LAW: a subject that tries to add a header stays one header.
law subject_one_line:
  {T.Text.clean("Hi\r\nBcc: x@y") == "HiBcc: x@y" : String}

# Replies
# -------

# LAW: a multi-line reply is read whole, its lines joined, and what
# follows it is kept for the next read.
law reply_multiline:
  {R.Reply.split("250-mx\r\n250-8BITMIME\r\n250 SIZE 9\r\nnext")
    == R.Got{R.Reply{250, "mx\n8BITMIME\nSIZE 9"}, "next"} : R.Split}

# LAW: a reply cut mid-way waits for more, keeping every byte.
law reply_partial:
  {R.Reply.split("250-mx\r\n25") == R.More{"250-mx\r\n25"} : R.Split}

# LAW: a line with no 3-digit code is a broken reply (code 0).
law reply_broken:
  {R.Reply.split("hello\r\n") == R.Got{R.Reply{0, ""}, ""} : R.Split}

# The message
# -----------

# LAW: line ends become CRLF, a leading dot is doubled, and the
# message ends with the lone-dot line.
law data_stuffed:
  {S.Smtp.data("a\n.b\n") == "a\r\n..b\r\n.\r\n" : String}

# Encodings
# ---------

# LAW: base64 matches RFC 4648's test vectors (section 10).
law base64_vectors:
  {[M.B64.text(""), M.B64.text("f"), M.B64.text("fo"), M.B64.text("foo"),
    M.B64.text("foob"), M.B64.text("fooba"), M.B64.text("foobar")]
    == ["", "Zg==", "Zm8=", "Zm9v", "Zm9vYg==", "Zm9vYmE=", "Zm9vYmFy"]
    : List<String>}

# LAW: text is base64'd as UTF-8, up to 4-byte code points.
law base64_utf8:
  {M.B64.text("ção ✓ 😀") == "w6fDo28g4pyTIPCfmIA=" : String}

# LAW: AUTH PLAIN carries NUL user NUL password (RFC 4616 section 4's
# example: tim / tanstaaftanstaaf).
law auth_plain:
  {S.Smtp.plain("tim", "tanstaaftanstaaf")
    == "AUTH PLAIN AHRpbQB0YW5zdGFhZnRhbnN0YWFm\r\n" : String}

# LAW: the Date header, in UTC, across the epoch, a leap day and today.
law date_header:
  {[M.Date.fmt(0), M.Date.fmt(951782400), M.Date.fmt(1790984246)]
    == ["Thu, 01 Jan 1970 00:00:00 +0000", "Tue, 29 Feb 2000 00:00:00 +0000",
      "Fri, 02 Oct 2026 23:37:26 +0000"] : List<String>}

# LAW: a printable ASCII subject goes as is; one with non-ASCII, or with
# "=?" (which could read as an encoded word), goes as RFC 2047 words.
law subject_encoding:
  {[M.Mime.subject("Oi tudo bem"), M.Mime.subject("Olá"), M.Mime.subject("a =? b")]
    == ["Oi tudo bem", "=?UTF-8?B?T2zDoQ==?=", "=?UTF-8?B?YSA9PyBi?="]
    : List<String>}

# LAW: a long subject is split into encoded words of at most 39 bytes,
# never inside a character, folded onto lines of their own.
law subject_folds:
  {M.Mime.subject("Relatório de manutenção das câmeras do cliente")
    == "=?UTF-8?B?UmVsYXTDs3JpbyBkZSBtYW51dGVuw6fDo28gZGFzIGPDom1lcmFz?=\r\n =?UTF-8?B?IGRvIGNsaWVudGU=?="
    : String}

# LAW: an ASCII body with short lines goes as 7bit; non-ASCII goes as
# base64 of its UTF-8 with CRLF line breaks.
law body_encoding:
  {[M.Mime.body("a\nb"), M.Mime.body("olá\n")]
    == [M.Body{"7bit", "a\r\nb"}, M.Body{"base64", "b2zDoQ0K\r\n"}] : List<M.Body>}

# LAW: a line past 998 chars cannot go as 7bit (RFC 5322 2.1.1).
law body_long_line:
  {M.Mime.seven(String.repeat("a", 999n), 0) == False{} : Bool}

# Commands and capabilities
# -------------------------

# LAW: MAIL declares the message size only when the server announced
# SIZE (RFC 1870), and SMTPUTF8 (with BODY=8BITMIME when offered) only
# when the message needs it (RFC 6531 3.4).
law mail_params:
  {[S.Smtp.mail("a@b.c", 1000, 42, False{}, True{}),
    S.Smtp.mail("a@b.c", 0, 42, False{}, True{}),
    S.Smtp.mail("joão@b.c", 0, 42, True{}, True{}),
    S.Smtp.mail("joão@b.c", 0, 42, True{}, False{})]
    == ["MAIL FROM:<a@b.c> SIZE=42\r\n", "MAIL FROM:<a@b.c>\r\n",
      "MAIL FROM:<joão@b.c> SMTPUTF8 BODY=8BITMIME\r\n",
      "MAIL FROM:<joão@b.c> SMTPUTF8\r\n"] : List<String>}

# LAW: EHLO's lines give STARTTLS, the AUTH mechanisms (also in the old
# "AUTH=" spelling) and SIZE; the first line is only the server's name.
law ehlo_caps:
  {[S.Caps.of("mx.example STARTTLS\nstarttls\nAUTH LOGIN PLAIN XOAUTH2\nSIZE 35882577\nSMTPUTF8\n8BITMIME"),
    S.Caps.of("mx\nAUTH=LOGIN\n8BITMIME"), S.Caps.of("mx\nSIZE")]
    == [S.Caps{True{}, ["LOGIN", "PLAIN", "XOAUTH2"], 35882577, True{}, True{}},
      S.Caps{False{}, ["LOGIN"], 0, False{}, True{}},
      S.Caps{False{}, [], 0, False{}, False{}}]
    : List<S.Caps>}

# LAW: addresses are dot-atom local@domain; anything that could break
# out of the <...> of MAIL or RCPT is refused.
law addresses:
  {[A.Addr.ok("me@example.com"), A.Addr.ok("a.b+tag@sub.example.org"),
    A.Addr.ok("joão@exemplo.com.br"), A.Addr.ok("a@b>c"),
    A.Addr.ok("a@b\r\nRCPT TO:<x@y>"), A.Addr.ok("a..b@c"), A.Addr.ok(".a@b"),
    A.Addr.ok("a@b@c"), A.Addr.ok("a b@c"), A.Addr.ok("@b"), A.Addr.ok("a@")]
    == [True{}, True{}, True{}, False{}, False{}, False{}, False{}, False{},
      False{}, False{}, False{}] : List<Bool>}

# Internationalized addresses
# ---------------------------

# LAW: Punycode matches RFC 3492's examples and other scripts.
law punycode:
  {[I.Idna.domain("bücher.example"), I.Idna.domain("münchen.de"),
    I.Idna.domain("例え.テスト"), I.Idna.domain("пример.рф"),
    I.Idna.domain("Example.COM")]
    == ["xn--bcher-kva.example", "xn--mnchen-3ya.de", "xn--r8jz45g.xn--zckzah",
      "xn--e1afmkfd.xn--p1ai", "Example.COM"] : List<String>}

# LAW: only a non-ASCII local part needs SMTPUTF8; a non-ASCII domain
# alone travels as A-labels, and then the whole message stays ASCII.
law needs_smtputf8:
  {[S.Mail.utf8(S.Mail{A.Mbox{"", "a@b.c"}, [A.Mbox{"João", "joão@exemplo.br"}], [],
      [], [], "", "", "", [], []}),
    S.Mail.utf8(S.Mail{A.Mbox{"", "a@b.c"}, [], [], [A.Mbox{"", "joao@exemplo-ção.br"}],
      [], "", "", "", [], []})]
    == [True{}, False{}] : List<Bool>}

law domain_to_alabel:
  {S.Mail.ascii(S.Mail{A.Mbox{"", "a@b.c"}, [A.Mbox{"Jo", "joao@exemplo-ção.br"}], [],
      [], [], "s", "b", "", [], []})
    == S.Mail{A.Mbox{"", "a@b.c"}, [A.Mbox{"Jo", "joao@xn--exemplo-o-s2a7b.br"}], [],
      [], [], "s", "b", "", [], []} : S.Mail}

# OAuth
# -----

# LAW: XOAUTH2's response matches Google's documented example.
law xoauth2_vector:
  {S.Smtp.xoauth2.resp("someuser@example.com",
    "ya29.vF9dft4qmTc2Nvb3RlckBhdHRhdmlzdGEuY29tCg")
    == "dXNlcj1zb21ldXNlckBleGFtcGxlLmNvbQFhdXRoPUJlYXJlciB5YTI5LnZGOWRmdDRxbVRjMk52YjNSbGNrQmhkSFJoZG1semRHRXVZMjl0Q2cBAQ=="
    : String}

# LAW: OAUTHBEARER's response matches RFC 7628's example (section 4.1).
law oauthbearer_vector:
  {S.Smtp.bearer.resp("user@example.com", "server.example.com", 143,
    "vF9dft4qmTc2Nvb3RlckBhbHRhdmlzdGEuY29tCg==")
    == "bixhPXVzZXJAZXhhbXBsZS5jb20sAWhvc3Q9c2VydmVyLmV4YW1wbGUuY29tAXBvcnQ9MTQzAWF1dGg9QmVhcmVyIHZGOWRmdDRxbVRjMk52YjNSbGNrQmhiSFJoZG1semRHRXVZMjl0Q2c9PQEB"
    : String}

# LAW: the mechanism is the one asked for when offered; on its own, OAuth
# with a token (XOAUTH2 first), else PLAIN, then LOGIN; never one the
# server did not offer.
law mechanism_choice:
  {[S.Mech.pick(S.AAuto{}, True{}, ["PLAIN", "XOAUTH2", "OAUTHBEARER"]),
    S.Mech.pick(S.AAuto{}, True{}, ["PLAIN", "OAUTHBEARER"]),
    S.Mech.pick(S.AAuto{}, False{}, ["LOGIN", "PLAIN", "XOAUTH2"]),
    S.Mech.pick(S.AAuto{}, False{}, ["LOGIN"]),
    S.Mech.pick(S.APlain{}, False{}, ["LOGIN"]),
    S.Mech.pick(S.AAuto{}, True{}, ["PLAIN"])]
    == [S.MXoauth2{}, S.MBearer{}, S.MPlain{}, S.MLogin{},
      S.MNo{"the server does not offer AUTH PLAIN"},
      S.MNo{"the server offers no XOAUTH2 or OAUTHBEARER"}] : List<S.Mech>}

# LAW: base64 decoding undoes the RFC 4648 vectors, padding or not.
law base64_decode:
  {[M.B64.decode("Zm9vYmFy"), M.B64.decode("Zm9vYg=="), M.B64.decode("Zm9vYg"),
    M.B64.decode("")]
    == [[102, 111, 111, 98, 97, 114], [102, 111, 111, 98], [102, 111, 111, 98], []]
    : List<List<&2, U32>>}

# Mailboxes and headers
# ---------------------

# LAW: lists are read as people write them: names, angle brackets,
# commas inside quotes, bare addresses.
law mailbox_list:
  {A.Mbox.list("Maria Silva <m@x.com>, j@y.org, \"Silva, João\" <j@z.br>, <k@w.io>")
    == [A.Mbox{"Maria Silva", "m@x.com"}, A.Mbox{"", "j@y.org"},
      A.Mbox{"Silva, João", "j@z.br"}, A.Mbox{"", "k@w.io"}] : List<&2, A.Mbox>}

# LAW: a name is written as atoms, as a quoted string (with its quotes
# escaped), or as encoded words when it is not ASCII or holds "=?".
law mailbox_show:
  {[A.Mbox.show(A.Mbox{"Maria Silva", "m@x.com"}), A.Mbox.show(A.Mbox{"", "j@y.org"}),
    A.Mbox.show(A.Mbox{"Silva, \"M\"", "m@x.com"}), A.Mbox.show(A.Mbox{"Zé", "z@x.com"}),
    A.Mbox.show(A.Mbox{"=?x?=", "q@r.s"})]
    == ["Maria Silva <m@x.com>", "j@y.org", "\"Silva, \\\"M\\\"\" <m@x.com>",
      "=?UTF-8?B?WsOp?= <z@x.com>", "=?UTF-8?B?PT94Pz0=?= <q@r.s>"] : List<String>}

# LAW: RCPT goes to To, Cc and Bcc, each address once.
law rcpt_list:
  {S.Mail.rcpts(S.Mail{A.Mbox{"", "f@x.com"}, [A.Mbox{"A", "a@x.com"}],
      [A.Mbox{"", "c@x.com"}], [A.Mbox{"", "b@x.com"}, A.Mbox{"", "a@x.com"}], [],
      "", "", "", [], []})
    == ["a@x.com", "c@x.com", "b@x.com"] : List<&2, String>}

# LAW: Bcc never reaches the headers; with only Bcc, To is the empty
# group (RFC 5322 A.1.3).
law bcc_hidden:
  {S.Smtp.text(S.Mail{A.Mbox{"", "f@x.com"}, [], [], [A.Mbox{"", "b@x.com"}], [],
      "s", "t", "", [], []}, 0, "id", "=_bend_B")
    == "Date: Thu, 01 Jan 1970 00:00:00 +0000\r\nFrom: f@x.com\r\nTo: undisclosed-recipients:;\r\nSubject: s\r\nMessage-ID: <id@x.com>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 7bit\r\n\r\nt"
    : String}

# MIME structure
# --------------

# LAW: text and HTML go as multipart/alternative, plain first; with
# files, inside multipart/mixed, each file base64 with its name.
law multipart_shape:
  {M.Mime.entity("t", "<b>h</b>", [M.Part{"a.txt", "text/plain", [104, 105]}], "B")
    == "Content-Type: multipart/mixed;\r\n boundary=\"B_m\"\r\n\r\nThis is a multi-part message in MIME format.\r\n--B_m\r\nContent-Type: multipart/alternative;\r\n boundary=\"B_a\"\r\n\r\nThis is a multi-part message in MIME format.\r\n--B_a\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 7bit\r\n\r\nt\r\n--B_a\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Transfer-Encoding: 7bit\r\n\r\n<b>h</b>\r\n--B_a--\r\n\r\n--B_m\r\nContent-Type: text/plain;\r\n name=\"a.txt\"\r\nContent-Disposition: attachment;\r\n filename=\"a.txt\"\r\nContent-Transfer-Encoding: base64\r\n\r\naGk=\r\n\r\n--B_m--\r\n"
    : String}

# LAW: a non-ASCII file name goes in RFC 2231's extended form.
law filename_2231:
  {[M.Mime.param("filename", "a b.pdf"), M.Mime.param("filename", "relatório.pdf")]
    == [";\r\n filename=\"a b.pdf\"", ";\r\n filename*=UTF-8''relat%C3%B3rio.pdf"]
    : List<String>}

# LAW: text that could hold a boundary never goes 7bit.
law boundary_safe:
  {M.Mime.body("x --=_bend_00 y")
    == M.Body{"base64", "eCAtLT1fYmVuZF8wMCB5\r\n"} : M.Body}

# The test server
# ---------------

# LAW: QUIT, between messages, is answered 221 and ends the
# connection, whatever the state.
law sink_quit:
  for from: String
  for n: U32
  for data: String
  {K.Sink.step(K.Sink{K.InCmd{}, from, n, data}, "QUIT")
    == K.Step{K.Sink{K.InCmd{}, from, n, data}, "221 bye\r\n", True{}, None{}, False{}}
    : K.Step}

# LAW: DATA before any recipient is refused, and nothing changes.
law sink_data_needs_rcpt:
  for from: String
  for data: String
  {K.Sink.step(K.Sink{K.InCmd{}, from, 0, data}, "DATA")
    == K.Step{K.Sink{K.InCmd{}, from, 0, data}, "503 need RCPT first\r\n",
      False{}, None{}, False{}} : K.Step}

# LAW: the lone-dot line saves exactly the message read so far (kept
# reversed while reading) and starts over.
law sink_dot_saves:
  for from: String
  for n: U32
  for data: String
  {K.Sink.step(K.Sink{K.InData{}, from, n, data}, ".")
    == K.Step{K.Sink.init(), "250 ok: queued\r\n", False{},
      Some{T.Text.onto(data, "")}, False{}}
    : K.Step}

# LAW: a stuffed line comes back unstuffed.
law sink_unstuffs:
  {K.Sink.step(K.Sink{K.InData{}, "a", 1, ""}, "..b")
    == K.Step{K.Sink{K.InData{}, "a", 1, "\n\rb."}, "", False{}, None{}, False{}}
    : K.Step}

# LAW: a second MAIL inside a transaction is refused (RFC 5321 4.1.4).
law sink_nested_mail:
  {K.Sink.step(K.Sink{K.InCmd{}, "<a@b.c>", 1, ""}, "MAIL FROM:<x@y.z>")
    == K.Step{K.Sink{K.InCmd{}, "<a@b.c>", 1, ""}, "503 nested MAIL command\r\n",
      False{}, None{}, False{}} : K.Step}

# LAW: EHLO ends any transaction, as RSET does (RFC 5321 4.1.4).
law sink_ehlo_resets:
  for from: String
  for n: U32
  for data: String
  {K.Sink.step(K.Sink{K.InCmd{}, from, n, data}, "EHLO client.example")
    == K.Step{K.Sink.init(), "250-bend-smtp sink\r\n250-8BITMIME\r\n250 SMTPUTF8\r\n",
      False{}, None{}, False{}} : K.Step}

# LAW: verbs are case-blind and whole words: "quit" is QUIT, "DATAX" is
# no DATA.
law sink_verbs:
  {[K.Sink.step(K.Sink.init(), "quit"), K.Sink.step(K.Sink.init(), "DATAX")]
    == [K.Step{K.Sink.init(), "221 bye\r\n", True{}, None{}, False{}},
      K.Step{K.Sink.init(), "500 unknown command\r\n", False{}, None{}, False{}}]
    : List<K.Step>}

# LAW: with STARTTLS on offer, EHLO announces it, MAIL waits for it, and
# a bare STARTTLS is answered 220 with the dialog started over and TLS
# to follow (RFC 3207 4, 4.2).
law sink_starttls:
  for from: String
  for n: U32
  for data: String
  {[K.Sink.stepx(K.Sink.init(), True{}, "EHLO c.example"),
    K.Sink.stepx(K.Sink.init(), True{}, "MAIL FROM:<a@b.c>"),
    K.Sink.stepx(K.Sink{K.InCmd{}, from, n, data}, True{}, "STARTTLS")]
    == [K.Step{K.Sink.init(),
          "250-bend-smtp sink\r\n250-STARTTLS\r\n250-8BITMIME\r\n250 SMTPUTF8\r\n",
          False{}, None{}, False{}},
        K.Step{K.Sink.init(), "530 5.7.0 must issue a STARTTLS command first\r\n",
          False{}, None{}, False{}},
        K.Step{K.Sink.init(), "220 2.0.0 ready to start TLS\r\n", False{}, None{},
          True{}}] : List<K.Step>}

# LAW: once TLS is on (or never offered), STARTTLS is not on offer, and
# it takes no parameters.
law sink_starttls_refused:
  {[K.Sink.stepx(K.Sink.init(), False{}, "STARTTLS"),
    K.Sink.stepx(K.Sink.init(), True{}, "STARTTLS now")]
    == [K.Step{K.Sink.init(), "502 5.5.1 STARTTLS is not offered\r\n", False{},
          None{}, False{}},
        K.Step{K.Sink.init(), "501 5.5.4 STARTTLS takes no parameters\r\n", False{},
          None{}, False{}}] : List<K.Step>}

# Extra headers
# -------------

# LAW: an extra header goes after Message-ID, as written when it is
# ASCII (a URL in angle brackets must stay readable) and as encoded
# words otherwise; a CR or LF in it cannot start another header.
law extra_headers:
  {S.Hdr.shows([S.Hdr{"List-Unsubscribe", "<https://x.example/u?id=1>"},
      S.Hdr{"X-Nota", "Olá"}, S.Hdr{"X-A", "b\r\nBcc: x@y"}])
    == "List-Unsubscribe: <https://x.example/u?id=1>\r\nX-Nota: =?UTF-8?B?T2zDoQ==?=\r\nX-A: bBcc: x@y\r\n"
    : String}

# LAW: a header the client writes itself, or with a malformed name, is
# refused, in any letter case.
law header_names:
  {[S.Hdr.ok("X-Campaign"), S.Hdr.ok("List-Unsubscribe"), S.Hdr.ok("Subject"),
    S.Hdr.ok("bcc"), S.Hdr.ok("CONTENT-TYPE"), S.Hdr.ok("X Bad"), S.Hdr.ok("X:Y"),
    S.Hdr.ok("")]
    == [True{}, True{}, False{}, False{}, False{}, False{}, False{}, False{}]
    : List<Bool>}

# Several messages
# ----------------

# LAW: each message's outcome is kept in order, in front of the rest,
# and an error that ends the connection keeps the ones already sent.
law batch_keeps_order:
  for a: S.Sent
  for b: S.Sent
  for code: U32
  for error: String
  {S.Batch.add(a, S.Batch.add(b, S.Batch{[], code, error}))
    == S.Batch{[a, b], code, error} : S.Batch}
