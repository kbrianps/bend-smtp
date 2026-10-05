# bend-smtp

English · [Português](README.pt-BR.md)

An SMTP client written in [Bend 2](https://github.com/bendlang/bend): TLS, OAuth, DKIM, international addresses, attachments, with its safety rules proven by the compiler. It answers [lilalittle/bend-packages#42](https://github.com/lilalittle/bend-packages/issues/42).

```python
import Base
import ./smtp.bend as S

def main() -> IO(Unit):
  do IO<Unit>:
    pass : String <- IO.try(String, IO.get_env("SMTP_PASSWORD"))
    b : S.Batch <- S.Smtp.send_mail(
      S.Opts.login(S.Opts.new("smtp.example.com"), "me@example.com", pass),
      S.Mail.new("Me <me@example.com>", "Ana <ana@x.com>, b@y.com", "Hi", "It works."))
    IO.print("done")
```

A complete program is in [`examples/hello.bend`](examples/hello.bend). There is also a command line:

    bend send.bend -o send
    SMTP_PASSWORD=... ./send --host smtp.gmail.com --user me@gmail.com \
      --from "Me <me@gmail.com>" --to "Ana <ana@x.com>, b@y.com" \
      --subject "Report" --body "text" --html-file body.html --attach report.pdf

## What is proven

`bend PROOF.bend` only passes while every law in [`LAWS.bend`](LAWS.bend) holds.

- **No injection, for every string.** A cleaned field holds no CR or LF (by induction), and every address, subject and header goes through it: none can start a new SMTP command or a new header line.
- **The RFCs' own test vectors**, checked by computation: base64 (RFC 4648), MD5 (RFC 1321), CRAM-MD5 (RFC 2195), AUTH PLAIN (RFC 4616), XOAUTH2 (Google's example), OAUTHBEARER (RFC 7628), Punycode (RFC 3492), DKIM canonicalization (RFC 6376 3.4.5).
- **The rules of the dialog**: an extension is used only when the server announced it; a proxy that cannot be read is an error, never a direct connection; a refusal already known is kept when the connection drops; Bcc never reaches the headers.

## What it does

| RFC | What |
|---|---|
| 5321 SMTP | several messages per connection, one transaction each; a refused recipient does not stop the others; EHLO with HELO fallback; the timeouts of 4.5.3.2; QUIT after any refusal |
| 3207, 8314 TLS | STARTTLS (EHLO again after it, plaintext sent before the handshake refused, no fallback to plain text) and implicit TLS; TLS 1.2+, certificate and host name verified; client certificates |
| 4954, 4616, 2195, 7628 AUTH | PLAIN, LOGIN, CRAM-MD5, XOAUTH2, OAUTHBEARER; never without TLS |
| 6531, 6532, 3492 | SMTPUTF8 for a non-ASCII local part; a non-ASCII domain alone travels as an A-label |
| 5322, 2045-2047, 2231 | Date, From, To, Cc, Reply-To, Message-ID, extra headers; text, HTML and attachments; RFC 2047 names and subjects |
| 6376, 8463 DKIM | RSA and Ed25519, relaxed and simple forms, oversigned headers |
| 1870, 2920, 3030, 3461, 2033 | SIZE, PIPELINING, CHUNKING, DSN, LMTP |
| 1928, 1929, 9110 | SOCKS5 and HTTP CONNECT proxies |

Checked against real servers: authenticated sends through Gmail (STARTTLS and implicit TLS, PLAIN and LOGIN, PIPELINING and BDAT, attachments), with SPF, DKIM and DMARC passing at the receiving side; and the dialog up to authentication against Outlook. `./test.sh` runs the proofs and 84 checks against two test servers (`BEND=path/to/bend ./test.sh`).

## Limits

- **Native build only**, tested on Linux. The network and TLS are C effects that open OpenSSL at run time (`libssl` 1.1 or 3 must be installed); under the JS backend they answer "not supported".
- **Memory**: a Bend string is a linked list, so an attachment costs about 55 bytes of RAM per byte (10 MB: about 1 s and 570 MB).
- **OAuth**: it sends an access token you already have; it does not obtain or refresh one.
- **IDNA**: a non-ASCII domain is converted as written (ASCII letters lower-cased), without Unicode normalization.
- **Left out on purpose**: DKIM's `l=` tag (it lets anyone append to a signed message, RFC 6376 8.2), and sending a password without TLS.
- The test server `sink.bend` is for tests: it delivers nothing.

## Command line

`./send` with no arguments prints every option. The password comes only from `SMTP_PASSWORD` (or the token from `SMTP_OAUTH_TOKEN`), never from the command line. Exit status: 0 sent to everyone; 3 sent in part; 1 nothing sent; 2 bad usage.

- `--to`, `--cc`, `--bcc`, `--reply-to`: lists as people write them (`"Silva, Ana" <ana@x.com>, b@y.com`)
- `--body`/`--body-file`, `--html`/`--html-file`, `--attach` (repeats), `--header "Name: value"` (repeats)
- `--individually`: one message per `--to` address, each seeing only itself, over one connection
- `--tls starttls|tls|plain`, `--port`, `--cafile`, `--cert`/`--key`, `--proxy socks5://...|http://...`, `--lmtp`
- `--auth plain|login|cram-md5|xoauth2|oauthbearer` (default: picked from what the server offers)
- `--dkim-domain`, `--dkim-selector`, `--dkim-key`, `--dkim-canon`, `--dkim-no-oversign`
- `--notify`, `--ret`, `--envid` (DSN), `--no-pipelining`, `--chunking`
- `--debug`: the dialog on stderr, with credentials and the message's text left out

## Files

- `smtp.bend`: the client (`Smtp.send_mail`, `Smtp.send_many`, `Opts.*`, `Mail.*`); `send.bend`: the command line
- `net.c`, `net.bend`: connections, DNS, TLS, proxies, the DKIM hash and signature
- `text.bend`, `reply.bend`, `mime.bend`, `addr.bend`, `idna.bend`, `md5.bend`, `dkim.bend`: the pure parts
- `sink.bend`: a test SMTP server in Bend; `tests/`: a scriptable test server, test proxies, a DKIM verifier
- `tests/certs/`: a CA, certificates and DKIM keys **for tests only** (the private keys are there on purpose)

MIT license.
