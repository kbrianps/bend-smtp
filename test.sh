#!/usr/bin/env bash
# The gate: the proofs, then the client against the Bend sink and
# against tests/server.py in every mode (TLS, STARTTLS, AUTH, refusals).
set -uo pipefail
cd "$(dirname "$0")"
BEND=${BEND:-bend}
PORT=${PORT:-2599}
TMP=$(mktemp -d)
FAILS=0
trap 'kill $SINK 2>/dev/null; rm -rf "$TMP"' EXIT

ok()   { echo "ok: $1"; }
bad()  { echo "FAIL: $1"; FAILS=$((FAILS + 1)); }

$BEND PROOF.bend 2>&1 | grep -q "ALL PROOFS CHECK" && ok "laws proven" || bad "laws"
$BEND send.bend -o send >/dev/null 2>&1 || { echo "build send failed"; exit 1; }
$BEND sink.bend -o sink >/dev/null 2>&1 || { echo "build sink failed"; exit 1; }

# Through the Bend sink: an ASCII body with dot lines, and a UTF-8 one.
./sink "$PORT" "$TMP" >/dev/null & SINK=$!
sleep 0.5
send() { ./send --host 127.0.0.1 --port "$PORT" --tls plain --from me@example.com "$@"; }
send --to "a@example.com, b@example.com" --subject "Oi" \
  --body $'line one\n.dot line\n..two dots\nlast' >/dev/null &&
  python3 tests/check_mail.py "$TMP/1.eml" "Oi" $'line one\n.dot line\n..two dots\nlast' 7bit &&
  ok "7bit message through the sink" || bad "7bit message through the sink"
send --to a@example.com --subject "Relatório — câmeras 📷" --body $'Olá\nção' >/dev/null &&
  python3 tests/check_mail.py "$TMP/2.eml" "Relatório — câmeras 📷" $'Olá\nção' base64 &&
  ok "UTF-8 subject and body through the sink" || bad "UTF-8 through the sink"
kill $SINK

# Against tests/server.py: $1 the case, $2 server flags, $3 expected
# output (a grep pattern), then the client's flags.
P2=$((PORT + 1))
case_() {
  local name=$1 flags=$2 want=$3; shift 3
  python3 tests/server.py --port $P2 $flags --cert tests/certs/server.pem \
    --key tests/certs/server.key --log "$TMP/$name.log" --out "$TMP/$name.eml" >/dev/null 2>&1 &
  local srv=$!
  sleep 0.6
  local out
  out=$(./send --host localhost --port $P2 --cafile tests/certs/ca.pem \
    --from me@example.com --to a@example.com --subject Oi --body ok "$@" 2>&1)
  wait $srv
  printf '%s\n' "$out" > "$TMP/last.out"
  if grep -q -- "$want" <<<"$out"; then ok "$name"; else bad "$name: $out"; fi
}
export SMTP_PASSWORD=pw
case_ "STARTTLS + AUTH PLAIN"   "--mode starttls --auth plain --user u --password pw" "^sent" --user u
case_ "implicit TLS + AUTH LOGIN" "--mode tls --auth login --user u --password pw" "^sent" --tls tls --user u
case_ "HELO when EHLO is refused" "--no-ehlo" "^sent" --tls plain
case_ "refused recipient"       "--reject-rcpt" "failed (550)" --tls plain
case_ "SIZE too small"          "--size 50" "failed (552)" --tls plain
case_ "STARTTLS injection"      "--mode starttls --inject" "data after STARTTLS" --tls starttls
case_ "no STARTTLS, no downgrade" "" "does not offer STARTTLS" --tls starttls
case_ "no password without TLS" "--auth plain --user u --password pw" "without TLS" --tls plain --user u
case_ "wrong password"          "--mode tls --auth plain --user u --password other" "failed (535)" --tls tls --user u
LONG=$(printf 'p%.0s' $(seq 1 600))
SMTP_PASSWORD=$LONG case_ "long AUTH PLAIN via 334" "--mode tls --auth plain --user u --password $LONG" "^sent" --tls tls --user u
grep -q "LONG COMMAND" "$TMP"/*.log && bad "a command line past 512 octets" || ok "no command line past 512 octets"
grep -q "^C: QUIT" "$TMP/refused recipient.log" && ok "QUIT after a refusal" || bad "no QUIT after a refusal"
grep -q "^C: HELO [^[]" "$TMP/HELO when EHLO is refused.log" && ok "HELO names a domain" || bad "HELO argument"

case_ "SMTPUTF8 address"        "--smtputf8" "^sent" --tls plain --from "joão@exemplo.br" --to "maria@exemplo.br"
grep -q "^C: MAIL FROM:<joão@exemplo.br> SMTPUTF8 BODY=8BITMIME" "$TMP/SMTPUTF8 address.log" &&
  ok "MAIL carries SMTPUTF8" || bad "MAIL without SMTPUTF8"
case_ "no SMTPUTF8, refused"    "" "failed (553)" --tls plain --from "joão@exemplo.br"
case_ "non-ASCII domain as A-label" "" "^sent" --tls plain --to "maria@exemplo-ção.br"
grep -q "^C: RCPT TO:<maria@xn--exemplo-o-s2a7b.br>" "$TMP/non-ASCII domain as A-label.log" &&
  ok "RCPT carries the A-label" || bad "RCPT without the A-label"

export SMTP_OAUTH_TOKEN=tok
SMTP_PASSWORD= case_ "XOAUTH2"               "--mode tls --auth xoauth2 --user u@x.com --token tok" "^sent" --tls tls --user u@x.com
SMTP_PASSWORD= SMTP_OAUTH_TOKEN=bad case_ "XOAUTH2, bad token" "--mode tls --auth xoauth2 --user u@x.com --token tok" "XOAUTH2 refused: {\"status\":\"401\"" --tls tls --user u@x.com
grep -q "^C: cancel ''" "$TMP/XOAUTH2, bad token.log" && ok "XOAUTH2 error answered with an empty line" || bad "XOAUTH2 cancel"
SMTP_PASSWORD= case_ "OAUTHBEARER over STARTTLS" "--mode starttls --auth oauthbearer --user u@x.com --token tok" "^sent" --user u@x.com
unset SMTP_OAUTH_TOKEN
case_ "one recipient refused"   "--reject b@x.com" "^  b@x.com (550" --tls plain --to "a@x.com, b@x.com"
grep -q "^C: RCPT TO:<a@x.com>" "$TMP/one recipient refused.log" && [ -s "$TMP/one recipient refused.eml" ] &&
  ok "the others still get it" || bad "partial delivery"
case_ "every recipient refused" "--reject-rcpt" "failed (550): every recipient was refused" --tls plain --to "a@x.com, b@x.com"

# HTML, attachments, Cc and Bcc, checked by Python's parsers.
head -c 5000 /dev/urandom > "$TMP/dados.bin"
printf 'a,b\n1,2\n' > "$TMP/relatório de manutenção.csv"
case_ "multipart with attachments" "" "^sent" --tls plain --from "Eu <me@x.com>" \
  --to "Ana <ana@x.com>" --cc "\"Silva, B\" <b@x.com>" --bcc "c@x.com" \
  --body $'texto\n.ponto' --html "<p>Olá</p>" --attach "$TMP/dados.bin" \
  --attach "$TMP/relatório de manutenção.csv"
python3 tests/check_parts.py "$TMP/multipart with attachments.eml" "$TMP/dados.bin" \
  "$TMP/relatório de manutenção.csv" && ok "parts, names and bytes intact, no Bcc" || bad "multipart check"
grep -q "^C: RCPT TO:<c@x.com>" "$TMP/multipart with attachments.log" && ok "Bcc gets RCPT" || bad "Bcc RCPT"

# Extra headers, the debug trace, several messages on one connection.
case_ "extra headers"           "" "^sent" --tls plain --header "X-Campaign: outubro" \
  --header "List-Unsubscribe: <https://x.example/u?id=1>"
grep -q "^X-Campaign: outubro" "$TMP/extra headers.eml" &&
  grep -q "^List-Unsubscribe: <https://x.example/u?id=1>" "$TMP/extra headers.eml" &&
  ok "headers written as given" || bad "extra headers"
out=$(./send --host localhost --port $P2 --tls plain --from me@example.com --to a@example.com \
  --header "Subject: outro" 2>&1)
grep -q "bad header" <<<"$out" && ok "own header refused before connecting" || bad "own header: $out"
SMTP_PASSWORD=segredo123 case_ "debug trace" "--mode tls --auth plain --user u --password segredo123" \
  "^C: (message, [0-9]* octets)" --tls tls --user u --body "corpo-secreto" --debug
python3 tests/server.py --port $P2 --mode tls --auth login --user u --password segredo123 \
  --cert tests/certs/server.pem --key tests/certs/server.key --log "$TMP/dbg.log" --out "$TMP/dbg.eml" >/dev/null &
sleep 0.6
out=$(SMTP_PASSWORD=segredo123 ./send --host localhost --port $P2 --cafile tests/certs/ca.pem --tls tls \
  --user u --from me@example.com --to a@example.com --body corpo-secreto --debug 2>&1)
wait
if grep -q -e "segredo123" -e "corpo-secreto" -e "$(printf segredo123 | base64)" <<<"$out"; then
  bad "the trace leaks a secret"; else ok "the trace hides the password and the text"; fi
case_ "one message per recipient" "--reject b@x.com" "^sent to c@x.com" --tls plain \
  --to "a@x.com, b@x.com, c@x.com" --individually
grep -q "^C: RSET" "$TMP/one message per recipient.log" && [ -s "$TMP/one message per recipient.eml.2" ] &&
  ! grep -q "c@x.com" "$TMP/one message per recipient.eml.1" &&
  ok "RSET after the refused one, each sees only itself" || bad "individually"
a=$(grep -h "^Message-ID" "$TMP/one message per recipient.eml.1")
b=$(grep -h "^Message-ID" "$TMP/one message per recipient.eml.2")
[ -n "$a" ] && [ "$a" != "$b" ] && ok "each message has its own Message-ID" || bad "Message-ID reuse"
case_ "connection lost mid-batch" "--hang-up-after 1" "^sent to a@x.com" --tls plain \
  --to "a@x.com, b@x.com, c@x.com" --individually
out=$(cat "$TMP/last.out")
grep -q "2 messages were not tried" <<<"$out" && ok "the sent one is kept, the rest reported" || bad "mid-batch: $out"

# Extensions: pipelining, DSN, chunking; LMTP; CRAM-MD5.
case_ "PIPELINING (replies held until DATA)" "--ext PIPELINING --hold" "^sent" --tls plain --to "a@x.com, b@x.com"
case_ "piped, every recipient refused" "--ext PIPELINING --hold --reject-rcpt --data-always" \
  "failed (550): every recipient was refused" --tls plain
grep -q "^EMPTY MESSAGE: 0 octets" "$TMP/piped, every recipient refused.log" &&
  ok "an unwanted 354 is ended with an empty message" || bad "piped 354"
case_ "piped, MAIL refused"     "--ext PIPELINING --hold --reject-mail" "failed (550): 5.7.1 sender refused" --tls plain
case_ "DSN parameters"          "--ext DSN" "^sent" --tls plain --notify success,failure --ret hdrs --envid "id+1"
grep -q "^C: MAIL FROM:<me@example.com> RET=HDRS ENVID=id+2B1" "$TMP/DSN parameters.log" &&
  grep -q "^C: RCPT TO:<a@example.com> NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;a@example.com" "$TMP/DSN parameters.log" &&
  ok "RET, ENVID, NOTIFY and ORCPT sent" || bad "DSN lines"
case_ "DSN not offered, not sent" "" "^sent" --tls plain --notify never
grep -q "NOTIFY" "$TMP/DSN not offered, not sent.log" && bad "NOTIFY without DSN" || ok "no DSN parameter without DSN"
case_ "CHUNKING"                "--ext CHUNKING" "^sent" --tls plain --chunking --body $'corpo-do-bdat\n.b' --debug
out=$(cat "$TMP/last.out")
grep -q "corpo-do-bdat" <<<"$out" && bad "the trace shows a BDAT message" || ok "the trace hides a BDAT message too"
grep -q "^C: BDAT [0-9]* LAST" "$TMP/CHUNKING.log" && grep -q "^\.b" "$TMP/CHUNKING.eml" &&
  ok "BDAT carries the message unstuffed" || bad "BDAT"
case_ "LMTP"                    "--lmtp --reject-final b@x.com" "^  b@x.com (550 5.2.2 mailbox full)" \
  --tls plain --lmtp --to "a@x.com, b@x.com"
grep -q "^C: LHLO" "$TMP/LMTP.log" && ok "LHLO, one final reply per recipient" || bad "LHLO"
SMTP_PASSWORD=pw case_ "AUTH CRAM-MD5" "--mode tls --auth cram-md5 --user u --password pw" "^sent" --tls tls --user u
SMTP_PASSWORD=no case_ "CRAM-MD5, wrong password" "--mode tls --auth cram-md5 --user u --password pw" "failed (535)" --tls tls --user u

# A client certificate, and a SOCKS5 proxy.
case_ "client certificate"      "--mode tls --client-ca tests/certs/ca.pem" "^sent" --tls tls \
  --cert tests/certs/client.pem --key tests/certs/client.key
case_ "no client certificate, refused" "--mode tls --client-ca tests/certs/ca.pem" "certificate required" --tls tls
P3=$((PORT + 2))
python3 tests/socks.py $P3 "$TMP/socks.log" "zé" "s:e@nha" >/dev/null 2>&1 & PROXY=$!
case_ "SOCKS5 proxy with a password" "--mode starttls" "^sent" --proxy "socks5://zé:s:e@nha@127.0.0.1:$P3"
wait $PROXY
grep -q "^connect atyp=3 localhost:$P2" "$TMP/socks.log" && ok "the proxy gets the host name, not an address" || bad "socks target: $(cat "$TMP/socks.log")"
python3 tests/socks.py $P3 "$TMP/socks2.log" u p >/dev/null 2>&1 & PROXY=$!
sleep 0.4
out=$(./send --host localhost --port $P2 --tls plain --from me@example.com --to a@example.com --body x \
  --proxy "socks5://u:wrong@127.0.0.1:$P3" 2>&1)
wait $PROXY
grep -q "the proxy refused the user and password" <<<"$out" && ok "SOCKS5 wrong password" || bad "socks auth: $out"

python3 tests/httpproxy.py $P3 "$TMP/http.log" "zé" "s:e@nha" >/dev/null 2>&1 & PROXY=$!
case_ "HTTP CONNECT proxy with a password" "--mode tls" "^sent" --tls tls --proxy "http://zé:s:e@nha@127.0.0.1:$P3"
wait $PROXY
grep -q "^CONNECT localhost:$P2" "$TMP/http.log" && grep -q "^auth ok" "$TMP/http.log" &&
  ok "the tunnel names the host, with Basic credentials" || bad "http proxy: $(cat "$TMP/http.log")"
python3 tests/httpproxy.py $P3 "$TMP/http2.log" u p >/dev/null 2>&1 & PROXY=$!
sleep 0.4
out=$(./send --host localhost --port $P2 --tls plain --from me@example.com --to a@example.com --body x \
  --proxy "http://u:wrong@127.0.0.1:$P3" 2>&1)
wait $PROXY
grep -q "(407)" <<<"$out" && ok "HTTP proxy wrong password" || bad "http proxy auth: $out"
out=$(./send --host localhost --port $P2 --tls plain --from me@example.com --to a@example.com --body x \
  --proxy "https://127.0.0.1:$P3" 2>&1); rc=$?
[ $rc -eq 2 ] && grep -q "bad proxy URL" <<<"$out" && ok "an unreadable proxy URL is an error, not a direct connection" || bad "bad proxy: $rc $out"

# DKIM: RSA and Ed25519, checked by tests/dkim_verify.py.
for k in rsa ed; do
  case_ "DKIM $k" "" "^sent" --tls plain --from "Zé <me@example.com>" --subject "Relatório — câmeras" \
    --body $'linha  com   espaços  \n\n.ponto\nfim\n\n' --html "<p>Olá</p>" --header "X-A: 1" --header "X-A: 2" \
    --dkim-domain example.com --dkim-selector s1 --dkim-key tests/certs/dkim-$k.key
  python3 tests/dkim_verify.py "$TMP/DKIM $k.eml" tests/certs/dkim-$k.key &&
    ok "DKIM $k signature verifies" || bad "DKIM $k signature"
done
python3 - "$TMP/DKIM rsa.eml" "$TMP/tampered.eml" "$TMP/relayed.eml" <<'PY'
import sys
raw = open(sys.argv[1], "rb").read()
head, body = raw.split(b"\r\n\r\n", 1)
open(sys.argv[2], "wb").write(raw.replace(b"Subject: ", b"Subject: X", 1))
open(sys.argv[3], "wb").write(head.replace(b"From: ", b"From:   ", 1) + b"\r\n\r\n" + body + b"\r\n\r\n")
PY
python3 tests/dkim_verify.py "$TMP/tampered.eml" tests/certs/dkim-rsa.key 2>/dev/null &&
  bad "a tampered subject still verifies" || ok "a tampered subject fails"
python3 tests/dkim_verify.py "$TMP/relayed.eml" tests/certs/dkim-rsa.key &&
  ok "spacing changed by a relay still verifies" || bad "relaxed canonicalization"
for c in relaxed/simple simple/relaxed simple/simple; do
  n="DKIM ${c/\// and }"
  case_ "$n" "" "^sent" --tls plain --subject "Olá  mundo" --body $'a  b  \n\n.c\n\n' \
    --dkim-domain example.com --dkim-selector s1 --dkim-key tests/certs/dkim-rsa.key --dkim-canon $c
  grep -q "c=$c;" "$TMP/$n.eml" && python3 tests/dkim_verify.py "$TMP/$n.eml" tests/certs/dkim-rsa.key &&
    ok "$n signature verifies" || bad "$n signature"
done
# Oversigning: a Subject added on the way breaks the signature; without
# it, the added one goes unnoticed (the verifier reads the last one).
python3 - "$TMP/DKIM rsa.eml" "$TMP/added.eml" <<'PY'
import sys
open(sys.argv[2], "wb").write(b"Subject: outro assunto\r\n" + open(sys.argv[1], "rb").read())
PY
python3 tests/dkim_verify.py "$TMP/added.eml" tests/certs/dkim-rsa.key 2>/dev/null &&
  bad "an added Subject still verifies" || ok "oversigning: an added Subject fails"
case_ "DKIM without oversigning" "" "^sent" --tls plain --dkim-no-oversign \
  --dkim-domain example.com --dkim-selector s1 --dkim-key tests/certs/dkim-rsa.key
python3 - "$TMP/DKIM without oversigning.eml" "$TMP/added2.eml" <<'PY'
import sys
open(sys.argv[2], "wb").write(b"Subject: outro assunto\r\n" + open(sys.argv[1], "rb").read())
PY
python3 tests/dkim_verify.py "$TMP/added2.eml" tests/certs/dkim-rsa.key &&
  ok "without it, the same addition passes (the option does what it says)" || bad "no-oversign"
out=$(./send --host localhost --port $P2 --tls plain --from me@example.com --to a@example.com --body x \
  --dkim-domain x.com --dkim-selector s --dkim-key tests/certs/ca.pem 2>&1); rc=$?
[ $rc -eq 1 ] && grep -q "cannot read the private key" <<<"$out" && ok "a bad DKIM key stops the send" || bad "bad DKIM key: $rc $out"

# The library called directly, past the command line's checks (the two
# injections found in review): refused before a connection is made.
$BEND tests/inject.bend -o "$TMP/inject" >/dev/null 2>&1 || bad "build tests/inject.bend"
out=$("$TMP/inject" $P2 ret 2>&1)
grep -q "^refused: bad ret" <<<"$out" && ok "library: a DSN option with a line end is refused" || bad "inject ret: $out"
out=$("$TMP/inject" $P2 ctype 2>&1)
grep -q "^refused: bad attachment type" <<<"$out" && ok "library: an attachment type with a line end is refused" || bad "inject ctype: $out"
python3 tests/server.py --port $P2 --ext DSN --log "$TMP/inj.log" --out "$TMP/inj.eml" >/dev/null 2>&1 &
sleep 0.6
out=$("$TMP/inject" $P2 more 2>&1)
wait
grep -q "^went through" <<<"$out" && grep -q "^C: MAIL FROM:<me@example.com> RET=HDRS$" "$TMP/inj.log" &&
  ! grep -q "^C: RSET" "$TMP/inj.log" && ok "library: valid DSN options still go, one command per line" || bad "inject more: $out"

# The Bend sink over TLS and STARTTLS.
for mode in tls starttls; do
  ./sink $P2 "$TMP" $mode tests/certs/server.pem tests/certs/server.key >/dev/null & SINK=$!
  sleep 0.5
  out=$(./send --host localhost --port $P2 --tls $mode --cafile tests/certs/ca.pem \
    --from me@example.com --to a@example.com --subject "sink $mode" --body ok 2>&1)
  kill $SINK; wait $SINK 2>/dev/null
  [ "$out" = "sent" ] && ok "Bend sink over $mode" || bad "Bend sink over $mode: $out"
done
./sink $P2 "$TMP" starttls tests/certs/server.pem tests/certs/server.key >/dev/null & SINK=$!
sleep 0.5
out=$(./send --host localhost --port $P2 --tls plain --from me@example.com --to a@example.com --body x 2>&1)
kill $SINK; wait $SINK 2>/dev/null
grep -q "failed (530)" <<<"$out" && ok "Bend sink wants STARTTLS before MAIL" || bad "sink STARTTLS: $out"

# An untrusted certificate (no --cafile) is refused.
python3 tests/server.py --port $P2 --mode tls --cert tests/certs/server.pem \
  --key tests/certs/server.key --log "$TMP/ca.log" --out "$TMP/ca.eml" >/dev/null 2>&1 &
sleep 0.6
out=$(./send --host localhost --port $P2 --tls tls --from me@example.com --to a@example.com --body x 2>&1)
wait
grep -q "certificate" <<<"$out" && ok "untrusted certificate refused" || bad "certificate: $out"

[ $FAILS -eq 0 ] && echo "all passed" || { echo "$FAILS failed"; exit 1; }
