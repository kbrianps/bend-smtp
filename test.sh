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

$BEND PROOF.bend 2>&1 | grep -q "All terms check." && ok "laws proven" || bad "laws"
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
    --key tests/certs/server.key --log "$TMP/$name.log" --out "$TMP/$name.eml" >/dev/null &
  local srv=$!
  sleep 0.6
  local out
  out=$(./send --host localhost --port $P2 --cafile tests/certs/ca.pem \
    --from me@example.com --to a@example.com --subject Oi --body ok "$@" 2>&1)
  wait $srv
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
