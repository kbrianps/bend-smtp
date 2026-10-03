// Net
// ===
//
// The JS backend has no TLS here: every network call fails with
// EOPNOTSUPP (95), so `bend send.bend` says so instead of half-working.
// Build natively: bend send.bend -o send.

function net_connect(host, port) {
  return io_fail(95);
}

function net_tls(sock, host, cafile, cert, key) {
  return io_tup(sock, io_fail(95));
}

function net_tls_accept(sock, cert, key) {
  return io_tup(sock, io_fail(95));
}

function net_send(sock, data) {
  return io_tup(sock, io_fail(95));
}

function net_poll(sock, max, ms) {
  return io_tup(sock, io_fail(95));
}

function net_close(sock) {
  return { $: "Unit" };
}

function net_time() {
  return Math.floor(Date.now() / 1000) >>> 0;
}

function net_helo(sock) {
  return io_tup(sock, "localhost");
}

function net_hostname() {
  return "localhost";
}

function net_debug(on) {
  return { $: "Unit" };
}

function net_connect_via(proxy, pport, user, pass, host, port) {
  return io_fail(95);
}

function dkim_sha256(data) {
  return io_fail(95);
}

function dkim_alg(keyfile) {
  return io_fail(95);
}

function dkim_sign(keyfile, data) {
  return io_fail(95);
}
