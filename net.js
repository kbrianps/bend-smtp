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
  return { $: CID(Unit) };
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
  return { $: CID(Unit) };
}

function net_connect_via(proxy, pport, user, pass, host, port, kind) {
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

io_eff(CID(Net.connect), net_connect);
io_eff(CID(Net.tls), net_tls);
io_eff(CID(Net.tls_accept), net_tls_accept);
io_eff(CID(Net.send), net_send);
io_eff(CID(Net.poll), net_poll);
io_eff(CID(Net.close), net_close);
io_eff(CID(Net.time), net_time);
io_eff(CID(Net.helo), net_helo);
io_eff(CID(Net.hostname), net_hostname);
io_eff(CID(Net.debug), net_debug);
io_eff(CID(Net.connect_via), net_connect_via);
io_eff(CID(Dkim.sha256), dkim_sha256);
io_eff(CID(Dkim.alg), dkim_alg);
io_eff(CID(Dkim.sign), dkim_sign);
