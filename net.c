// Net
// ===
//
// Sockets that may turn TLS mid-stream, for SMTP's STARTTLS (RFC 3207)
// and implicit TLS (RFC 8314). A connection is a plain Socket handle, its
// descriptor; Net.tls wraps that descriptor in an OpenSSL session kept in
// a table here, and Net.send, Net.poll and Net.close go through the
// session when the descriptor has one, else straight to the socket.
//
// bend links no OpenSSL, so libssl is opened at run time (dlopen) on the
// first Net.tls; a program that never asks for TLS never touches it.
// bend defines CID_X only for the effects a program uses, so each one
// registers under #ifdef.
// Certificates are verified (chain and host name) against the system's
// trust store, or against a CA file the caller names.

#include <dlfcn.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define NET_WANT_READ     2
#define NET_WANT_WRITE    3
#define NET_SYSCALL       5
#define NET_ZERO_RETURN   6
#define NET_SET_SNI       55
#define NET_SET_MIN_PROTO 123
#define NET_TLS1_2        0x0303
#define NET_VERIFY_PEER   1
#define NET_FILETYPE_PEM  1
#define NET_CONNECT_MS    30000
#define NET_HANDSHAKE_MS  60000

typedef struct {
  int   tried;
  int   ok;
  void* lib;
  void* (*client_method)(void);
  void* (*server_method)(void);
  int   (*ctx_use_chain)(void*, const char*);
  int   (*ctx_use_key)(void*, const char*, int);
  int   (*ctx_check_key)(const void*);
  int   (*do_accept)(void*);
  void* (*ctx_new)(void*);
  void  (*ctx_free)(void*);
  long  (*ctx_ctrl)(void*, int, long, void*);
  int   (*ctx_default_paths)(void*);
  int   (*ctx_load_locations)(void*, const char*, const char*);
  void  (*ctx_set_verify)(void*, int, void*);
  void* (*ssl_new)(void*);
  void  (*ssl_free)(void*);
  int   (*set_fd)(void*, int);
  long  (*ssl_ctrl)(void*, int, long, void*);
  int   (*set1_host)(void*, const char*);
  void* (*get0_param)(void*);
  int   (*param_set1_ip_asc)(void*, const char*);
  int   (*do_connect)(void*);
  int   (*do_read)(void*, void*, int);
  int   (*do_write)(void*, const void*, int);
  int   (*do_shutdown)(void*);
  int   (*get_error)(const void*, int);
  int   (*has_pending)(const void*);
  long  (*verify_result)(const void*);
  const char* (*verify_string)(long);
  unsigned long (*err_get)(void);
  void  (*err_string)(unsigned long, char*, size_t);
  void  (*err_clear)(void);
} NetSsl;

static NetSsl net_ssl;

// A session per descriptor: the SSL and its context, or NULL for plain.
typedef struct {
  void* ssl;
  void* ctx;
  int   server;
} NetTls;

#define NET_FDS 65536
static NetTls net_tab[NET_FDS];

static NetTls* net_at(int fd) {
  return fd >= 0 && fd < NET_FDS && net_tab[fd].ssl != NULL ? &net_tab[fd]
    : NULL;
}

static char net_msg[512];

static void* net_sym(const char* name, int* ok) {
  void* p = dlsym(net_ssl.lib, name);
  if (p == NULL) {
    *ok = 0;
  }
  return p;
}

// Opens libssl once and finds every call above; 0 if any is missing.
static int net_load(void) {
  if (net_ssl.tried) {
    return net_ssl.ok;
  }
  net_ssl.tried = 1;
  const char* names[] = {
    "libssl.so.3", "libssl.so.1.1", "libssl.so", "libssl.3.dylib",
    "/opt/homebrew/opt/openssl@3/lib/libssl.3.dylib",
    "/usr/local/opt/openssl@3/lib/libssl.3.dylib", NULL };
  for (int i = 0; names[i] != NULL && net_ssl.lib == NULL; i += 1) {
    net_ssl.lib = dlopen(names[i], RTLD_NOW | RTLD_GLOBAL);
  }
  if (net_ssl.lib == NULL) {
    return 0;
  }
  int ok = 1;
  net_ssl.client_method      = net_sym("TLS_client_method", &ok);
  net_ssl.server_method      = net_sym("TLS_server_method", &ok);
  net_ssl.ctx_use_chain      = net_sym("SSL_CTX_use_certificate_chain_file", &ok);
  net_ssl.ctx_use_key        = net_sym("SSL_CTX_use_PrivateKey_file", &ok);
  net_ssl.ctx_check_key      = net_sym("SSL_CTX_check_private_key", &ok);
  net_ssl.do_accept          = net_sym("SSL_accept", &ok);
  net_ssl.ctx_new            = net_sym("SSL_CTX_new", &ok);
  net_ssl.ctx_free           = net_sym("SSL_CTX_free", &ok);
  net_ssl.ctx_ctrl           = net_sym("SSL_CTX_ctrl", &ok);
  net_ssl.ctx_default_paths  = net_sym("SSL_CTX_set_default_verify_paths", &ok);
  net_ssl.ctx_load_locations = net_sym("SSL_CTX_load_verify_locations", &ok);
  net_ssl.ctx_set_verify     = net_sym("SSL_CTX_set_verify", &ok);
  net_ssl.ssl_new            = net_sym("SSL_new", &ok);
  net_ssl.ssl_free           = net_sym("SSL_free", &ok);
  net_ssl.set_fd             = net_sym("SSL_set_fd", &ok);
  net_ssl.ssl_ctrl           = net_sym("SSL_ctrl", &ok);
  net_ssl.set1_host          = net_sym("SSL_set1_host", &ok);
  net_ssl.get0_param         = net_sym("SSL_get0_param", &ok);
  net_ssl.param_set1_ip_asc  = net_sym("X509_VERIFY_PARAM_set1_ip_asc", &ok);
  net_ssl.do_connect         = net_sym("SSL_connect", &ok);
  net_ssl.do_read            = net_sym("SSL_read", &ok);
  net_ssl.do_write           = net_sym("SSL_write", &ok);
  net_ssl.do_shutdown        = net_sym("SSL_shutdown", &ok);
  net_ssl.get_error          = net_sym("SSL_get_error", &ok);
  net_ssl.has_pending        = net_sym("SSL_has_pending", &ok);
  net_ssl.verify_result      = net_sym("SSL_get_verify_result", &ok);
  net_ssl.verify_string      = net_sym("X509_verify_cert_error_string", &ok);
  net_ssl.err_get            = net_sym("ERR_get_error", &ok);
  net_ssl.err_string         = net_sym("ERR_error_string_n", &ok);
  net_ssl.err_clear          = net_sym("ERR_clear_error", &ok);
  net_ssl.ok = ok;
  return ok;
}

// The reason an OpenSSL call failed, in net_msg.
static const char* net_why(void* ssl, const char* what) {
  long v = ssl != NULL ? net_ssl.verify_result(ssl) : 0;
  if (v != 0) {
    snprintf(net_msg, sizeof(net_msg), "%s: certificate: %s", what,
      net_ssl.verify_string(v));
    return net_msg;
  }
  unsigned long e = net_ssl.err_get();
  char buf[256] = "unknown error";
  if (e != 0) {
    net_ssl.err_string(e, buf, sizeof(buf));
  }
  snprintf(net_msg, sizeof(net_msg), "%s: %s", what, buf);
  return net_msg;
}

static void net_drop(int fd) {
  NetTls* t = net_at(fd);
  if (t != NULL) {
    net_ssl.ssl_free(t->ssl);
    net_ssl.ctx_free(t->ctx);
    t->ssl = NULL;
    t->ctx = NULL;
  }
}

// Net.connect
// -----------

// On a helper thread: resolve the name (IPv4 or IPv6), then try each
// address with a bounded connect; the socket ends non-blocking.
static void net_connect_call(IoWork* w) {
  char port[16];
  snprintf(port, sizeof(port), "%u", (unsigned)w->word);
  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family   = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  struct addrinfo* res = NULL;
  int g = getaddrinfo(w->data, port, &hints, &res);
  w->made = -1;
  if (g != 0) {
    w->code = g == EAI_SYSTEM ? (u32)errno : 0;
    w->text = (char*)gai_strerror(g);
    return;
  }
  w->code = ECONNREFUSED;
  w->text = NULL;
  for (struct addrinfo* a = res; a != NULL && w->made < 0; a = a->ai_next) {
    int fd = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
    if (fd < 0) {
      w->code = (u32)errno;
      continue;
    }
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    int r = connect(fd, a->ai_addr, a->ai_addrlen);
    if (r < 0 && errno == EINPROGRESS) {
      struct pollfd p = { fd, POLLOUT, 0 };
      int n = poll(&p, 1, NET_CONNECT_MS);
      int err = n == 0 ? ETIMEDOUT : 0;
      socklen_t len = sizeof(err);
      if (n > 0 && getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) != 0) {
        err = errno;
      }
      r = err == 0 ? 0 : -1;
      errno = err;
    }
    if (r < 0) {
      w->code = (u32)errno;
      close(fd);
      continue;
    }
    w->made = fd;
    w->code = 0;
  }
  freeaddrinfo(res);
}

static Term net_connect_pack(Env e, IoWork* w) {
  free(w->data);
  if (w->made < 0) {
    return io_fail(e, w->code, w->text);
  }
  return io_done(e, io_hand(w->made));
}

Term net_connect_run(Env e, Term* f, IoWork* w) {
  w->data = io_cstr(e, f[0], &w->size);
  w->word = (u32)f[1];
  w->code = 0;
  w->text = NULL;
  if (io_nul(w->data, w->size) || (u32)f[1] > 65535) {
    free(w->data);
    return io_fail(e, EINVAL, NULL);
  }
  return io_work(w, net_connect_call, net_connect_pack);
}

static void __attribute__((constructor)) net_connect_use(void) {
#ifdef CID_NET_CONNECT
  io_eff(CID_NET_CONNECT, net_connect_run, 0);
#endif
}

// Net.tls
// -------

static Term net_tls_end(Env e, IoWork* w, Term r) {
  return io_tup(e, io_hand(w->hand), r);
}

static Term net_tls_fail(Env e, IoWork* w, const char* msg) {
  net_drop((int)w->hand);
  return net_tls_end(e, w, io_fail(e, 0, msg));
}

// One handshake step; a step that wants the socket parks until it is
// ready, and a handshake past its deadline fails.
static Term net_tls_more(Env e, IoWork* w) {
  NetTls* t = net_at((int)w->hand);
  if (t == NULL) {
    return net_tls_end(e, w, io_fail(e, EBADF, NULL));
  }
  net_ssl.err_clear();
  int r = t->server ? net_ssl.do_accept(t->ssl) : net_ssl.do_connect(t->ssl);
  if (r == 1) {
    return net_tls_end(e, w, io_done(e, term_pak(CID_UNIT, 0)));
  }
  int k = net_ssl.get_error(t->ssl, r);
  u64 at = (u64)w->made;
  if ((k == NET_WANT_READ || k == NET_WANT_WRITE) && io_tick() < at) {
    return io_wait_on(w, (int)w->hand, k == NET_WANT_READ ? POLLIN : POLLOUT,
      at, net_tls_more);
  }
  if (k == NET_WANT_READ || k == NET_WANT_WRITE) {
    return net_tls_fail(e, w, "tls: the handshake timed out");
  }
  return net_tls_fail(e, w, net_why(t->ssl, "tls"));
}

// Net.tls(sock, host, cafile): a verified TLS 1.2+ session on the socket,
// for host (its name or IP must be on the certificate); cafile "" trusts
// the system's store.
Term net_tls_run(Env e, Term* f, IoWork* w) {
  w->hand = (intptr_t)io_hand_v(f[0]);
  int   fd = (int)w->hand;
  u64   hn = 0, cn = 0;
  char* host = io_cstr(e, f[1], &hn);
  char* ca   = io_cstr(e, f[2], &cn);
  const char* bad = NULL;
  if (!net_load()) {
    bad = "tls: libssl (OpenSSL 1.1 or 3) was not found";
  } else if (fd < 0 || fd >= NET_FDS || net_at(fd) != NULL) {
    bad = "tls: this socket cannot start TLS";
  } else if (io_nul(host, hn) || io_nul(ca, cn) || hn == 0) {
    bad = "tls: a host name is needed";
  }
  if (bad != NULL) {
    free(host);
    free(ca);
    return net_tls_end(e, w, io_fail(e, 0, bad));
  }
  net_ssl.err_clear();
  void* ctx = net_ssl.ctx_new(net_ssl.client_method());
  void* ssl = NULL;
  int   ok  = ctx != NULL;
  ok = ok && net_ssl.ctx_ctrl(ctx, NET_SET_MIN_PROTO, NET_TLS1_2, NULL) == 1;
  ok = ok && (cn > 0 ? net_ssl.ctx_load_locations(ctx, ca, NULL)
    : net_ssl.ctx_default_paths(ctx)) == 1;
  if (ok) {
    net_ssl.ctx_set_verify(ctx, NET_VERIFY_PEER, NULL);
    ssl = net_ssl.ssl_new(ctx);
    ok = ssl != NULL && net_ssl.set_fd(ssl, fd) == 1;
  }
  // An IP literal is checked against the certificate's IP entries and sent
  // no SNI (RFC 6066 3: SNI names are host names only).
  unsigned char ip[16];
  int lit = inet_pton(AF_INET, host, ip) == 1 || inet_pton(AF_INET6, host, ip) == 1;
  if (ok && lit) {
    ok = net_ssl.param_set1_ip_asc(net_ssl.get0_param(ssl), host) == 1;
  } else if (ok) {
    ok = net_ssl.ssl_ctrl(ssl, NET_SET_SNI, 0, host) == 1
      && net_ssl.set1_host(ssl, host) == 1;
  }
  free(host);
  free(ca);
  if (!ok) {
    const char* why = net_why(NULL, "tls setup");
    if (ssl != NULL) {
      net_ssl.ssl_free(ssl);
    }
    if (ctx != NULL) {
      net_ssl.ctx_free(ctx);
    }
    return net_tls_end(e, w, io_fail(e, 0, why));
  }
  net_tab[fd].ssl = ssl;
  net_tab[fd].ctx = ctx;
  net_tab[fd].server = 0;
  w->made = (intptr_t)(io_tick() + (u64)NET_HANDSHAKE_MS * 1000000ull);
  return net_tls_more(e, w);
}

static void __attribute__((constructor)) net_tls_use(void) {
#ifdef CID_NET_TLS
  io_eff(CID_NET_TLS, net_tls_run, 0);
#endif
}

// Net.tls_accept(sock, cert, key): the server's side of the handshake,
// with a PEM certificate chain and its PEM key; the client is not asked
// for a certificate.
Term net_tls_accept_run(Env e, Term* f, IoWork* w) {
  w->hand = (intptr_t)io_hand_v(f[0]);
  int   fd = (int)w->hand;
  u64   cn = 0, kn = 0;
  char* cert = io_cstr(e, f[1], &cn);
  char* key  = io_cstr(e, f[2], &kn);
  const char* bad = NULL;
  if (!net_load()) {
    bad = "tls: libssl (OpenSSL 1.1 or 3) was not found";
  } else if (fd < 0 || fd >= NET_FDS || net_at(fd) != NULL) {
    bad = "tls: this socket cannot start TLS";
  } else if (io_nul(cert, cn) || io_nul(key, kn) || cn == 0 || kn == 0) {
    bad = "tls: a certificate and a key are needed";
  }
  if (bad != NULL) {
    free(cert);
    free(key);
    return net_tls_end(e, w, io_fail(e, 0, bad));
  }
  net_ssl.err_clear();
  void* ctx = net_ssl.ctx_new(net_ssl.server_method());
  void* ssl = NULL;
  int   ok  = ctx != NULL;
  ok = ok && net_ssl.ctx_ctrl(ctx, NET_SET_MIN_PROTO, NET_TLS1_2, NULL) == 1;
  ok = ok && net_ssl.ctx_use_chain(ctx, cert) == 1;
  ok = ok && net_ssl.ctx_use_key(ctx, key, NET_FILETYPE_PEM) == 1;
  ok = ok && net_ssl.ctx_check_key(ctx) == 1;
  if (ok) {
    ssl = net_ssl.ssl_new(ctx);
    ok = ssl != NULL && net_ssl.set_fd(ssl, fd) == 1;
  }
  free(cert);
  free(key);
  if (!ok) {
    const char* why = net_why(NULL, "tls setup");
    if (ssl != NULL) {
      net_ssl.ssl_free(ssl);
    }
    if (ctx != NULL) {
      net_ssl.ctx_free(ctx);
    }
    return net_tls_end(e, w, io_fail(e, 0, why));
  }
  net_tab[fd].ssl = ssl;
  net_tab[fd].ctx = ctx;
  net_tab[fd].server = 1;
  w->made = (intptr_t)(io_tick() + (u64)NET_HANDSHAKE_MS * 1000000ull);
  return net_tls_more(e, w);
}

static void __attribute__((constructor)) net_tls_accept_use(void) {
#ifdef CID_NET_TLS_ACCEPT
  io_eff(CID_NET_TLS_ACCEPT, net_tls_accept_run, 0);
#endif
}

// Net.send
// --------

// Sends what is left, through the session if there is one; a full socket
// (or a TLS write that wants a read) parks until the socket is ready.
static Term net_send_more(Env e, IoWork* w) {
  int     fd = (int)w->hand;
  NetTls* t  = net_at(fd);
  while (w->code == 0 && (u64)w->made < w->size) {
    char* p    = w->data + w->made;
    u64   left = w->size - (u64)w->made;
    if (t == NULL) {
      ssize_t n = send(fd, p, left, MSG_NOSIGNAL);
      if (n < 0 && errno == EAGAIN) {
        return io_wait_on(w, fd, POLLOUT, 0, net_send_more);
      }
      w->made += io_sys_end(w, n);
      continue;
    }
    net_ssl.err_clear();
    int n = net_ssl.do_write(t->ssl, p, left > INT32_MAX ? INT32_MAX : (int)left);
    if (n > 0) {
      w->made += n;
      continue;
    }
    int k = net_ssl.get_error(t->ssl, n);
    if (k == NET_WANT_READ || k == NET_WANT_WRITE) {
      return io_wait_on(w, fd, k == NET_WANT_READ ? POLLIN : POLLOUT, 0,
        net_send_more);
    }
    w->code = k == NET_SYSCALL && errno != 0 ? (u32)errno : EPIPE;
    w->text = k == NET_SYSCALL ? NULL : (char*)net_why(t->ssl, "tls send");
  }
  Term r = w->code != 0 ? io_fail(e, w->code, w->text)
    : io_done(e, term_pak(CID_UNIT, 0));
  free(w->data);
  return io_tup(e, io_hand(w->hand), r);
}

Term net_send_run(Env e, Term* f, IoWork* w) {
  w->hand = (intptr_t)io_hand_v(f[0]);
  w->data = io_cstr(e, f[1], &w->size);
  w->made = 0;
  w->code = 0;
  w->text = NULL;
  return net_send_more(e, w);
}

static void __attribute__((constructor)) net_send_use(void) {
#ifdef CID_NET_SEND
  io_eff(CID_NET_SEND, net_send_run, 0);
#endif
}

// Net.poll
// --------

// Net.poll(sock, max, ms): up to max bytes, Some{""} on the peer's close,
// None{} when ms pass with nothing. A TLS session may hold decrypted bytes
// the socket no longer shows, so it is read before any wait.
static Term net_poll_end(Env e, IoWork* w, Term r) {
  free(w->data);
  return io_tup(e, io_hand(w->hand), r);
}

static Term net_poll_some(Env e, IoWork* w, u64 n) {
  return net_poll_end(e, w, io_done(e,
    io_box(e, CID_SOME, io_str(e, w->data, n))));
}

static Term net_poll_more(Env e, IoWork* w) {
  int     fd = (int)w->hand;
  NetTls* t  = net_at(fd);
  u64     at = (u64)w->size;
  short   ev = POLLIN;
  if (t == NULL) {
    ssize_t n = recv(fd, w->data, (size_t)w->made, 0);
    if (n >= 0) {
      return net_poll_some(e, w, (u64)n);
    }
    if (errno != EAGAIN) {
      return net_poll_end(e, w, io_fail(e, (u32)errno, NULL));
    }
  } else {
    net_ssl.err_clear();
    int n = net_ssl.do_read(t->ssl, w->data, (int)w->made);
    if (n > 0) {
      return net_poll_some(e, w, (u64)n);
    }
    int k = net_ssl.get_error(t->ssl, n);
    if (k == NET_ZERO_RETURN || (k == NET_SYSCALL && n == 0)) {
      return net_poll_some(e, w, 0);
    }
    if (k != NET_WANT_READ && k != NET_WANT_WRITE) {
      return net_poll_end(e, w, io_fail(e, k == NET_SYSCALL ? (u32)errno : 0,
        k == NET_SYSCALL ? NULL : net_why(t->ssl, "tls recv")));
    }
    ev = k == NET_WANT_READ ? POLLIN : POLLOUT;
  }
  if (io_tick() >= at) {
    return net_poll_end(e, w, io_done(e, term_pak(CID_NONE, 0)));
  }
  return io_wait_on(w, fd, ev, at, net_poll_more);
}

Term net_poll_run(Env e, Term* f, IoWork* w) {
  w->hand = (intptr_t)io_hand_v(f[0]);
  w->made = f[1] > 0 && f[1] < INT32_MAX ? (intptr_t)f[1] : 4096;
  w->size = io_tick() + (u64)f[2] * 1000000ull;
  w->data = io_mem(malloc((size_t)w->made + 1));
  return net_poll_more(e, w);
}

static void __attribute__((constructor)) net_poll_use(void) {
#ifdef CID_NET_POLL
  io_eff(CID_NET_POLL, net_poll_run, 0);
#endif
}

// Net.close
// ---------

// Ends the session (one close_notify, not waited on) and the socket.
Term net_close_run(Env e, Term* f, IoWork* w) {
  int     fd = (int)io_hand_v(f[0]);
  NetTls* t  = net_at(fd);
  if (t != NULL) {
    net_ssl.do_shutdown(t->ssl);
    net_drop(fd);
  }
  close(fd);
  return term_pak(CID_UNIT, 0);
}

static void __attribute__((constructor)) net_close_use(void) {
#ifdef CID_NET_CLOSE
  io_eff(CID_NET_CLOSE, net_close_run, 0);
#endif
}

// Net.time, Net.helo
// ------------------

// Seconds since 1970 (UTC), for the Date header.
Term net_time_run(Env e, Term* f, IoWork* w) {
  return (Term)(u32)time(NULL);
}

static void __attribute__((constructor)) net_time_use(void) {
#ifdef CID_NET_TIME
  io_eff(CID_NET_TIME, net_time_run, 0);
#endif
}

// The host's own name, as gethostname says it (for HELO, whose argument
// must be a domain, never an address literal).
Term net_hostname_run(Env e, Term* f, IoWork* w) {
  char name[300] = "localhost";
  if (gethostname(name, 256) != 0 || name[0] == 0) {
    strcpy(name, "localhost");
  }
  return io_str(e, name, strlen(name));
}

static void __attribute__((constructor)) net_hostname_use(void) {
#ifdef CID_NET_HOSTNAME
  io_eff(CID_NET_HOSTNAME, net_hostname_run, 0);
#endif
}

// The name to give EHLO (RFC 5321 4.1.4): the host's name when it is
// fully qualified, else the connection's own address as a literal
// ("[192.0.2.1]", "[IPv6:2001:db8::1]").
Term net_helo_run(Env e, Term* f, IoWork* w) {
  int  fd = (int)io_hand_v(f[0]);
  char name[300] = "";
  if (gethostname(name, 256) != 0 || strchr(name, '.') == NULL
      || name[strlen(name) - 1] == '.') {
    struct sockaddr_storage ss;
    socklen_t len = sizeof(ss);
    char ip[INET6_ADDRSTRLEN] = "127.0.0.1";
    int  v6 = 0;
    if (getsockname(fd, (struct sockaddr*)&ss, &len) == 0) {
      if (ss.ss_family == AF_INET6) {
        v6 = 1;
        inet_ntop(AF_INET6, &((struct sockaddr_in6*)&ss)->sin6_addr, ip,
          sizeof(ip));
      } else {
        inet_ntop(AF_INET, &((struct sockaddr_in*)&ss)->sin_addr, ip, sizeof(ip));
      }
    }
    snprintf(name, sizeof(name), v6 ? "[IPv6:%s]" : "[%s]", ip);
  }
  return io_tup(e, io_hand(fd), io_str(e, name, strlen(name)));
}

static void __attribute__((constructor)) net_helo_use(void) {
#ifdef CID_NET_HELO
  io_eff(CID_NET_HELO, net_helo_run, 0);
#endif
}
