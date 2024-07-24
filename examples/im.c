#include <sqlite3.h>

#include <mbedtls/base64.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/ssl.h>

#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/poll.h>
#include <stdbool.h>

#include "xmpp.h"
#include "cacert.inc"

#define Log(fmt, ...) printf(fmt "\n" __VA_OPT__(,) __VA_ARGS__)

#define DB_FILE "o/im.db"

static sqlite3 *db;
static struct xmppClient client;

static void AddMessage(const char *body, int id) {
  static sqlite3_stmt *stmt;
  int rc =
      sqlite3_prepare(db, "insert into message(id, body) values (?, ?)",
                      -1, &stmt, NULL);
  assert(rc == SQLITE_OK);
  rc = sqlite3_bind_int(stmt, 1, id);
  assert(rc == SQLITE_OK);
  rc = sqlite3_bind_text(stmt, 2, body, -1, NULL);
  assert(rc == SQLITE_OK);
  rc = sqlite3_step(stmt);
  assert(rc == SQLITE_DONE);
  sqlite3_finalize(stmt);
}

static struct {
  mbedtls_ssl_context ssl;
  mbedtls_net_context server_fd;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_x509_crt cacert;
  mbedtls_ssl_config conf;
} conn;

static void InitializeConn(const char *server, const char *port) {
  mbedtls_ssl_init(&conn.ssl);
  mbedtls_x509_crt_init(&conn.cacert);
  mbedtls_ctr_drbg_init(&conn.ctr_drbg);
  mbedtls_ssl_config_init(&conn.conf);
  mbedtls_entropy_init(&conn.entropy);
  assert(mbedtls_ctr_drbg_seed(&conn.ctr_drbg, mbedtls_entropy_func,
                               &conn.entropy, NULL, 0) == 0);
  //assert(mbedtls_x509_crt_parse_file(
  //           &conn.cacert, "/etc/ssl/certs/ca-certificates.crt") >= 0);
  assert(mbedtls_x509_crt_parse(&conn.cacert, cacert_pem, cacert_pem_len) >=
         0);
  assert(mbedtls_ssl_set_hostname(&conn.ssl, server) == 0);
  assert(mbedtls_ssl_config_defaults(&conn.conf, MBEDTLS_SSL_IS_CLIENT,
                                     MBEDTLS_SSL_TRANSPORT_STREAM,
                                     MBEDTLS_SSL_PRESET_DEFAULT) == 0);
  mbedtls_ssl_conf_authmode(&conn.conf, MBEDTLS_SSL_VERIFY_REQUIRED);
  mbedtls_ssl_conf_ca_chain(&conn.conf, &conn.cacert, NULL);
  mbedtls_ssl_conf_rng(&conn.conf, mbedtls_ctr_drbg_random,
                       &conn.ctr_drbg);
  assert(mbedtls_ssl_setup(&conn.ssl, &conn.conf) == 0);
  mbedtls_net_init(&conn.server_fd);
  assert(mbedtls_net_connect(&conn.server_fd, server, port,
                             MBEDTLS_NET_PROTO_TCP) == 0);
  mbedtls_ssl_set_bio(&conn.ssl, &conn.server_fd, mbedtls_net_send,
                      mbedtls_net_recv, NULL);
}

static bool Poll() {
  struct pollfd fds[2] = {0};
  fds[0].fd = STDIN_FILENO;
  fds[0].events = POLLIN;
  fds[1].fd = conn.server_fd.fd;
  fds[1].events = POLLIN;
  int r = poll(fds, 2, -1);
  assert(r >= 0);
  if (fds[0].revents & POLLIN)
    return false;
  if (fds[1].revents & POLLIN)
    return true;
  assert(false);
}

static void SendAll() {
  int n, i = 0;
  do {
    if (client.features & XMPP_STREAMFEATURE_STARTTLS)
      n = mbedtls_ssl_write(&conn.ssl, client.comp.p+i, client.comp.n-i);
    else
      n = mbedtls_net_send(&conn.server_fd, client.comp.p+i, client.comp.n-i);
    i += n;
  } while (n > 0);
  client.comp.n = 0;
  memset(client.comp.p, 0, client.comp.c); // just in case
}

static void Handshake() {
  int r;
  while ((r = mbedtls_ssl_handshake(&conn.ssl)) != 0)
    assert(r == MBEDTLS_ERR_SSL_WANT_READ ||
           r == MBEDTLS_ERR_SSL_WANT_WRITE);
  assert(mbedtls_ssl_get_verify_result(&conn.ssl) == 0);
}

static void IterateClient() {
  int r;
  for (;;) {
    switch ((r = xmppIterate(&client))) {
    case XMPP_ITER_SEND:
      Log("Out: \e[32m%.*s\e[0m", (int)client.comp.n, client.comp.p);
      SendAll();
      break;
    case XMPP_ITER_READY:
      if (!Poll())
        return;
      // fallthrough
    case XMPP_ITER_RECV:
      Log("Waiting for recv...");
      if (client.features & XMPP_STREAMFEATURE_STARTTLS)
        r = mbedtls_ssl_read(&conn.ssl, client.parser.p+client.parser.n, client.parser.c-client.parser.n);
      else
        r = mbedtls_net_recv(&conn.server_fd, client.parser.p+client.parser.n, client.parser.c-client.parser.n);
      assert(r >= 0);
      client.parser.n += r;
      Log("In:  \e[34m%.*s\e[0m", (int)client.parser.n, client.parser.p);
      break;
    case XMPP_ITER_STARTTLS:
      Handshake();
      break;
    case XMPP_ITER_GIVEPWD:
      xmppSupplyPassword(&client, "adminpass");
      break;
    case XMPP_ITER_STANZA:
      break;
    case XMPP_ITER_OK:
    default:
      break;
    }
  }
}

static void Loop() {
  char *line = NULL, *msgbody;
  size_t n;
  xmppInitClient(&client, "admin@localhost/resource", 0);
  for (;;) {
    IterateClient();
    getline(&line, &n, stdin);
    xmppSendMessage(&client, "admin@localhost", "hello there!");
  }

  //while (getline(&line, &n, stdin) != -1) {
  //  // if (!strncmp(line, "/msg ", 5)) {
  //  //   msgbody = line+5;
  //  //   AddMessage(msgbody, 0);
  //  // }
  //  if (line[0] != '\n') {
  //    AddMessage(line, 0);
  //    mbedtls_net_send(&conn.server_fd, line, strlen(line));
  //    puts("message sent!");
  //  }
  //}
  free(line);
}

int main() {
  unlink(DB_FILE);
  int rc = sqlite3_open(DB_FILE, &db);
  assert(rc == SQLITE_OK);
  rc = sqlite3_exec(db, "create table if not exists message(id, body)",
                    NULL, NULL, NULL);
  assert(rc == SQLITE_OK);
  InitializeConn("localhost", "5222"); // $ nc -l -p 10444
  Loop();
  sqlite3_close(db);
}
