/**
 * Copyright 2024 mierenhoop
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "../example/xmpp.c"

#include <sys/poll.h>

#include "cacert.inc"

#define Log(fmt, ...) fprintf(stdout, fmt "\n" __VA_OPT__(,) __VA_ARGS__)
#define LogWarn(fmt, ...) fprintf(stdout, "\e[33m" fmt "\e[0m\n" __VA_OPT__(,) __VA_ARGS__)

int xmppRandom(void *p, size_t n) { return getrandom(p, n, 0) != n; }

static mbedtls_ssl_context ssl;
static mbedtls_net_context server_fd;
static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;
static mbedtls_x509_crt cacert;
static mbedtls_ssl_config conf;

static struct xmppClient client;
static struct StaticData sd;

static void SetupTls(const char *domain, const char *port) {
  mbedtls_ssl_init(&ssl);
  mbedtls_x509_crt_init(&cacert);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_ssl_config_init(&conf);
  mbedtls_entropy_init(&entropy);

  assert(mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                               &entropy, NULL, 0) == 0);
  assert(mbedtls_x509_crt_parse(&cacert, cacert_pem, cacert_pem_len) >=
         0);

  assert(mbedtls_ssl_set_hostname(&ssl, domain) == 0);
  assert(mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                     MBEDTLS_SSL_TRANSPORT_STREAM,
                                     MBEDTLS_SSL_PRESET_DEFAULT) == 0);
  mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
  mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
  mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
  mbedtls_ssl_conf_max_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_2);
  assert(mbedtls_ssl_setup(&ssl, &conf) == 0);

  mbedtls_net_init(&server_fd);
  assert(mbedtls_net_connect(&server_fd, domain, port,
                             MBEDTLS_NET_PROTO_TCP) == 0);
  mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send,
                      mbedtls_net_recv, NULL);
}

static void CleanupTls() {
  mbedtls_ssl_close_notify(&ssl);
  mbedtls_net_free(&server_fd);
  mbedtls_x509_crt_free(&cacert);
  mbedtls_ssl_free(&ssl);
  mbedtls_ssl_config_free(&conf);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
}

static void NetSend() {
  char *buf;
  size_t sz;
  int n;
  bool istls;
  xmppGetSendBuffer(&client, &buf, &sz, &istls);
  if (istls)
    n = mbedtls_ssl_write(&ssl, buf, sz);
  else
    n = mbedtls_net_send(&server_fd, buf, sz);
  assert(n > 0);
  xmppAddAmountSent(&client, n);
}

static void Receive() {
  int r;
  char *buf;
  size_t maxsz;
  bool istls;
  xmppGetReceiveBuffer(&client, &buf, &maxsz, &istls);
  if (istls)
    r = mbedtls_ssl_read(&ssl, buf, maxsz);
  else
    r = mbedtls_net_recv(&server_fd, buf, maxsz);
  assert(r >= 0);
  xmppAddAmountReceived(&client, r);
}

static bool HasDataAvailable() {
  struct pollfd pfd = {0};
  pfd.fd = server_fd.fd;
  pfd.events = POLLIN;
  int r = poll(&pfd, 1, 200);
  assert(r >= 0);
  return r && pfd.revents & POLLIN;
}

static void TestClient() {
  SetupTls("localhost", "5222");
  xmppInitClient(&client, &sd, "admin@localhost/resource", 0);
  bool sent = false;
  int r;
  while ((r = xmppIterate(&client))) {
    switch (r) {
    case XMPP_ITER_SEND:
      Log("Out: \e[32m%.*s\e[0m", (int)client.builder.n, client.builder.p);
      NetSend();
      break;
    case XMPP_ITER_READY:
      if (!sent) {
        xmppFormatStanza(&client, "<message to='%s' id='%s'><body>%s</body></message>", "admin@localhost", "message1", "Hello!");
        sent = true;
        break;
      }
      if (!HasDataAvailable())
        goto stop;
      // fallthrough
    case XMPP_ITER_RECV:
      Log("Waiting for recv...");
      Receive();
      Log("In:  \e[34m%.*s\e[0m", (int)client.parser.n, client.parser.p);
      break;
    case XMPP_ITER_STARTTLS:
      while ((r = mbedtls_ssl_handshake(&ssl)) != 0) {
        Log("%d", r);
        assert(r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE);
      }
      assert(mbedtls_ssl_get_verify_result(&ssl) == 0);
      break;
    case XMPP_ITER_GIVEPWD:
      xmppSupplyPassword(&client, "adminpass");
      break;
    case XMPP_ITER_STANZA:
      break;
    case XMPP_ITER_OK:
    default:
      if (r < 0) {
        Log("Error %d", r);
        goto stop;
      }
      break;
    }
  }
stop:
  CleanupTls();
}

static void TestXmlSlice() {
  char buf[12];
  struct xmppXmlSlice slc = {0};
  slc.p = "'test'",
  slc.rawn = 6,
  slc.n = 4,
  assert(xmppCompareXmlSlice("test", &slc));
  assert(!xmppCompareXmlSlice("atest", &slc));
  assert(!xmppCompareXmlSlice("testa", &slc));
  xmppReadXmlSlice(buf, &slc);
  assert(!strcmp(buf, "test"));
  slc.p = "\"&lt;test&gt;\"";
  slc.rawn = 14;
  slc.n = 6;
  assert(xmppCompareXmlSlice("<test>", &slc));
  assert(!xmppCompareXmlSlice("a<test>", &slc));
  assert(!xmppCompareXmlSlice("<test>a", &slc));
  xmppReadXmlSlice(buf, &slc);
  assert(!strcmp(buf, "<test>"));
  slc.p = ">test<";
  slc.rawn = 6;
  slc.n = 4;
  assert(xmppCompareXmlSlice("test", &slc));
  assert(!xmppCompareXmlSlice("atest", &slc));
  assert(!xmppCompareXmlSlice("testa", &slc));
  xmppReadXmlSlice(buf, &slc);
  assert(!strcmp(buf, "test"));
  int32_t i = 0xcc;
  slc.p = "'1000'";
  slc.rawn = 6;
  slc.n = 4;
  assert(xmppDecodeIntXmlSlice(&i, &slc) && i == 1000);
  slc.p = "'-10'";
  slc.rawn = 5;
  slc.n = 3;
  assert(xmppDecodeIntXmlSlice(&i, &slc) && i == -10);
  slc.p = "''";
  slc.rawn = 2;
  slc.n = 0;
  assert(!xmppDecodeIntXmlSlice(&i, &slc));
}

static char in[50000], xbuf[2000];

static struct xmppParser SetupXmppParser(const char *xml) {
  struct xmppParser p = {0};
  p.p = in;
  p.c = sizeof(in);
  strcpy(p.p, xml);
  p.n = strlen(p.p);
  p.xbuf = xbuf;
  p.xbufn = sizeof(xbuf);
  return p;
}

static void TestXml() {
  struct xmppStanza st;
	struct xmppParser p = SetupXmppParser(
			"<?xml version='1.0'?>"
			"<stream:stream"
			" from='im.example.com'"
			" id='++TR84Sm6A3hnt3Q065SnAbbk3Y='"
			" to='juliet@im.example.com'"
			" version='1.0'"
			" xml:lang='en'"
			" xmlns='jabber:client'"
			" xmlns:stream='http://etherx.jabber.org/streams'>"
      "<stream:features>"
      "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls>"
      "</stream:features>"
      );
  assert(xmppParseStanza(&p, &st, false) == 0);
  assert(xmppCompareXmlSlice("juliet@im.example.com", &st.to));
}

static void ExpectUntil(int goal, const char *exp) {
  for (;;) {
    int r = xmppIterate(&client);
    if (goal && r == goal)
      return;
    switch (r) {
    case XMPP_ITER_SEND:
      if (strncmp(client.builder.p, exp, client.builder.n)) {
        Log("Expected %s, but got %.*s", exp, (int)client.builder.n, client.builder.p);
        assert(false);
      }
      exp += client.builder.n;
      client.builder.n = 0;
      break;
    case XMPP_ITER_OK:
      break;
    default:
      Log("Expected goal %d, but got %d", goal, r);
      assert(false);
    }
  }
  assert(false);
}

static void Send(const char *s) {
  strcpy(client.parser.p+client.parser.n, s);
  client.parser.n += strlen(s);
}

static void SetupStream() {
  xmppInitClient(&client, &sd, "admin@localhost/resource", XMPP_OPT_FORCEPLAIN);
  ExpectUntil(XMPP_ITER_RECV, "<?xml version='1.0'?><stream:stream xmlns='jabber:client' version='1.0' xmlns:stream='http://etherx.jabber.org/streams' to='localhost'>");
  Send("<?xml version='1.0'?><stream:stream from='localhost' xml:lang='en' id='some-stream-id' version='1.0' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'><stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>SCRAM-SHA-1</mechanism></mechanisms><register xmlns='urn:xmpp:invite'/><register xmlns='urn:xmpp:ibr-token:0'/><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/><register xmlns='http://jabber.org/features/iq-register'/></stream:features>");
  ExpectUntil(XMPP_ITER_RECV, "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>");
  Send("<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>");
  ExpectUntil(XMPP_ITER_STARTTLS, "");
  ExpectUntil(XMPP_ITER_RECV, "<?xml version='1.0'?><stream:stream xmlns='jabber:client' version='1.0' xmlns:stream='http://etherx.jabber.org/streams' to='localhost'>");
  Send("<?xml version='1.0'?><stream:stream from='localhost' xml:lang='en' id='some-stream-id-2' version='1.0' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'><stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>SCRAM-SHA-1</mechanism><mechanism>SCRAM-SHA-1-PLUS</mechanism><mechanism>PLAIN</mechanism></mechanisms><register xmlns='urn:xmpp:invite'/><register xmlns='urn:xmpp:ibr-token:0'/><register xmlns='http://jabber.org/features/iq-register'/></stream:features>");
  ExpectUntil(XMPP_ITER_GIVEPWD, "");
  xmppSupplyPassword(&client, "adminpass");
  ExpectUntil(XMPP_ITER_RECV, "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>AGFkbWluAGFkbWlucGFzcw==</auth>");
  Send("<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>");
  ExpectUntil(XMPP_ITER_RECV, "<?xml version='1.0'?><stream:stream xmlns='jabber:client' version='1.0' xmlns:stream='http://etherx.jabber.org/streams' to='localhost'>");
  Send("<?xml version='1.0'?><stream:stream from='localhost' xml:lang='en' id='8824a41e-dca3-4770-888f-493f858ce800' version='1.0' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'><stream:features><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><required/></bind><session xmlns='urn:ietf:params:xml:ns:xmpp-session'><optional/></session><sub xmlns='urn:xmpp:features:pre-approval'/><c ver='WmLhVdPgNBF2TJv5X+4p6F0IMeM=' hash='sha-1' xmlns='http://jabber.org/protocol/caps' node='http://prosody.im'/><ver xmlns='urn:xmpp:features:rosterver'/><csi xmlns='urn:xmpp:csi:0'/><sm xmlns='urn:xmpp:sm:2'><optional/></sm><sm xmlns='urn:xmpp:sm:3'><optional/></sm></stream:features>");
  ExpectUntil(XMPP_ITER_RECV, "<iq id='bind' type='set'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><resource>resource</resource></bind></iq>");
  Send("<iq type='result' id='bind'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><jid>admin@localhost/resource</jid></bind></iq>");
  ExpectUntil(XMPP_ITER_READY, "<enable xmlns='urn:xmpp:sm:3' resume='true'/>");
  Send("<enabled resume='true' max='600' xmlns='urn:xmpp:sm:3' id='sm-id'/>");
}

// TODO: maybe we should send ESKIP at the beginning instead of the end.
static void TestSkipper() {
  SetupStream();
  client.parser.c = 10;
  strcpy(client.parser.p, "<message><");
  client.parser.n = 10;
  ExpectUntil(XMPP_ITER_RECV, "");
  strcpy(client.parser.p, "/message>");
  client.parser.n = 9;
  ExpectUntil(XMPP_ESKIP, "");
}

static void TestParseJid() {
  char buf[50];
  struct xmppJid jid;
  xmppParseJid(&jid, buf, sizeof(buf), "admin@localhost/resource");
  assert(jid.localp == buf);
  assert(!strcmp(jid.localp, "admin"));
  assert(!strcmp(jid.domainp, "localhost"));
  assert(!strcmp(jid.resourcep, "resource"));
}

static void TestBuilderInClient() {
  memset(&client, 0, sizeof(client));
  memset(&sd, 0, sizeof(sd));
  xmppInitClient(&client, &sd, "admin@localhost", 0);
  client.features |= XMPP_STREAMFEATURE_SMACKS;
  assert(!xmppFormatStanza(&client, "test"));
  assert(!strcmp(client.builder.p, "test<r xmlns='urn:xmpp:sm:3'/>"));
  assert(client.actualsent == 1);
}

static void TestBuilder() {
  char buf[100] = {0};
  struct xmppBuilder builder;
  memset(&builder, 0, sizeof(builder));
  builder.p = buf;
  builder.c = sizeof(buf);
  xmppAppendXml(&builder, "%s %d", "test<>", 100);
  assert(builder.n == 16);
  assert(!strcmp(buf, "test&lt;&gt; 100"));
}

int main() {
  puts("Starting tests");
  TestXmlSlice();
  TestClient();
  TestXml();
  TestSkipper();
  TestParseJid();
  TestBuilder();
  TestBuilderInClient();
  puts("All tests passed");
  return 0;
}
