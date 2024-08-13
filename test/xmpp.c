#include "../xmpp.c"

#include <sys/poll.h>

#include "cacert.inc"

static mbedtls_ssl_context ssl;
static mbedtls_net_context server_fd;
static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;
static mbedtls_x509_crt cacert;
static mbedtls_ssl_config conf;

static struct xmppClient client;

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

static void SendAll() {
  int n, i = 0;
  do {
    if (client.features & XMPP_STREAMFEATURE_STARTTLS)
      n = mbedtls_ssl_write(&ssl, client.comp.p+i, client.comp.n-i);
    else
      n = mbedtls_net_send(&server_fd, client.comp.p+i, client.comp.n-i);
    i += n;
  } while (n > 0);
  client.comp.n = 0;
  memset(client.comp.p, 0, client.comp.c); // just in case
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
  xmppInitClient(&client, "admin@localhost/resource", 0);
  bool sent = false;
  int r;
  while ((r = xmppIterate(&client))) {
    switch (r) {
    case XMPP_ITER_SEND:
      Log("Out: \e[32m%.*s\e[0m", (int)client.comp.n, client.comp.p);
      SendAll();
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
      if (client.features & XMPP_STREAMFEATURE_STARTTLS)
        r = mbedtls_ssl_read(&ssl, client.parser.p+client.parser.n, client.parser.c-client.parser.n);
      else
        r = mbedtls_net_recv(&server_fd, client.parser.p+client.parser.n, client.parser.c-client.parser.n);
      assert(r >= 0);
      client.parser.n += r;
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

static struct xmppParser SetupXmppParser(const char *xml) {
  static char buf[1000];
  struct xmppParser p = {0};
  p.p = client.in;
  p.c = sizeof(client.in);
  strcpy(p.p, xml);
  p.n = strlen(xml);
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
  assert(st.to.p && !strncmp(st.to.p, "juliet@im.example.com", st.to.rawn));
  assert(st.to.rawn == st.to.n);
  assert(FindElement("proceed", 7, "p=proceed f=failure") == 'p');
  assert(FindElement("failure", 7, "p=proceed f=failure") == 'f');
  assert(FindElement("", 0, "p=proceed f=failure") == XMPP_EXML);
  assert(FindElement("roceed", 6, "p=proceed f=failure") == '?');
  assert(FindElement("procee", 6, "p=proceed f=failure") == '?');
  assert(FindElement("ailure", 6, "p=proceed f=failure") == '?');
  assert(FindElement("failur", 6, "p=proceed f=failure") == '?');
  assert(FindElement("failuree", 8, "p=proceed f=failure") == '?');
  assert(FindElement("efailure", 8, "p=proceed f=failure") == '?');
  assert(FindElement("procee", 6, "p=proceed f=failure c=procee") == 'c');
  assert(!StrictStrEqual("SCRAM-SHA-1", "SCRAM-SHA-1-PLUS", sizeof("SCRAM-SHA-1-PLUS")-1));
  assert(StrictStrEqual("SCRAM-SHA-1", "SCRAM-SHA-1", sizeof("SCRAM-SHA-1")-1));
  assert(!StrictStrEqual("SCRAM-SHA-1", "PLAIN", sizeof("PLAIN")-1));
}

static void ExpectUntil(int goal, const char *exp) {
  for (;;) {
    int r = xmppIterate(&client);
    if (goal && r == goal)
      return;
    switch (r) {
    case XMPP_ITER_SEND:
      if (strncmp(client.comp.p, exp, client.comp.n)) {
        Log("Expected %s, but got %.*s", exp, (int)client.comp.n, client.comp.p);
        assert(false);
      }
      exp += client.comp.n;
      client.comp.n = 0;
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
  xmppInitClient(&client, "admin@localhost/resource", XMPP_OPT_FORCEPLAIN);
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

int main() {
  puts("Starting tests");
  TestClient();
  TestXml();
  TestSkipper();
  puts("All tests passed");
  return 0;
}