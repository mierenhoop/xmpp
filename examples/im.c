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
#include <sys/random.h>
#include <stdbool.h>

#include "xmpp.h"
#include "test/cacert.inc"
#include "omemo.h"

#include "system.h"

#if 0
#define Log(fmt, ...) fprintf(log, fmt "\n" __VA_OPT__(,) __VA_ARGS__)
#else
#define Log(fmt, ...) fprintf(stdout, fmt "\n" __VA_OPT__(,) __VA_ARGS__)
#define LogWarn(fmt, ...) fprintf(stdout, "\e[33m" fmt "\e[0m\n" __VA_OPT__(,) __VA_ARGS__)
#endif

#define STORE_LOCATION "/tmp/store"

#define PUBLISH_OPTIONS_OPEN                                           \
  "<publish-options><x xmlns='jabber:x:data' type='submit'><field "    \
  "var='FORM_TYPE' "                                                   \
  "type='hidden'><value>http://jabber.org/protocol/"                   \
  "pubsub#publish-options</value></field><field "                      \
  "var='pubsub#persist_items'><value>true</value></field><field "      \
  "var='pubsub#access_model'><value>open</value></field></x></"        \
  "publish-options>"

typedef char Uuidv4[36+1];

static char *logdata;
static size_t logdatan;
static FILE *log;
static struct xmppClient client;
static char linebuf[1000];
static char *line;
static size_t linen;
static struct Store omemostore;
static struct Session omemosession;
static int deviceid;
static struct {
  Uuidv4 subdevicelist;
} pending;

#define IsPending(field) (pending.field[0] != 0)

void SystemRandom(void *d, size_t n) {
  assert(getrandom(d, n, 0) == n);
}

// https://github.com/rxi/uuid4/blob/master/src/uuid4.c
static void GenerateUuidv4(Uuidv4 dst) {
  static const char *template = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx";
  static const char *chars = "0123456789abcdef";
  uint8_t rnd[16];
  const char *p;
  int i, n;
  SystemRandom(rnd, 16);
  p = template;
  i = 0;
  while (*p) {
    n = rnd[i >> 1];
    n = (i & 1) ? (n >> 4) : (n & 0xf);
    switch (*p) {
      case 'x'  : *dst = chars[n];              i++;  break;
      case 'y'  : *dst = chars[(n & 0x3) + 8];  i++;  break;
      default   : *dst = *p;
    }
    dst++, p++;
  }
  *dst = '\0';
}

static void Die() {
  free(line);
  exit(0);
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
  mbedtls_ssl_conf_max_tls_version(&conn.conf, MBEDTLS_SSL_VERSION_TLS1_2);
  assert(mbedtls_ssl_setup(&conn.ssl, &conn.conf) == 0);
  mbedtls_net_init(&conn.server_fd);
  assert(mbedtls_net_connect(&conn.server_fd, server, port,
                             MBEDTLS_NET_PROTO_TCP) == 0);
  mbedtls_ssl_set_bio(&conn.ssl, &conn.server_fd, mbedtls_net_send,
                      mbedtls_net_recv, NULL);
}

static void Initialize(const char *jid) {
  xmppInitClient(&client, jid, 0);
  InitializeConn(client.jid.domain, "5222");
}

static void Close() {
  Log("Closing XMPP stream");
  mbedtls_ssl_close_notify(&conn.ssl);
  mbedtls_net_free(&conn.server_fd);
  mbedtls_x509_crt_free(&conn.cacert);
  mbedtls_ssl_free(&conn.ssl);
  mbedtls_ssl_config_free(&conn.conf);
  mbedtls_ctr_drbg_free(&conn.ctr_drbg);
  mbedtls_entropy_free(&conn.entropy);
}

static void SendAll() {
  int n, i = 0;
  do {
    if (client.features & XMPP_STREAMFEATURE_STARTTLS)
      n = mbedtls_ssl_write(&conn.ssl, client.builder.p+i, client.builder.n-i);
    else
      n = mbedtls_net_send(&conn.server_fd, client.builder.p+i, client.builder.n-i);
    i += n;
  } while (n > 0);
  client.builder.n = 0;
  memset(client.builder.p, 0, client.builder.c); // just in case
}

static void Handshake() {
  int r;
  while ((r = mbedtls_ssl_handshake(&conn.ssl)) != 0)
    assert(r == MBEDTLS_ERR_SSL_WANT_READ ||
           r == MBEDTLS_ERR_SSL_WANT_WRITE);
  assert(mbedtls_ssl_get_verify_result(&conn.ssl) == 0);
}

static char *GetLine() {
  ssize_t n;
  // We expect that stdin is buffered on newlines.
  if ((n = read(STDIN_FILENO, linebuf, sizeof(linebuf)-1)) <= 0)
    Die();
  linebuf[n-1] = 0;
  return linebuf;
}

static void GivePassword() {
  char *pwd;
  printf("Password? ");
  fflush(stdout);
  pwd = GetLine();
  xmppSupplyPassword(&client, pwd);
  explicit_bzero(pwd, strlen(pwd));
}

static void PrintSlice(struct xmppXmlSlice *slc, const char *alt) {
  char *p;
  if (slc->p && (p = calloc(slc->n+1, 1))) {
    xmppReadXmlSlice(p, *slc);
    printf("%s", p);
    free(p);
  } else {
    printf("%s", alt);
  }
}

static void PrintMessage(struct xmppStanza *st) {
  PrintSlice(&st->from, "[unknown]");
  printf("> ");
  PrintSlice(&st->message.body, "[empty]");
  puts("");
  fflush(stdout);
}

// This function might be useful for xmpp.c
static bool HasExactAttribute(struct xmppParser *parser, const char *k, const char *v) {
  struct xmppXmlSlice attr;
  while (xmppParseAttribute(parser, &attr)) {
    if (!strcmp(k, parser->x.attr) && StrictStrEqual(v, attr.p, attr.rawn))
      return true;
  }
  return false;
}

static void AnnounceOmemoDevice() {
  //xmppFormatStanza(&client, "<iq xmlns='jabber:client' to='admin@localhost' type='get' id='pubsub%d'><pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='eu.siacs.conversations.axolotl.devicelist' max_items='1' /></pubsub></iq>", rand());
  xmppFormatStanza(
      &client, "<iq xmlns='jabber:client' type='set' id='announce%d'><pubsub "
               "xmlns='http://jabber.org/protocol/pubsub'><publish "
               "node='eu.siacs.conversations.axolotl.devicelist'><item "
               "id='current'><list "
               "xmlns='eu.siacs.conversations.axolotl'><device "
               "id='%d' /></list></item></publish>"
PUBLISH_OPTIONS_OPEN
               "</pubsub></iq>", rand(), deviceid);
}

static void ReAddDevices(struct xmppParser *parser) {
  bool found = false;
  struct xmppXmlSlice attr;
  while (xmppParseElement(parser)) {
    while (xmppParseAttribute(parser, &attr)) {
      if (!strcmp(parser->x.attr, "id")) {
        char *e;
        long id = strtol(attr.p, &e, 10);
        if (e > attr.p && id > 0) {
          if (id == deviceid)
            found = true;
          FormatXml(&client.builder, "<device id='%d'/>", id);
        }
      }
    }
    xmppParseUnknown(parser);
  }
  if (!found)
    FormatXml(&client.builder, "<device id='%d'/>", deviceid);
}

static void ParseDeviceList(struct xmppParser *parser) {
  if (xmppParseElement(parser) && !strcmp(parser->x.elem, "item")) {
    if (xmppParseElement(parser) && !strcmp(parser->x.elem, "list")) {
      FormatXml(
          &client.builder,
          "<iq xmlns='jabber:client' type='set' "
          "id='announce%d'><pubsub "
          "xmlns='http://jabber.org/protocol/pubsub'><publish "
          "node='eu.siacs.conversations.axolotl.devicelist'><item "
          "id='current'><list xmlns='eu.siacs.conversations.axolotl'>",
          rand(), deviceid);
      ReAddDevices(parser);
      xmppFormatStanza(&client,
                       "</list></item></publish></pubsub></iq>", rand(),
                       deviceid);
    }
  }
}

static void *Malloc(size_t n) {
  void *p = malloc(n);
  assert(p);
  return p;
}

static void DecodeBase64(uint8_t **p, size_t *n, struct xmppXmlSlice *slc) {
  *p = Malloc(slc->n);
  assert(!mbedtls_base64_decode(*p, slc->n, n, slc->p, slc->rawn));
}

static void ParseKey(struct xmppParser *parser, struct xmppXmlSlice *keyslc, bool *isprekey) {
  struct xmppXmlSlice attr;
  bool found = false;
  while (xmppParseAttribute(parser, &attr)) {
    if (!strcmp(parser->x.attr, "rid")) {
      found = strtol(attr.p, NULL, 10) == deviceid; // TODO: put deviceid in store.
    } else if (!strcmp(parser->x.attr, "prekey")) {
      *isprekey = true;
    }
  }
  if (found)
    xmppParseContent(parser, keyslc);
  else
    xmppParseUnknown(parser);
}

static void ParseEncryptedMessage(struct xmppParser *parser) {
  struct xmppXmlSlice keyslc = {0}, ivslc = {0}, payloadslc = {0};
  bool isprekey = false;
  uint8_t *key, *iv, *payload;
  size_t keysz, ivsz, payloadsz;
  while (xmppParseElement(parser)) {
    if (!strcmp(parser->x.elem, "header")) {
      while (xmppParseElement(parser)) {
        if (!strcmp(parser->x.elem, "key")) {
          ParseKey(parser, &keyslc, &isprekey);
        } else if (!strcmp(parser->x.elem, "iv")) {
          xmppParseContent(parser, &ivslc);
        } else {
          xmppParseUnknown(parser);
        }
      }
    } else if (!strcmp(parser->x.elem, "payload")) {
      xmppParseContent(parser, &payloadslc);
    } else {
      xmppParseUnknown(parser);
    }
  }
  if (!(keyslc.n && ivslc.n && payloadslc.n)) {
    LogWarn("The OMEMO message is either not complete or not addressed to us.");
    return;
  }
  DecodeBase64(&key, &keysz, &keyslc);
  DecodeBase64(&iv, &ivsz, &ivslc);
  DecodeBase64(&payload, &payloadsz, &payloadslc);
  char *decryptedpayload = Malloc(payloadsz+1);
  decryptedpayload[payloadsz] = 0;
  Payload decryptedkey;
  if (isprekey) {
    int r = DecryptPreKeyMessage(&omemosession, &omemostore, decryptedkey, key, keysz);
    if (r < 0) {
      LogWarn("PreKeyMessage decryption error: %d", r);
      return;
    }
  } else {
    if (!omemosession.fsm) {
      LogWarn("Session has not been initialized yet, a PreKeyMessage should have been sent.");
      return;
    }
    int r = DecryptMessage(&omemosession, &omemostore, decryptedkey, key, keysz);
    if (r < 0) {
      LogWarn("Message decryption error: %d", r);
      return;
    }
  }
  DecryptRealMessage(decryptedpayload, decryptedkey, PAYLOAD_SIZE, iv, payload, payloadsz);
  Log("Got OMEMO msg: %s", decryptedpayload);
}

static void ParseSpecificStanza(struct xmppStanza *st) {
  struct xmppParser parser;
  memset(&parser, 0, sizeof(struct xmppParser));
  yxml_init(&parser.x, parser.xbuf, sizeof(parser.xbuf));
  fflush(stdout);
  parser.p = st->raw.p;
  parser.c = parser.n = st->raw.rawn;
  assert(!setjmp(parser.jb));
  if (xmppParseElement(&parser)) {
    while (xmppParseElement(&parser)) {
      if (!strcmp(parser.x.elem, "pubsub")) {
        //if (xmppParseElement(&parser) &&
        //    !strcmp(parser.x.elem, "items") &&
        //    HasExactAttribute(
        //        &parser, "node",
        //        "eu.siacs.conversations.axolotl.devicelist"))
        //  ParseDeviceList(&parser);
      }
      if (st->type == XMPP_STANZA_MESSAGE && !strcmp(parser.x.elem, "encrypted")) {
        ParseEncryptedMessage(&parser);
      } else {
        xmppParseUnknown(&parser);
      }
    }
  }
}

static void SubscribeDeviceList() {
  GenerateUuidv4(pending.subdevicelist);
  xmppFormatStanza(&client, "<iq xmlns='jabber:client' to='admin@localhost' type='get' id='%s'><pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='eu.siacs.conversations.axolotl.devicelist' max_items='1'/></pubsub></iq>", pending.subdevicelist);
}

static void AnnounceOmemoBundle() {
  SerializedKey spk, ik;
  SerializeKey(spk, omemostore.cursignedprekey.kp.pub);
  SerializeKey(ik, omemostore.identity.pub);
  FormatXml(
      &client.builder,
      "<iq type='set' id='announce%d'><pubsub "
      "xmlns='http://jabber.org/protocol/pubsub'><publish "
      "node='eu.siacs.conversations.axolotl.bundles:%d'><item "
      "id='current'><bundle "
      "xmlns='eu.siacs.conversations.axolotl'><signedPreKeyPublic "
      "signedPreKeyId='%d'>%b</"
      "signedPreKeyPublic><signedPreKeySignature>%b</"
      "signedPreKeySignature><identityKey>%b</"
      "identityKey><prekeys>", rand(), deviceid, omemostore.cursignedprekey.id,
      33, spk, 64, omemostore.cursignedprekey.sig, 33, ik);
  for (int i = 0; i < NUMPREKEYS; i++) {
    SerializedKey pk;
    SerializeKey(pk, omemostore.prekeys[i].kp.pub);
    FormatXml(&client.builder,
              "<preKeyPublic preKeyId='%d'>%b</preKeyPublic>", omemostore.prekeys[i].id,
              33, pk);
  }

  xmppFormatStanza(&client, "</prekeys></bundle></"
                            "item></publish>" PUBLISH_OPTIONS_OPEN "</pubsub></iq>");
}

// returns true if stream is done for
static bool IterateClient() {
  int r;
  static int sent = 0;
  while ((r = xmppIterate(&client))) {
    switch (r) {
    case XMPP_ITER_SEND:
      Log("Out: \e[32m%.*s\e[0m", (int)client.builder.n, client.builder.p);
      SendAll();
      break;
    case XMPP_ITER_READY:
      Log("Polling...");
      if (!sent) {
        xmppFormatStanza(&client, "<presence/>");
        //SubscribeDeviceList();
        AnnounceOmemoDevice();
        AnnounceOmemoBundle();
        sent = 1;
        continue;
      }
      printf("> ");
      fflush(stdout);
      if (!SystemPoll())
        return false;
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
      sent = false; // TODO: hack
      Handshake();
      break;
    case XMPP_EPASS:
      puts("Password was wrong.");
      break;
    case XMPP_ITER_GIVEPWD:
      GivePassword();
      break;
    case XMPP_ITER_STANZA:
      Log("Stanza type %d", client.stanza.type);
      if (client.stanza.type == XMPP_STANZA_MESSAGE && client.stanza.message.body.p) {
        PrintMessage(&client.stanza);
      }
      ParseSpecificStanza(&client.stanza);
      break;
    case XMPP_ITER_OK:
    default:
      if (r < 0) {
        Log("Error encountered %d", r);
        Die();
      }
      break;
    }
  }
  return true;
}

static void HandleCommand() {
  static char jid[3074];
  const char *cmd = GetLine();
  if (!strncmp("/login ", cmd, 7)) {
    if (!xmppIsInitialized(&client)) {
      strcpy(jid, cmd+7);
      strcat(jid, "/resource");
      Initialize(jid);
      puts("Logging in...");
    } else {
      puts("Log out first.");
    }
  } else if (!strcmp("/logout", cmd)) {
    xmppEndStream(&client);
  } else if (!strcmp("/log", cmd)) {
    fflush(log);
    printf("Printing log:\n%d %s\n", (int)logdatan, logdata);
  } else if (!strncmp("/ping ", cmd, 6)) {
    strcpy(jid, cmd+6);
    xmppFormatStanza(&client, "<iq to='%s' id='%s' type='set'><ping xmlns='urn:xmpp:ping'/></iq>", jid, "ping1");
  } else if (!strcmp("/", cmd)) {
    puts("Try: /login jid password");
  } else if (strlen(cmd)) {
    if (!xmppIsInitialized(&client)) {
      puts("Can not send messages yet.\nTry: /login jid password");
    } else {
      //xmppSendMessage(&client, "user@localhost", cmd);
      xmppFormatStanza(&client, "<message type='chat' to='%s' id='message%d'><body>%s</body></message>", "user@localhost", rand(), cmd);
    }
  }
}

static void Loop() {
  char *line = NULL, *msgbody;
  size_t n;
  for (;;) {
    if (xmppIsInitialized(&client)) {
      if (IterateClient()) {
        Close();
        continue;
      }
    } else {
      printf("> ");
      fflush(stdout);
    }
    HandleCommand();
  }
  free(line);
}

void RunIm() {
  log = open_memstream(&logdata, &logdatan);
  assert(log);
  InitializeConn("localhost", "5222");
  Loop();
  Die();
}

bool SystemPoll() {
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

#ifdef IM_NATIVE

static bool ReadWholeFile(const char *path, uint8_t **data, size_t *n) {
  FILE *f = fopen(path, "r");
  if (!f)
    return false;
  fseek(f, 0, SEEK_END);
  *n = ftell(f);
  fseek(f, 0, SEEK_SET);
  if ((*data = malloc(*n))) {
    fread(*data, 1, *n, f);
  }
  fclose(f);
  return *data != NULL;
}

static void SaveStore() {
  FILE *f = fopen(STORE_LOCATION, "w");
  if (f) {
    fwrite(&omemostore, sizeof(struct Store), 1,  f);
    fclose(f);
  }
}

static void LoadStore() {
  uint8_t *data;
  size_t n;
  if (ReadWholeFile(STORE_LOCATION, &data, &n)) {
    if (n == sizeof(struct Store)) {
      memcpy(&omemostore, data, sizeof(struct Store));
      free(data);
      return;
    }
    free(data);
  }
  SetupStore(&omemostore);
  SaveStore();
}

int main() {
  deviceid = 1024;
  LoadStore();
  RunIm();
}

#endif
