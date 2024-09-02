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
static struct StaticData sd;
static char linebuf[1000];
static char *line;
static struct Store omemostore;
static struct Session omemosession;
static int32_t deviceid, remoteid;
static uint32_t curpending;
static Uuidv4 pending[10];

#define PENDING_REMOTEDEVICELIST 0
#define PENDING_OURDEVICELIST 1
#define PENDING_BUNDLE 2

void SystemRandom(void *d, size_t n) {
  assert(getrandom(d, n, 0) == n);
}

static int RandomInt() {
  uint16_t n;
  SystemRandom(&n, 2);
  return n;
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
  xmppInitClient(&client, &sd, jid, 0);
  InitializeConn(client.jid.domainp, "5222");
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
    xmppReadXmlSlice(p, slc);
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

static int GetPendingFromId(struct xmppXmlSlice *id) {
  if (id->rawn != 36) // sizeof(Uuidv4)-1
    return -1;
  for (int i = 0; i < (sizeof(pending)/sizeof(*pending)); i++) {
    if ((curpending & (1 << i)) && !memcmp(id->p, pending[i], 36)) {
      curpending &= ~(1 << i);
      memset(pending[i], 0, 36);
      return i;
    }
  }
  return -1;
}

static int FindNextChar(const char *s, char c) {
  const char *p = strchr(s, c);
  return p ? p - s : strlen(s);
}

static const char *NextItem(const char *s, int n) {
  return s[n] == '\0' ? s + n : s + n + 1;
}

// elems is string with space-separated elements, for example: "iq pubsub items item bundle".
// returns true if succeeded
static bool ParseMultiple(struct xmppParser *parser, const char *elems) {
  int n = FindNextChar(elems, ' ');
  if (n) {
    while (xmppParseElement(parser)) {
      if (!strncmp(elems, parser->x.elem, n) && parser->x.elem[n] == '\0') {
        return ParseMultiple(parser, NextItem(elems, n));
      } else {
        xmppParseUnknown(parser);
      }
    }
    return false;
  }
  return true;
}

static void FetchBundle() {
  GenerateUuidv4(pending[PENDING_BUNDLE]);
  xmppFormatStanza(&client, "<iq type='get' to='%s' id='%s'><pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='eu.siacs.conversations.axolotl.bundles:%d'/></pubsub></iq>", "user@localhost", pending[PENDING_BUNDLE], remoteid);
  curpending |= (1 << PENDING_BUNDLE);
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

// d = dest buffer of size n
static void ParseBase64Content(struct xmppParser *parser, uint8_t *d, int n) {
  struct xmppXmlSlice slc;
  size_t olen;
  xmppParseContent(parser, &slc);
  assert(!mbedtls_base64_decode(d, n, &olen, slc.p, slc.rawn));
  assert(olen == n);
}

static void ParseBase64PubKey(struct xmppParser *parser, Key d) {
  SerializedKey ser;
  ParseBase64Content(parser, ser, 33);
  memcpy(d, ser+1, 32);
}

static int ParseNumberAttribute(struct xmppParser *parser, const char *name) {
  struct xmppXmlSlice attr;
  while (xmppParseAttribute(parser, &attr)) {
    if (!strcmp(parser->x.attr, name)) {
      return strtol(attr.p, NULL, 10);
    }
  }
  assert(false); // TODO: instead of such assertions, we may longjmp
  return 0;
}

static bool ParseRandomPreKey(struct xmppParser *parser, struct Bundle *bundle) {
  int i = 0;
  while (xmppParseElement(parser)) {
    assert(!strcmp(parser->x.elem, "preKeyPublic"));
    if (RandomInt() % ++i == 0) {
      bundle->pk_id = ParseNumberAttribute(parser, "preKeyId");
      ParseBase64PubKey(parser, bundle->pk);
    } else {
      xmppParseUnknown(parser);
    }
  }
  assert(i > 0);
  return true;
}

static void ParseBundle(struct xmppParser *parser) {
  struct Bundle bundle;
  int found = 0;
  while (xmppParseElement(parser)) {
    if (!strcmp(parser->x.elem, "signedPreKeyPublic")) {
      bundle.spk_id = ParseNumberAttribute(parser, "signedPreKeyId");
      ParseBase64PubKey(parser, bundle.spk);
      found |= 1 << 0;
      Log("spk");
    } else if (!strcmp(parser->x.elem, "signedPreKeySignature")) {
      ParseBase64Content(parser, bundle.spks, 64);
      found |= 1 << 1;
      Log("spks");
    } else if (!strcmp(parser->x.elem, "identityKey")) {
      ParseBase64PubKey(parser, bundle.ik);
      found |= 1 << 2;
      Log("ik");
    } else if (!strcmp(parser->x.elem, "prekeys")) {
      if (ParseRandomPreKey(parser, &bundle))
        found |= 1 << 3;
      Log("pk");
    } else {
      xmppParseUnknown(parser);
    }
  }
  assert(found == 0xf);
  int r = InitFromBundle(&omemosession, &omemostore, &bundle);
  if (r < 0) {
    LogWarn("Bundle init fail: %d", r);
    return;
  }
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

static bool GetRemoteId(struct xmppParser *parser) {
  struct xmppXmlSlice attr;
  while (xmppParseAttribute(parser, &attr)) {
    if (!strcmp(parser->x.attr, "sid")) {
      remoteid = strtol(attr.p, NULL, 10);
      return true;
    }
  }
  return false;
}

static void ParseEncryptedMessage(struct xmppParser *parser) {
  struct xmppXmlSlice keyslc = {0}, ivslc = {0}, payloadslc = {0};
  bool isprekey = false;
  uint8_t *key, *iv, *payload;
  size_t keysz, ivsz, payloadsz;
  while (xmppParseElement(parser)) {
    if (!strcmp(parser->x.elem, "header")) {
      if (!GetRemoteId(parser)) {
        LogWarn("The OMEMO message is corrupt.");
        return;
      }
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
  int r = DecryptAnyMessage(&omemosession, &omemostore, decryptedkey, isprekey, key, keysz);
  if (r < 0) {
    LogWarn("PreKeyMessage decryption error: %d", r);
    return;
  }
  DecryptRealMessage(decryptedpayload, decryptedkey, PAYLOAD_SIZE, iv, payload, payloadsz);
  Log("Got OMEMO msg: %s", decryptedpayload);
}

#define SetupParser(parser, ret, p_, n_) \
  int ret; \
  uint8_t xbuf[200]; \
  struct xmppParser parser[1] = {{ .p = (p_), .n = (n_), .c = (n_) }}; \
  yxml_init(&parser->x, xbuf, sizeof(xbuf)); /* TODO: should we remove xbuf(n) from the struct? */ \
  if ((ret = setjmp(parser->jb)))

static void ParseSpecificStanza(struct xmppStanza *st) {
  SetupParser(parser, r, st->raw.p, st->raw.n) {
    LogWarn("Parsing the stanza failed with error %d", r);
    return;
  }
  if (xmppParseElement(parser)) {
    while (xmppParseElement(parser)) {
      if (!strcmp(parser->x.elem, "pubsub")) {
        if (xmppParseElement(parser) &&
            !strcmp(parser->x.elem, "items")) {
          if (HasExactAttribute(parser, "node", "eu.siacs.conversations.axolotl.devicelist")) {
            //ParseDeviceList(parser);
          } else {
            assert(xmppParseElement(parser) && !strcmp(parser->x.elem, "item"));
            if (xmppParseElement(parser) && !strcmp(parser->x.elem, "bundle"))
              ParseBundle(parser);
          }
        }
      }
      if (st->type == XMPP_STANZA_MESSAGE && !strcmp(parser->x.elem, "encrypted")) {
        ParseEncryptedMessage(parser);
      } else {
        xmppParseUnknown(parser);
      }
    }
  }
}

static int ParseDeviceId(struct xmppParser *parser) {
  struct xmppXmlSlice attr;
  int id;
  while (xmppParseAttribute(parser, &attr)) {
    if (!strcmp(parser->x.attr, "id")) {
      char *e;
      id = strtol(attr.p, &e, 10);
      //if e < p+n
      //  id = -1;
    }
  }
  xmppParseUnknown(parser);
  return id;
}

static void ParseOurDeviceList(struct xmppStanza *st) {
  SetupParser(parser, r, st->raw.p, st->raw.n) {
    LogWarn("Parsing the stanza failed with error %d", r);
    return;
  }
  // TODO: xmppFormatBegin (this would clear an unfinished stanza)
  xmppStartStanza(&client.builder);
  xmppAppendXml(
      &client.builder,
      "<iq xmlns='jabber:client' type='set' "
      "id='announce%d'><pubsub "
      "xmlns='http://jabber.org/protocol/pubsub'><publish "
      "node='eu.siacs.conversations.axolotl.devicelist'><item "
      "id='current'><list xmlns='eu.siacs.conversations.axolotl'>",
      RandomInt(), deviceid);
  if (ParseMultiple(parser, "iq pubsub items item list")) {
    while (xmppParseElement(parser)) {
      int id = ParseDeviceId(parser);
      if (id != deviceid)
        xmppAppendXml(&client.builder, "<device id='%d'/>", id);
    }
  }
  xmppAppendXml(&client.builder, "<device id='%d'/>", deviceid);
  xmppAppendXml(&client.builder,
                   "</list></item></publish>" PUBLISH_OPTIONS_OPEN "</pubsub></iq>", RandomInt(),
                   deviceid);
  xmppFlush(&client, true);
}


static void ParseRemoteDeviceList(struct xmppStanza *st) {
  SetupParser(parser, r, st->raw.p, st->raw.n) {
    LogWarn("Parsing the stanza failed with error %d", r);
    return;
  }
  if (ParseMultiple(parser, "iq pubsub items item list")) {
    while (xmppParseElement(parser)) {
      int id = ParseDeviceId(parser);
      if (id > 0) {
        remoteid = id;
        Log("REMOTE ID FOUND");
        FetchBundle();
      } else
        LogWarn("Id attr corrupt");
      return;
    }
  }
  Log("REMOTE ID NOT FOUND");
}

static void SubscribeDeviceList(const char *jid, int pendid) {
  GenerateUuidv4(pending[pendid]);
  xmppFormatStanza(&client, "<iq xmlns='jabber:client' to='%s' type='get' id='%s'><pubsub xmlns='http://jabber.org/protocol/pubsub'><items node='eu.siacs.conversations.axolotl.devicelist' max_items='1'/></pubsub></iq>", jid, pending[pendid]);
  // only pending if format succeeded
  curpending |= (1 << pendid);
}

static void AnnounceOmemoBundle() {
  SerializedKey spk, ik;
  SerializeKey(spk, omemostore.cursignedprekey.kp.pub);
  SerializeKey(ik, omemostore.identity.pub);
  xmppStartStanza(&client.builder);
  xmppAppendXml(
      &client.builder,
      "<iq type='set' id='announce%d'><pubsub "
      "xmlns='http://jabber.org/protocol/pubsub'><publish "
      "node='eu.siacs.conversations.axolotl.bundles:%d'><item "
      "id='current'><bundle "
      "xmlns='eu.siacs.conversations.axolotl'><signedPreKeyPublic "
      "signedPreKeyId='%d'>%b</"
      "signedPreKeyPublic><signedPreKeySignature>%b</"
      "signedPreKeySignature><identityKey>%b</"
      "identityKey><prekeys>", RandomInt(), deviceid, omemostore.cursignedprekey.id,
      33, spk, 64, omemostore.cursignedprekey.sig, 33, ik);
  for (int i = 0; i < NUMPREKEYS; i++) {
    SerializedKey pk;
    SerializeKey(pk, omemostore.prekeys[i].kp.pub);
    xmppAppendXml(&client.builder,
              "<preKeyPublic preKeyId='%d'>%b</preKeyPublic>", omemostore.prekeys[i].id,
              33, pk);
  }

  xmppAppendXml(&client.builder, "</prekeys></bundle></"
                            "item></publish>" PUBLISH_OPTIONS_OPEN "</pubsub></iq>");
  xmppFlush(&client, true);
}

static void Send() {
  char *buf;
  size_t sz;
  int n;
  bool istls;
  xmppGetSendBuffer(&client, &buf, &sz, &istls);
  if (istls)
    n = mbedtls_ssl_write(&conn.ssl, buf, sz);
  else
    n = mbedtls_net_send(&conn.server_fd, buf, sz);
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
    r = mbedtls_ssl_read(&conn.ssl, buf, maxsz);
  else
    r = mbedtls_net_recv(&conn.server_fd, buf, maxsz);
  assert(r >= 0);
  xmppAddAmountReceived(&client, r);
}

// returns true if stream is done for
static bool IterateClient() {
  int r;
  static int sent = 0;
  while ((r = xmppIterate(&client))) {
    switch (r) {
    case XMPP_ITER_SEND:
      Log("Out: \e[32m%.*s\e[0m", (int)client.builder.n, client.builder.p);
      Send();
      break;
    case XMPP_ITER_READY:
      Log("Polling...");
      if (!sent) {
        xmppFormatStanza(&client, "<presence/>");
        SubscribeDeviceList("admin@localhost", PENDING_OURDEVICELIST);
        SubscribeDeviceList("user@localhost", PENDING_REMOTEDEVICELIST);
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
      Receive();
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
      switch (GetPendingFromId(&client.stanza.id)) {
      break; case PENDING_OURDEVICELIST:
        puts("DEVICE LIST");
        ParseOurDeviceList(&client.stanza);
      break; case PENDING_REMOTEDEVICELIST:
        ParseRemoteDeviceList(&client.stanza);
      break; default:
        ParseSpecificStanza(&client.stanza);
      }
      break;
    case XMPP_ITER_OK: // fallthrough
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

static void SendNormalOmemo(const char *msg, const char *to, int rid) {
  size_t msgn = strlen(msg);
  char *payload = Malloc(msgn);
  char iv[12];
  Payload encryptionkey;
  EncryptRealMessage(payload, encryptionkey, iv, msg, msgn);

  struct PreKeyMessage encrypted;
  int r = EncryptRatchet(&omemosession, &omemostore, &encrypted, encryptionkey);
  if (r < 0) {
    LogWarn("Message encryption error: %d", r);
    return;
  }

  xmppFormatStanza(
      &client,
      "<message to='%s' id='%d' type='chat'><encrypted "
      "xmlns='eu.siacs.conversations.axolotl'><header sid='%d'><key "
      "[prekey='true' ]rid='%d'>%b</key><iv>%b</iv></header><payload>%b</payload></"
      "encrypted>"
"<encryption xmlns='urn:xmpp:eme:0' name='OMEMO' namespace='eu.siacs.conversations.axolotl'/><body>You received a message encrypted with OMEMO but your client doesn't support OMEMO.</body>"
"<request xmlns='urn:xmpp:receipts'/><markable xmlns='urn:xmpp:chat-markers:0'/>"
      "<store xmlns='urn:xmpp:hints'/></message>",
      to, RandomInt(), deviceid, encrypted.isprekey, rid, encrypted.n, encrypted.p, 12, iv, msgn,
      payload);
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
      if (IsSessionInitialized(&omemosession)) {
        if (remoteid)
          SendNormalOmemo(cmd, "user@localhost", remoteid);
        else
          LogWarn("Remote id has not been found yet");
      } else {
        xmppFormatStanza(&client, "<message type='chat' to='%s' id='message%d'><body>%s</body></message>", "user@localhost", RandomInt(), cmd);
      }
    }
  }
}

static void Loop() {
  char *line = NULL;
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
