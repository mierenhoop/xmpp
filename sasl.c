#include <mbedtls/pkcs5.h>
#include <mbedtls/base64.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/random.h>
#include <stdbool.h>
#include <assert.h>

#include "xmpp.h"
#include "yxml.h"

// https://sans-io.readthedocs.io/

// mbedtls random source
// https://github.com/Mbed-TLS/mbedtls/blob/2a674bd9ce4758dff0d18f4ac8b6da4419efc504/library/entropy.c#L48
// ESP: https://github.com/espressif/esp-idf/blob/0479494e7abe5aef71393fba2e184b3a78ea488f/components/mbedtls/port/esp_hardware.c#L19


//#ifndef NDEBUG
//#define Assert(expr) do { \
//  if (!(expr)) {\
//    fprintf(stderr, "\x1b[31mAssertion failed \x1b[34m%s:%d: \x1b[33m%s\x1b[0m\n", __FILE__,  __LINE__, #expr); \
//    exit(1); \
//    } \
//  } while (0)
//
//#else
//#define Assert()
//#endif

// gets the length of the stanza, sees if stanza is complete
// or is larger than max stanza size
// gets length of content stuffs specific to stanza type
// also store pointer offsets of content or attr strings
// maybe mutate original xml?
struct StanzaParser {
  // yxml_t
  int depth;
};

// if (s.p && (d = malloc(s.n))) xmppReadXmlSlice(d, s);
// TODO: have specific impl for this?
void xmppReadXmlSlice(char *d, struct xmppXmlSlice s) {
  //yxml_t x;
}

#define XMPP_SASL_CHALLENGE 1
#define XMPP_SASL_SUCCESS   2

#define XMPP_STREAMFEATURE_STARTTLS (1 << 0)
#define XMPP_STREAMFEATURE_BIND (1 << 1)
#define XMPP_STREAMFEATURE_SCRAMSHA1 (1 << 2)
#define XMPP_STREAMFEATURE_SCRAMSHA1PLUS (1 << 3)
#define XMPP_STREAMFEATURE_PLAIN (1 << 4)

enum xmppStanzaType {
  xmppStanzaStreamFeatures,
};

struct xmppStanza {
  int type; // iq/message/presence
  struct xmppXmlSlice id, from, to;
  union {
    struct xmppXmlSlice challenge;
    struct xmppXmlSlice success;
  };
};

enum xmppStanzaReadReturn {
  xmppStanzaReadError = -1,
  xmppStanzaReadNothing = 0,
  xmppStanzaReadOk,
  xmppStanzaReadEndStream,
  xmppStanzaReadUnknown,
};

static bool ComparePaddedString(const char *p, const char *s, size_t pn) {
  return true;
}

struct xmppStream {
  yxml_t x;
};

// Skip all the way until the end of the element it has just entered
// ret:
//   < 0: respective yxml error
//   = 0: unexpected end
//   > 0: amount of bytes read
static int SkipUnknownXml(yxml_t *x, const char *p, size_t n) {
  int stack = 1;
  for (int i = 0; i < n; i++) {
    yxml_ret_t r = yxml_parse(x, p[i]);
    switch (r) {
    case YXML_ELEMSTART:
      stack++;
      break;
    case YXML_ELEMEND:
      if (--stack == 0)
        return i; // TODO: i+1?
      break;
    default:
      if (r < 0)
        return r;
    }
  }
  return 0;
}

// expects yxml state already entered stream:features
static int ReadStreamFeatures(struct xmppStream *s, int f, const char *p, size_t n) {
  int j;
  for (int i = 0; i < n; i++) {
    yxml_ret_t r = yxml_parse(&s->x, p[i]);
    switch (r) {
    case YXML_ELEMSTART:
      i++;
      if ((j = SkipUnknownXml(&s->x, p+i, n-i)) < 0)
        return j;
      i += j;
    case YXML_ELEMEND:
      assert(!strcmp(s->x.elem, "stream:features"));
      return i;
    default:
      if (r < 0)
        return r;
    }
  }
}

enum xmppStanzaReadReturn xmppReadStanza(struct xmppStream *s, const char *p, size_t n) {
  enum {
    IQ,
    MESSAGE,
    PRESENCE,
  };
  struct xmppStanza st;
  int i;
  for (i = 0; i < n; i++) {
    yxml_ret_t r = yxml_parse(&s->x, p[i]);
    switch (r) {
    case YXML_OK:
    case YXML_CONTENT:
      break;
    case YXML_ELEMSTART:
      if (!strcmp(s->x.elem, "iq")) {
      } else if (!strcmp(s->x.elem, "message")) {
      } else if (!strcmp(s->x.elem, "presence")) {
      } else if (!strcmp(s->x.elem, "stream:features")) {
      } else {
        SkipUnknownXml(&s->x, p+i, n-i);
        return xmppStanzaReadUnknown;
      }
      goto found;
    case YXML_ELEMEND:
      puts("stream end");
      return xmppStanzaReadEndStream;
    default:
      puts("stream error");
      return xmppStanzaReadError;
    }
  }
  return xmppStanzaReadNothing;
found:
  for (; i < n; i++) {
    yxml_ret_t r = yxml_parse(&s->x, p[i]);
    switch (r) {
    }
  }
}

void xmppExpectStream(struct xmppStream *s, char *b, size_t bn, const char *p, size_t pn) {
  yxml_init(&s->x, (void*)b, bn);
  for (int i = 0; i < pn; i++) {
    yxml_ret_t r = yxml_parse(&s->x, p[i]);
    switch (r) {
    case YXML_OK:
    case YXML_CONTENT:
      break;
    case YXML_ELEMSTART:
      if (!strcmp(s->x.elem, "stream:stream")) {
        return;
      } else {
        puts("errrorrrr");
        return;
      }
    default:
      puts("stream error");
    }
  }
}

static char *SafeStpCpy(char *d, char *e, char *s) {
  while (*s && d < e)
    *d++ = *s++;
  return d;
}

// n = number of random bytes
// p should be at least twice as big
// doesn't add nul byte
// TODO: use mbedtls random for compat?
// TODO: make this more performant
// char *FillRandomHex(char *p, char *e)
static void FillRandomHex(char *p, size_t n) {
  char b[3];
  getrandom(p, n, 0); // TODO: check error
  while (n--) {
    sprintf(b, "%02x", (unsigned char)p[n]);
    memcpy(p + n*2, b, 2);
  }
}

// TODO: check if this conforms to sasl spec
// and also check for d buf size
static char *SanitizeSaslUsername(char *d, const char *s) {
  for (;*s;s++) {
    switch (*s) {
    case '=':
      d = stpcpy(d, "=3D");
      break;
    case ',':
      d = stpcpy(d, "=2C");
      break;
    default:
      *d++ = *s;
      break;
    }
  }
  return d;
}

// TODO: check for ctx->n or SafeStpCpy
void xmppInitSaslContext(struct xmppSaslContext *ctx, char *p, size_t n, const char *user) {
  memset(ctx, sizeof(ctx), 0);
  ctx->p = p;
  ctx->n = n;
  p = stpcpy(p, "n,,n=");
  ctx->initialmsg = 3;
  p = SanitizeSaslUsername(p, user);
  p = stpcpy(p, ",r=");
  p = stpcpy(p, "fyko+d2lbbFgONRv9qkxdawL"); // for testing
  //FillRandomHex(p, 32);
  //p += 64;
  ctx->fsm = xmppSaslInitialized;
  *p++ = ',';
  ctx->serverfirstmsg = p - ctx->p;
}

static char *EncodeBase64(char *d, char *e, char *s, size_t n) {
  if (mbedtls_base64_encode(d, e-d, &n, s, n))
    return e;
  return d+n;
}

static char *DecodeBase64(char *d, char *e, char *s, size_t n, bool nul) {
  if (mbedtls_base64_decode(d, e-d, &n, s, n))
    return e;
  if (nul) {
  }
  return d+n;
}

char *xmppFormatSaslInitialMessage(char *p, char *e, struct xmppSaslContext *ctx) {
  p = SafeStpCpy(p, e, "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='SCRAM-SHA-1'>");
  p = EncodeBase64(p, e, ctx->p, ctx->serverfirstmsg-1);
  //mbedtls_base64_encode(p, 9001, &n, ctx->p, ctx->serverfirstmsg-1); // IDK random value
  return SafeStpCpy(p, e, "</auth>");
}

void xmppFormatSaslResponse(char *p, struct xmppSaslContext *ctx) {
  size_t n;
  p = stpcpy(p, "<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>");
  mbedtls_base64_encode(p, 9001, &n, ctx->p+ctx->clientfinalmsg, ctx->clientfinalmsgend-ctx->clientfinalmsg); // IDK random values
  p = stpcpy(p + n, "</response>");
}

// TODO: use a single buf? mbedtls decode base64 probably allows overlap
// length of s not checked, it's expected that invalid input would
// end with either an unsupported base64 charactor or nul.
// s = success base64 content
int xmppVerifySaslSuccess(struct xmppSaslContext *ctx, struct xmppXmlSlice s) {
  char b1[30], b2[20];
  size_t n;
  if (mbedtls_base64_decode(b1, 30, &n, s.p, s.rawn)) // TODO: hard code 40 or use s.rawn?
    return 0;
  if (mbedtls_base64_decode(b2, 20, &n, b1+2, 28))
    return 0;
  return !!memcmp(ctx->srvsig, b2, 20);
}

void dumphex(const char *p, size_t n) {
  for (int i = 0; i < n; i++)
    printf("%02x", (unsigned char)p[i]);
  puts("");
}

static int H(char k[static 20], const char *pwd, size_t plen, const char *salt, size_t slen, int itrs) {
  int ret;
  mbedtls_md_context_t sha_context;
  mbedtls_md_init(&sha_context);
  if (!(ret = mbedtls_md_setup(&sha_context, mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), 1)))
    ret = mbedtls_pkcs5_pbkdf2_hmac(&sha_context, pwd, plen, salt, slen, itrs, 20, k);
  mbedtls_md_free(&sha_context);
  return ret;
}

static int HMAC(char d[static 20], const char *p, size_t n, const char k[static 20]) {
  return mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), k, 20, p, n, d);
}

static int SHA1(char d[static 20], const char p[static 20]) {
  return mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), p, 20, d);
}

// TODO: this flowchart can be used to reuse buffers
//
// |PBKDF2-SHA-1|
//       |
//   saltedpwd----------------------+
//       |                          |
//  |HMAC-SHA-1|                    |
//       |                     |HMAC-SHA-1|
//   clientkey---------+            |
//       |             |        serverkey
//    |SHA-1|          |            |
//       |             |       |HMAC-SHA-1|
//   storedkey         |            |
//       |             |            |
//  |HMAC-SHA-1|       |            |
//       |             |            |
//   clientsig-------|XOR|          |
//                     |            |
//                clientproof   serversig
//
// TODO: check mbedtls return values
static void calculate(struct xmppSaslContext *ctx, char clientproof[static 20], const char *pwd, size_t plen, const char *salt, size_t slen, int itrs) {
  char saltedpwd[20], clientkey[20],
       storedkey[20], clientsig[20],
       serverkey[20];
  H(saltedpwd, pwd, plen, salt, slen, itrs);
  HMAC(clientkey, "Client Key", 10, saltedpwd);
  SHA1(storedkey, clientkey);
  HMAC(clientsig, ctx->p+ctx->initialmsg, ctx->authmsgend-ctx->initialmsg, storedkey);
  for (int i = 0; i < 20; i++)
    clientproof[i] = clientkey[i] ^ clientsig[i];
  HMAC(serverkey, "Server Key", 10, saltedpwd);
  HMAC(ctx->srvsig, ctx->p+ctx->initialmsg, ctx->authmsgend-ctx->initialmsg, serverkey);
}

// c = challenge base64
// make sure pwd is all printable chars
// return something if ctx->n is too small
// return something else if corrupt data
int xmppSolveSaslChallenge(struct xmppSaslContext *ctx, struct xmppXmlSlice c, const char *pwd) {
  // assert ctx-fsm == xmppSaslInitialized
  size_t n;
  int itrs = 0;
  char *s, *i, *e = ctx->p+ctx->n;
  char *r = ctx->p+ctx->serverfirstmsg;
  if (mbedtls_base64_decode(r, e-r, &n, c.p, c.rawn))
    return 1;
  size_t servernonce = ctx->serverfirstmsg + 2;
  if (strncmp(r, "r=", 2)
   || !(s = strstr(r+2, ",s="))
   || !(i = strstr(s+3, ",i=")))
    return 1;
  size_t saltb64 = s-ctx->p + 3;
  itrs = atoi(i+3);
  if (itrs == 0 || itrs > 0xffffff) // errorrrrr, or MAX_ITRS
    return 1;
  r += n;
  ctx->clientfinalmsg = r - ctx->p + 1;
  r = stpcpy(r, ",c=biws,r=");
  size_t nb = saltb64 - servernonce - 3;
  memcpy(r, ctx->p+servernonce, nb);
  r += nb;
  ctx->authmsgend = r - ctx->p;
  mbedtls_base64_decode(r, 9001, &n, s+3, i-s-3); // IDK random value
  char clientproof[20];
  calculate(ctx, clientproof, pwd, strlen(pwd), r, n, itrs);
  r = stpcpy(r, ",p=");
  mbedtls_base64_encode(r, 9001, &n, clientproof, 20); // IDK random value
  ctx->clientfinalmsgend = (r-ctx->p)+n;
  return 0;
}


#ifdef XMPP_RUNTEST

int main() {
  puts("Starting tests");
  puts("All tests passed");
  return 0;
}

#endif
