#include <mbedtls/pkcs5.h>
#include <mbedtls/base64.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/random.h>
#include <stdbool.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdarg.h>

#include "xmpp.h"
#include "yxml.h"

#include "cacert.h"

// https://sans-io.readthedocs.io/

// mbedtls random source
// https://github.com/Mbed-TLS/mbedtls/blob/2a674bd9ce4758dff0d18f4ac8b6da4419efc504/library/entropy.c#L48
// ESP: https://github.com/espressif/esp-idf/blob/0479494e7abe5aef71393fba2e184b3a78ea488f/components/mbedtls/port/esp_hardware.c#L19

#ifndef NDEBUG
#define Log(fmt, ...) printf(fmt "\n" __VA_OPT__(,) __VA_ARGS__)
#define LogWarn(fmt, ...) fprintf(stderr, "\e[31mWarning:\e[0m " fmt "\n" __VA_OPT__(,)  __VA_ARGS__)
#else
#define Log(fmt, ...) ((void)0)
#define LogWarn(fmt, ...) ((void)0)
#endif

#define RetErr(err) (LogWarn("Returning error at line %d: %s", __LINE__, xmppErrToStr(err)), (err))

// gets the length of the stanza, sees if stanza is complete
// or is larger than max stanza size
// gets length of content stuffs specific to stanza type
// also store pointer offsets of content or attr strings
// maybe mutate original xml?
struct StanzaParser {
  // yxml_t
  int depth;
};

// if (s.p && (d = calloc(s.n+1))) xmppReadXmlSlice(d, s);
// TODO: have specific impl for this?
// TODO: we can skip the whole prefix initialization since that is
// static. just memcpy the internal state to the struct.
void xmppReadXmlSlice(char *d, struct xmppXmlSlice s) {
  static const char attrprefix[] = "<x e='";
  static const char contprefix[] = "<x>";
  char buf[16];
  int i;
  yxml_t x;
  yxml_init(&x, buf, sizeof(buf));
  int target = s.isattr ? YXML_ATTRVAL : YXML_CONTENT;
  const char *prefix = s.isattr ? attrprefix : contprefix;
  size_t n = s.isattr ? sizeof(attrprefix)-1 : sizeof(contprefix)-1;
  for (i = 0; i < n; i++) {
    yxml_parse(&x, prefix[i]);
  }
  for (i = 0; i < s.rawn; i++) {
    // with parsing input validation has already succeeded so there is
    // no reason to check for errors again.
    if (yxml_parse(&x, s.p[i]) == target)
      d = stpcpy(d, x.data);
  }
  if (s.isattr) {
    if (yxml_parse(&x, '\'') == YXML_ATTRVAL)
      d = stpcpy(d, x.data);
  }
}

#define XMPP_EMEM -1
#define XMPP_EXML -2
#define XMPP_ECRYPTO -3
#define XMPP_EPARTIAL -4

const char *xmppErrToStr(int e) {
  switch (e) {
  case XMPP_EMEM: return "XMPP_EMEM";
  case XMPP_EXML: return "XMPP_EXML";
  case XMPP_ECRYPTO: return "XMPP_ECRYPTO";
  case XMPP_EPARTIAL: return "XMPP_EPARTIAL";
  }
  return "[unknown error]";
}

#define XMPP_SASL_CHALLENGE 1
#define XMPP_SASL_SUCCESS   2

#define XMPP_STREAMFEATURE_STARTTLS (1 << 0)
#define XMPP_STREAMFEATURE_BIND (1 << 1)
#define XMPP_STREAMFEATURE_SCRAMSHA1 (1 << 2)
#define XMPP_STREAMFEATURE_SCRAMSHA1PLUS (1 << 3)
#define XMPP_STREAMFEATURE_PLAIN (1 << 4)


#define XMPP_STANZA_EMPTY 0
#define XMPP_STANZA_MESSAGE 1
#define XMPP_STANZA_PRESENCE 2
#define XMPP_STANZA_IQ 3
#define XMPP_STANZA_STREAMFEATURES 4
#define XMPP_STANZA_BINDJID 5
#define XMPP_STANZA_SMACKSENABLED 6
#define XMPP_STANZA_ACKREQUEST 7
#define XMPP_STANZA_ACKANSWER 8


// Any of the child elements can be null.
// We only support a single body, subject, etc. This deviates from the spec.
// It will only read the first instance.
struct xmppMessage {
  struct xmppXmlSlice body, thread, treadparent, subject;
};

// 8.3.2
#define XMPP_ERRORTYPE_AUTH 1
#define XMPP_ERRORTYPE_CANCEL 2
#define XMPP_ERRORTYPE_CONTINUE 3
#define XMPP_ERRORTYPE_MODIFY 4
#define XMPP_ERRORTYPE_WAIT 5

#define XMPP_ERRORCONDITION_BAD_REQUEST
#define XMPP_ERRORCONDITION_CONFLICT
#define XMPP_ERRORCONDITION_FEATURE_NOT_IMPLEMENTED
#define XMPP_ERRORCONDITION_FORBIDDEN
#define XMPP_ERRORCONDITION_GONE
// etc.. rfc6120 8.3.3

struct xmppError {
  int stanzakind;
  int errortype;
  int condition;
  struct xmppXmlSlice text;
};

struct xmppSmacksEnabled {
  int max;
  bool resume;
};

struct xmppStanza {
  int type; // iq/message/presence
  struct xmppXmlSlice id, from, to;
  union {
    //struct xmppXmlSlice challenge;
    //struct xmppXmlSlice success;
    struct xmppMessage message;
    struct xmppError error;
    struct xmppXmlSlice bindjid;
    struct xmppSmacksEnabled smacksenabled;
    int ack;
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

#define HasOverflowed(p, e) ((p) == (e))

// TODO: extract out to separate struct Parser
// TODO: don't use yxml, but in-house parser,
// dozens of LOC can be removed because XMPP only allows subset of XML
// and the usage here is usecase specific.
struct xmppParser {
  yxml_t x;
  int i, n;
  const char *p;
};

struct xmppStream {
  struct xmppXmlSlice from, to, id;
  int features;
};

struct xmppClient {
  int sentacks, recvacks;
};

// Skip all the way until the end of the element it has just entered
// ret:
//   < 0: XMPP error
//   = 0: OK
static int SkipUnknownXml(struct xmppParser *p) {
  int stack = 1;
  while (p->i < p->n) {
    yxml_ret_t r = yxml_parse(&p->x, p->p[p->i++]);
    switch (r) {
    case YXML_ELEMSTART:
      stack++;
      break;
    case YXML_ELEMEND:
      if (--stack == 0)
        return 0;
      break;
    default:
      if (r < 0)
        return XMPP_EXML;
    }
  }
  return RetErr(XMPP_EPARTIAL);
}

// ret:
//  < 0: XMPP error
//  = 0: OK
//  = 1: end
// attribute name will be in s->x.attr
// slc will contain the attr value
// MUST be called directly after YXML_ELEMSTART
// even for a self-closing element, it will not trigger in this function.
static int ParseAttribute(struct xmppParser *p, struct xmppXmlSlice *slc) {
  int r;
  slc->p = NULL;
  slc->n = 0;
  slc->rawn = 0;
  slc->isattr = true;
  while (1) { // hacky way to check end of attr list
    if (!slc->p && (p->p[p->i-1] == '>' || p->p[p->i-1] == '/'))
      return 0;
    if (!(p->i < p->n))
      break;
    switch ((r = yxml_parse(&p->x, p->p[p->i++]))) {
    case YXML_ATTREND:
      return 1;
    case YXML_ATTRVAL:
      if (!slc->p)
        slc->p = p->p + p->i - 1;
      slc->n += strlen(p->x.data);
      break;
    default:
      if (r < 0)
        return XMPP_EXML;
    }
    if (slc->p)
      slc->rawn++;
  }
  return XMPP_EPARTIAL;
}

// MAY ONLY be called after ParseAttribute returns 1
// or right after ELEMSTART
// will read all the way to end of element
static int GetXmlContent(struct xmppParser *p, struct xmppXmlSlice *slc) {
  int r;
  bool stop = false;
  struct xmppXmlSlice attr;
  slc->p = NULL;
  slc->n = 0;
  slc->rawn = 0;
  slc->isattr = false;
  while ((r = ParseAttribute(p, &attr)) > 0) {}
  if (r < 0) return r;
  while (p->i < p->n) {
    if (!slc->p) {
      if (p->p[p->i - 1] == '>')
        slc->p = p->p + p->i;
    }
    if (p->p[p->i] == '<') stop = true; // TODO: this is stupid
    switch ((r = yxml_parse(&p->x, p->p[p->i++]))) {
    case YXML_ELEMEND:
      return 0;
    case YXML_CONTENT:
      if (!slc->p) // TODO: remove this...
        slc->p = p->p + p->i - 1;
      slc->n += strlen(p->x.data);
      break;
    default:
      if (r < 0)
        return XMPP_EXML;
    }
    if (slc->p && !stop)
      slc->rawn++;
  }
  return XMPP_EPARTIAL;
}

// elem = the found xml element name
// n = the length of said element name
// opt = opt string ("<char>=<element-name> <char2>=<element-name2>...")
// returns found char or 0
static int FindElement(const char *elem, size_t n, const char *opt) {
  const char *p = opt;
  if (!elem || !n)
    return XMPP_EXML;
  // might be more efficient with strchr & strspn.
  while ((p = strstr(p, elem))) {
    if (p-opt >= 2 && p[-1] == '='
      && (p[n] == '\0' || p[n] == ' '))
      return p[-2];
    p++;
  }
  return '?';
}

// opposite of inspect element ;)
// returns 1 when end of parent element
static int ExpectElement(struct xmppParser *p) { //, const char *opt) {
  int r;
  while (p->i < p->n) {
    switch ((r = yxml_parse(&p->x, p->p[p->i++]))) {
    case YXML_OK:
      break;
    case YXML_ELEMSTART:
      return 1; //return FindElement(s->x.elem, yxml_symlen(s->x.elem), opt);
    case YXML_ELEMEND:
      return 0;
    default:
      if (r < 0)
        return XMPP_EXML;
    }
  }
  return XMPP_EPARTIAL;
}

static int SliceToI(struct xmppXmlSlice s) {
  int v = 0;
  bool neg = s.rawn > 0 && s.p[0] == '-';
  for (int i = 0; i < s.rawn; i++) {
    if (s.p[i] < '0' || s.p[i] > '9')
      return 0;
    v = v * 10 + s.p[i];
  }
  return neg ? -v : v;
}

static int ReadAck(struct xmppParser *p, struct xmppStanza *st) {
  struct xmppXmlSlice attr;
  int r;
  st->type = XMPP_STANZA_ACKANSWER;
  while ((r = ParseAttribute(p, &attr)) > 0) {
    if (!strcmp(p->x.elem, "h"))
      st->ack = SliceToI(attr);
  }
  return r < 0 ? r : SkipUnknownXml(p);
}

// TODO: have new yxml state per stanza, this is only because if a stanza is partial
// we want to ignore it and let the user decide if it needs to get more data from server
// and read it again, the yxml would be messed up for reading again
// maybe this is not needed.
// But right now if we want to correctly detect </stream:stream>, the new yxml state should
// start with <stream:stream>
int xmppReadStanza(struct xmppParser *p, struct xmppStanza *st) {
  // As with xmppReadXmlSlice, we might be able to init yxml with memset
  static const char prefix[] = "<stream:stream>";
  int i, r;
  struct xmppXmlSlice attr;
  for (i = 0; i < sizeof(prefix)-1; i++) {
    yxml_parse(&p->x, prefix[i]);
  }
  memset(st, 0, sizeof(*st));
  if ((r = ExpectElement(p)))
    return r < 0 ? r : XMPP_EXML;
  if (!strcmp(p->x.elem, "iq")) st->type = XMPP_STANZA_IQ;
  else if (!strcmp(p->x.elem, "a")) return ReadAck(p, st);
  else if (!strcmp(p->x.elem, "r")) {
    st->type = XMPP_STANZA_ACKREQUEST;
    return SkipUnknownXml(p);
  }
  //while ((r = ParseAttribute(s, &attr)) > 0) {
  //  if (!strcmp(s->x.attr)
  //}
  return xmppStanzaReadNothing;
}

// Read stream and features
// Features ALWAYS come after server stream according to spec
// If server too slow, user should read more.
int xmppExpectStream(struct xmppParser *p, struct xmppStream *s) {
  struct xmppXmlSlice attr;
  int r;
  s->features = 0;
  if ((r = ExpectElement(p)) <= 0 || strcmp(p->x.elem, "stream:stream"))
    return r < 0 ? r : XMPP_EXML;
  while ((r = ParseAttribute(p, &attr)) > 0) {
    if (!strcmp(p->x.attr, "id")) {
      memcpy(&s->id, &attr, sizeof(attr));
    } else if (!strcmp(p->x.attr, "from")) {
      memcpy(&s->from, &attr, sizeof(attr));
    } else if (!strcmp(p->x.attr, "to")) {
      memcpy(&s->to, &attr, sizeof(attr));
    }
  }
  if (r < 0)
    return r;
  if ((r = ExpectElement(p)) <= 0 || strcmp(p->x.elem, "stream:features"))
    return r < 0 ? r : XMPP_EXML;
  while ((r = ExpectElement(p)) > 0) {
    if (!strcmp(p->x.elem, "starttls")) {
      s->features |= XMPP_STREAMFEATURE_STARTTLS;
    } else if (!strcmp(p->x.elem, "mechanisms")) {
      while ((r = ExpectElement(p)) > 0) { // TODO: check if elem is mechanism
        struct xmppXmlSlice mech;
        if ((r = GetXmlContent(p, &mech)))
          return r;
        if (!strncmp(mech.p, "SCRAM-SHA-1", mech.n)) // TODO: mech.rawn
          s->features |= XMPP_STREAMFEATURE_SCRAMSHA1;
        else if (!strncmp(mech.p, "SCRAM-SHA-1-PLUS", mech.n)) // TODO: mech.rawn
          s->features |= XMPP_STREAMFEATURE_SCRAMSHA1PLUS;
        else if (!strncmp(mech.p, "PLAIN", mech.n)) // TODO: mech.rawn
          s->features |= XMPP_STREAMFEATURE_PLAIN;
      }
      if (r < 0)
        return r;
      continue;
    }
    if ((r = SkipUnknownXml(p)))
      return r;
  }
  if (r < 0)
    return r;
  return 0;
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
  memset(ctx, 0, sizeof(*ctx));
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

static char *EncodeBase64(char *d, char *e, const char *s, size_t n) {
  if (mbedtls_base64_encode((unsigned char *)d, e-d, &n, (const unsigned char *)s, n))
    return e;
  return d+n;
}

static char *DecodeBase64(char *d, char *e, const char *s, size_t n, bool nul) {
  if (mbedtls_base64_decode((unsigned char *)d, e-d, &n, (const unsigned char *)s, n))
    return e;
  if (nul) {
  }
  return d+n;
}

static char *EncodeXmlString(char *d, char *e, const char *s) {
  for (;*s && d < e; s++) {
    switch (*s) {
    break; case '"': d = SafeStpCpy(d, e, "&quot;");
    break; case '\'': d = SafeStpCpy(d, e, "&apos;");
    break; case '&': d = SafeStpCpy(d, e, "&amp;");
    break; case '<': d = SafeStpCpy(d, e, "&lt;");
    break; case '>': d = SafeStpCpy(d, e, "&gt;");
    break; default:
      *d++ = *s;
      break;
    }
  }
  return d;
}

// TODO: maybe add more features like padding
static char *Itoa(char *d, char *e, int i) {
  char buf[16];
  int mult = 1;
  int n = 0;
  if (i < 0)
    mult = -1;
  while (i && n < sizeof(buf)) {
    buf[n++] = '0' + (i % 10) * mult;
    i /= 10;
  }
  if (mult == -1 && n < sizeof(buf))
    buf[n++] = '-';
  while (n-- && d < e) {
    *d++ = buf[n];
  }
  return d;
}

// Analogous to the typical printf formatting, except only the following applies:
// - %s: Encoded XML attribute value string
// - %b: Base64 string, first arg is len and second is raw data
// - %d: unsigned integer
// TODO: the rest... are they really needed?
// TODO: change sig to size_t FormatXml(char *d, size_t n, fmt, ...)?
static char *FormatXml(char *d, char *e, const char *fmt, ...) {
  va_list ap;
  bool skip = false;
  size_t n;
  int i;
  const char *s;
  va_start(ap, fmt);
  for (; *fmt && d < e; fmt++) {
    switch (*fmt) {
    break; case '%':
      fmt++;
      switch (*fmt) {
      break; case 'd':
        i = va_arg(ap, int);
        if (!skip)
          d = Itoa(d, e, i);
      break; case 's': // xml string
        s = va_arg(ap, const char*);
        if (!skip)
          d = EncodeXmlString(d, e, s);
      break; case 'c': // content TODO: different encoding than xml string?
      break; case 'b': // base64
        n = va_arg(ap, size_t);
        s = va_arg(ap, const char*);
        if (!skip)
          d = EncodeBase64(d, e, s, n);
      }
    break; case '[': skip = !va_arg(ap, int); // actually bool
    break; case ']': skip = false;
    break; default:
      if (!skip)
        *d++ = *fmt;
    }
  }
  va_end(ap);
  if (d < e)
    *d = 0;
  return d;
}

#define xmppFormatStream(p, e, from, to) FormatXml(p, e, \
    "<?xml version='1.0'?>" \
    "<stream:stream xmlns='jabber:client'" \
    " version='1.0' xmlns:stream='http://etherx.jabber.org/streams'" \
    " from='%s' to='%s'>", from, to);

// For static XML we can directly call SafeStpCpy
#define xmppFormatStartTls(p, e) SafeStpCpy(p, e, "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")

char *xmppFormatSaslInitialMessage(char *p, char *e, struct xmppSaslContext *ctx) {
  return FormatXml(p, e, 
      "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='SCRAM-SHA-1'>%b</auth>", ctx->serverfirstmsg-1, ctx->p);
}

char *xmppFormatSaslResponse(char *p, char *e, struct xmppSaslContext *ctx) {
  return FormatXml(p, e,
      "<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>%b</response>", 
      ctx->clientfinalmsgend-ctx->clientfinalmsg, ctx->p+ctx->clientfinalmsg);
}

// TODO: use a single buf? mbedtls decode base64 probably allows overlap
// length of s not checked, it's expected that invalid input would
// end with either an unsupported base64 charactor or nul.
// s = success base64 content
int xmppVerifySaslSuccess(struct xmppSaslContext *ctx, struct xmppXmlSlice s) {
  char b1[30], b2[20];
  size_t n;
  if (mbedtls_base64_decode(b1, 30, &n, s.p, s.rawn)
   || mbedtls_base64_decode(b2, 20, &n, b1+2, 28))
    return XMPP_EXML;
  return !!memcmp(ctx->srvsig, b2, 20);
}

void dumphex(const char *p, size_t n) {
  for (int i = 0; i < n; i++)
    printf("%02x", (unsigned char)p[i]);
  puts("");
}

void dumpxmlslice(struct xmppXmlSlice slc) {
  printf("XML SLICE n %ld rawn %ld %.*s\n", slc.n, slc.rawn, (int)slc.n, slc.p);
}

static int H(char k[static 20], const char *pwd, size_t plen, const char *salt, size_t slen, int itrs) {
  int r;
  mbedtls_md_context_t sha_context;
  mbedtls_md_init(&sha_context);
  if (!(r = mbedtls_md_setup(&sha_context, mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), 1)))
    r = mbedtls_pkcs5_pbkdf2_hmac(&sha_context, pwd, plen, salt, slen, itrs, 20, k);
  mbedtls_md_free(&sha_context);
  if (r != 0) {
    LogWarn("MbedTLS PBKDF2-HMAC error: %s", mbedtls_high_level_strerr(r));
    return 0;
  }
  return 1;
}

static int HMAC(char d[static 20], const char *p, size_t n, const char k[static 20]) {
  int r = mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), k, 20, p, n, d);
  if (r != 0) {
    LogWarn("MbedTLS HMAC error: %s", mbedtls_high_level_strerr(r));
    return 0;
  }
  return 1;
}

static int SHA1(char d[static 20], const char p[static 20]) {
  int r = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), p, 20, d);
  if (r != 0) {
    LogWarn("MbedTLS SHA1 error: %s", mbedtls_high_level_strerr(r));
    return 0;
  }
  return 1;
}

static int XorSha1(char d[20], const char a[20], const char b[20]) {
  for (int i = 0; i < 20; i++)
    d[i] = a[i] ^ b[i];
  return 1;
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
static int calculate(struct xmppSaslContext *ctx, char clientproof[static 20], const char *pwd, size_t plen, const char *salt, size_t slen, int itrs) {
  char saltedpwd[20], clientkey[20],
  storedkey[20], clientsig[20],
  serverkey[20];
  return H(saltedpwd, pwd, plen, salt, slen, itrs)
    && HMAC(clientkey, "Client Key", 10, saltedpwd)
    && SHA1(storedkey, clientkey)
    && HMAC(clientsig, ctx->p+ctx->initialmsg, ctx->authmsgend-ctx->initialmsg, storedkey)
    && XorSha1(clientproof, clientkey, clientsig)
    && HMAC(serverkey, "Server Key", 10, saltedpwd)
    && HMAC(ctx->srvsig, ctx->p+ctx->initialmsg, ctx->authmsgend-ctx->initialmsg, serverkey);
}

// TODO: error handling
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
    return XMPP_EMEM;
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
  if (!calculate(ctx, clientproof, pwd, strlen(pwd), r, n, itrs))
    return XMPP_ECRYPTO;
  r = stpcpy(r, ",p=");
  mbedtls_base64_encode(r, 9001, &n, clientproof, 20); // IDK random value
  ctx->clientfinalmsgend = (r-ctx->p)+n;
  return 0;
}

static void GetChallengeRealFast(const char *p, struct xmppXmlSlice *s) {
  for (;*p;p++) {
    if (*p == '>') {
      s->p = p+1;
      break;
    }
  }
  for (;*p;p++) {
    if (*p == '<') {
      s->n = s->rawn = p - s->p;
      break;
    }
  }
}

// TODO: incorporate the following ~three functions in xmppReadStanza?

// ret
//  < 0: error
//  = 0: yes
//  > 0: no
int xmppCanTlsProceed(struct xmppParser *s) {
  int r;
  if ((r = ExpectElement(s)) <= 0) // TODO: || (r = SkipUnknownXml(s))) not needed
    return r < 0 ? r : XMPP_EXML;
  if (!strcmp(s->x.elem, "proceed"))
    return 0;
  else if (!strcmp(s->x.elem, "failure"))
    return 1;
  return XMPP_EXML;
}

int xmppGetSaslChallenge(struct xmppParser *s, struct xmppXmlSlice *c) {
  int r;
  struct xmppXmlSlice attr;
  if ((r = ExpectElement(s)) <= 0)
    return r < 0 ? r : XMPP_EXML;
  if (strcmp(s->x.elem, "challenge"))
    return XMPP_EXML;
  return GetXmlContent(s, c);
}

// TODO: function body looks suspiciously like the above
// consider refactoring
// ret
//  < 0: error
//  = 0: success
//  > 0: fail
int xmppIsSaslSuccess(struct xmppParser *s, struct xmppSaslContext *ctx) {
  int r;
  struct xmppXmlSlice slc;
  if ((r = ExpectElement(s)) <= 0)
    return r < 0 ? r : XMPP_EXML;
  if (strcmp(s->x.elem, "success"))
    return XMPP_EXML;
  if ((r = GetXmlContent(s, &slc)))
    return r;
  return xmppVerifySaslSuccess(ctx, slc);
}

// use this function when the in buffer has been filled, you've read
// some previous stanzas and now the stanza at the end couldn't be
// fully read, so you move it all the way forward and read the
// remaining parts (+ more stanzas).
// p is beginning of response buffer
// n is size of all response data
// s is end of last stanza, start of possible second stanza
// returns end of last resonse data
static size_t MoveStanza(char *p, size_t n, size_t s) {
  memmove(p, p + s, n - s);
  return n - s;
}

#define xmppFormatIq(p, e, from, to, id, fmt, ...) FormatXml(p, e, "<iq" \
    " type='get'" \
    " from='%s'" \
    " to='%s'" \
    " id='%s'>" fmt "</iq>", \
    from, to, id \
    __VA_OPT__(,) __VA_ARGS__)

// TODO: better way to do this?
// res: string or NULL if you want the server to generate it
#define xmppFormatBindResource(p, e, from, to, id, res) \
  xmppFormatIq(p, e, from, to, id, \
      "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'[/>][><resource>%s</resource></bind>]", \
      !res, !!res, res)

// XEP-0199: XMPP Ping

#define xmppFormatPing(p, e, from, to, id) xmppFormatIq(p, e, from, to, id, "<ping xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")

// XEP-0030: Service Discovery

#define xmppFormatDisco(p, e, from, to, id) xmppFormatIq(p, e, from, to, id, "<query xmlns='http://jabber.org/protocol/disco#info'/>")

// XEP-0198: Stream Management

#define xmppFormatAckEnable(p, e) SafeStpCpy(p, e, "<enable xmlns='urn:xmpp:sm:3'/>")
#define xmppFormatAckResume(p, e, h, previd) FormatXml(p, e, "<resume xmlns='urn:xmpp:sm:3' h='%d' previd='%s'/>", h, previd)
#define xmppFormatAckRequest(p, e) SafeStpCpy(p, e, "<r xmlns='urn:xmpp:sm:3'/>")
#define xmppFormatAckAnswer(p, e, h) FormatXml(p, e, "<a xmlns='urn:xmpp:sm:3' h='%d'/>", h)

#ifdef XMPP_RUNTEST

static char in[10000], out[10000], saslbuf[1000], yxmlbuf[1000];
static mbedtls_ssl_context ssl;
static mbedtls_net_context server_fd;
static struct xmppParser parser;

static struct xmppParser SetupXmppParser(const char *xml) {
  static char buf[1000];
  struct xmppParser p = {0};
  yxml_init(&p.x, buf, sizeof(buf));
  p.p = xml;
  p.i = 0;
  p.n = strlen(xml);
  return p;
}

static char *CloneXmlSlice(struct xmppXmlSlice slc) {
  char *d = NULL;
  if (slc.p && (d = calloc(slc.n+1, 1)))
    xmppReadXmlSlice(d, slc);
  return d;
}

static void TestXml() {
  struct xmppStream str;
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
  assert(xmppExpectStream(&p, &str) == 0);
  assert(str.to.p && !strncmp(str.to.p, "juliet@im.example.com", str.to.rawn));
  assert(str.to.rawn == str.to.n);
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
}

static void TestSkipUnknownXml() {
}

static void TestSasl() {
  static char buffer[xmppMinMaxStanzaSize+1], buffer2[1000];
  char *bufe = buffer + sizeof(buffer);
  struct xmppSaslContext ctx;
  xmppInitSaslContext(&ctx, buffer2, sizeof(buffer2), "user");
  xmppFormatSaslInitialMessage(buffer, bufe, &ctx);
  printf("initial: %s\n", buffer);
  const char *challenge =  "cj1meWtvK2QybGJiRmdPTlJ2OXFreGRhd0wzcmZjTkhZSlkxWlZ2V1ZzN2oscz1RU1hDUitRNnNlazhiZjkyLGk9NDA5Ng==";
  struct xmppXmlSlice c = { .p = challenge, .rawn = strlen(challenge) };
  printf("sasl: %d\n", xmppSolveSaslChallenge(&ctx, c, "pencil"));
  xmppFormatSaslResponse(buffer, bufe, &ctx);
  puts(buffer);
  memcpy(ctx.srvsig, "\xae\x61\x7d\xa6\xa5\x7c\x4b\xbb\x2e\x02\x86\x56\x8d\xae\x1d\x25\x19\x05\xb0\xa4", 20);
  c.p =  "dj1ybUY5cHFWOFM3c3VBb1pXamE0ZEpSa0ZzS1E9";
  c.rawn = strlen(c.p);
  printf("%d\n", xmppVerifySaslSuccess(&ctx, c));
}

static void Transfer(int s, char *e) {
  printf("Sending %s\n", out);
  write(s, out, e-out);
  int r;
  if ((r = read(s, in, sizeof(in))) > 0) {
    in[r] = '\0';
    printf("Got response %d %s\n", r, in);
  }
}

// these macros are getting too crazy...
// method either net or ssl
// fn is xmppFormat* function
// ... is args passed after format
#define Send(method, ctx, fn, ...) do { \
  char *end = fn(out, out+sizeof(out) __VA_OPT__(,) __VA_ARGS__); \
  Log("Out: \e[32m%s\e[0m", out); \
  mbedtls_##method(ctx, out, end - out); \
} while (0)

#define SendPlain(...) Send(net_send, &server_fd, __VA_ARGS__)
#define SendSsl(...) Send(ssl_write, &ssl, __VA_ARGS__)

#define Receive(method, ctx) do { \
  size_t n = mbedtls_##method(ctx, in, sizeof(in)); \
  parser.p = in; \
  parser.n = n; \
  parser.i = 0; \
  yxml_init(&parser.x, yxmlbuf, sizeof(yxmlbuf)); \
  in[n] = '\0'; \
  Log("In:  \e[34m%s\e[0m", in); \
} while (0)

#define ReceivePlain() Receive(net_recv, &server_fd)
#define ReceiveSsl() Receive(ssl_read, &ssl)

void thing() {
  char *buf = NULL;
  int ret, len;
  struct xmppStream stream;

  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_x509_crt cacert;
  mbedtls_ssl_config conf;

  mbedtls_ssl_init(&ssl);
  mbedtls_x509_crt_init(&cacert);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_ssl_config_init(&conf);
  mbedtls_entropy_init(&entropy);

  assert(mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0) == 0);
  assert(mbedtls_x509_crt_parse(&cacert, cacert_pem, cacert_pem_len) >= 0);

  assert(mbedtls_ssl_set_hostname(&ssl, "localhost") == 0);
  assert(mbedtls_ssl_config_defaults(&conf,
          MBEDTLS_SSL_IS_CLIENT,
          MBEDTLS_SSL_TRANSPORT_STREAM,
          MBEDTLS_SSL_PRESET_DEFAULT) == 0);
  mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
  mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
  mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
  assert(mbedtls_ssl_setup(&ssl, &conf) == 0);

  mbedtls_net_init(&server_fd);
  assert(mbedtls_net_connect(&server_fd, "localhost",
          "5222", MBEDTLS_NET_PROTO_TCP) == 0);
  mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

  SendPlain(xmppFormatStream, "admin@localhost", "localhost");
  ReceivePlain();
  assert(xmppExpectStream(&parser, &stream) == 0);
  assert(stream.features & XMPP_STREAMFEATURE_STARTTLS);
  SendPlain(xmppFormatStartTls);
  ReceivePlain();
  assert(xmppCanTlsProceed(&parser) == 0);

	while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
		if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
      printf("%d\n", ret);
			assert(false);
		}
	}

  int flags;
	if ((flags = mbedtls_ssl_get_verify_result(&ssl)) != 0) {
    puts("cert faile");
	} else {
    puts("cert Successssss");
	}
  SendSsl(xmppFormatStream, "admin@localhost", "localhost");
  ReceiveSsl();
  assert(xmppExpectStream(&parser, &stream) == 0);
  assert(stream.features & XMPP_STREAMFEATURE_SCRAMSHA1);

  struct xmppSaslContext ctx;
  struct xmppXmlSlice challenge;
  xmppInitSaslContext(&ctx, saslbuf, sizeof(saslbuf), "admin");
  SendSsl(xmppFormatSaslInitialMessage, &ctx);
  ReceiveSsl();
  assert(xmppGetSaslChallenge(&parser, &challenge) == 0);
  dumpxmlslice(challenge);
  xmppSolveSaslChallenge(&ctx, challenge, "adminpass");
  SendSsl(xmppFormatSaslResponse, &ctx);
  ReceiveSsl();
  assert(xmppIsSaslSuccess(&parser, &ctx) == 0);

  SendSsl(xmppFormatStream, "admin@localhost", "localhost");
  ReceiveSsl();
  assert(xmppExpectStream(&parser, &stream) == 0);
  SendSsl(xmppFormatBindResource, "admin@localhost", "localhost", "bind1", NULL);
  ReceiveSsl();

  //xmppFormatAckAnswer(out, out+sizeof(out), INT_MAX);
  //Log("%s %d\n", out, INT_MAX);

  mbedtls_ssl_close_notify(&ssl);
  mbedtls_net_free(&server_fd);
  mbedtls_x509_crt_free(&cacert);
  mbedtls_ssl_free(&ssl);
  mbedtls_ssl_config_free(&conf);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
}

static void Do(int s) {
  struct xmppSaslContext ctx;
  struct xmppXmlSlice c;
  char *e = xmppFormatStream(out, out+sizeof(out), "admin@localhost", "localhost");
  Transfer(s, e);
  xmppInitSaslContext(&ctx, saslbuf, sizeof(saslbuf), "admin");
  e = xmppFormatSaslInitialMessage(out, out+sizeof(out), &ctx);
  Transfer(s, e);
  GetChallengeRealFast(in, &c);
  //printf("%p %d\n", c.p, c.rawn);
  xmppSolveSaslChallenge(&ctx, c, "adminpass");
  e = xmppFormatSaslResponse(out, out+sizeof(out), &ctx);
  Transfer(s, e);
  GetChallengeRealFast(in, &c);
  printf("Success? %s\n", xmppVerifySaslSuccess(&ctx, c) == 0 ? "yes" : "no");
}

static void TestConnection() {
  int s = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in sa = {0};
  sa.sin_family = AF_INET;
  sa.sin_port = htons(5222);
  puts("Connecting");
  if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) < 0)
    perror("connection failed");
  puts("Connected");
  Do(s);
  close(s);
}

// minimum maximum stanza size = 10000
int main() {
  puts("Starting tests");
  //TestXml();
  thing();
  //TestSasl();
  //TestConnection();
  puts("All tests passed");
  return 0;
}

#if 0

https://github.com/espressif/esp-idf/blob/master/examples/protocols/smtp_client/main/smtp_client_example_main.c

struct xmppClient c;
char req[10000], resp[10000];
xmppInitiate(&c, from, to, features); // features can be SASLSCRAMSHA1|SASLPLAIN|TLS|MUSTTLS
xmppFormatStream();
write();

read();
xmppParseStream(); // parse stream and features

// r could be one of 
//  | PARTIAL(req buffer not complete, stanza not complete ending, so should read more bytes from stream)
//  | SEND(should send req)
int r = xmppIterate(req, strlen(req), resp, sizeof(resp));

#endif

#endif
