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
#include <setjmp.h>

#include "xmpp.h"
#include "yxml.h"

#ifndef NDEBUG
#define Log(fmt, ...) printf(fmt "\n" __VA_OPT__(,) __VA_ARGS__)
#define LogWarn(fmt, ...) fprintf(stderr, "\e[31mWarning:\e[0m " fmt "\n" __VA_OPT__(,)  __VA_ARGS__)
#else
#define Log(fmt, ...) ((void)0)
#define LogWarn(fmt, ...) ((void)0)
#endif

static char *EncodeBase64(char *d, char *e, const char *s, size_t n) {
  if (mbedtls_base64_encode((unsigned char *)d, e-d, &n, (const unsigned char *)s, n))
    return e;
  return d+n;
}

static char *DecodeBase64(char *d, char *e, const char *s, size_t n) {
  if (mbedtls_base64_decode((unsigned char *)d, e-d, &n, (const unsigned char *)s, n))
    return e;
  return d+n;
}

// Check if some user provided string u with size n matches a constant
// string c. This function is useful for when n is not constant. It is
// reasonable to compare XML strings using this, however we expect that
// there are no useless entities or CDATA.
// Returns true if matches, be careful it's the opposite of strcmp.
static bool StrictStrEqual(const char *c, const char *u, size_t n) {
  while (--n) {
    if (!c || *c++ != *u++)
      return false;
  }
  return !c[1] && !n;
}

// Usage:
//  if (s.p && (d = calloc(s.n+1))) xmppReadXmlSlice(d, s);
// TODO: we can skip the whole prefix initialization since that is
// static. just memcpy the internal state to the struct.
void xmppReadXmlSlice(char *d, struct xmppXmlSlice s) {
  if (s.type == XMPP_SLICE_ATTR || s.type == XMPP_SLICE_CONT) {
    static const char attrprefix[] = "<x e=";
    static const char contprefix[] = "<x>";
    char buf[16];
    int i, n;
    yxml_t x;
    yxml_init(&x, buf, sizeof(buf));
    int target = s.type == XMPP_SLICE_ATTR ? YXML_ATTRVAL : YXML_CONTENT;
    const char *prefix = s.type == XMPP_SLICE_ATTR ? attrprefix : contprefix;
    n = s.type == XMPP_SLICE_ATTR ? sizeof(attrprefix)-1 : sizeof(contprefix)-1;
    for (i = 0; i < n; i++) {
      yxml_parse(&x, prefix[i]);
    }
    i = 0;
    n = s.rawn;
    if (s.type == XMPP_SLICE_ATTR) { // Also parse the '/"
      i--;
      n++;
    }
    for (; i < n; i++) {
      // with parsing input validation has already succeeded so there is
      // no reason to check for errors again.
      if (yxml_parse(&x, s.p[i]) == target)
        d = stpcpy(d, x.data);
    }
  } else if (s.type == XMPP_SLICE_B64) {
    DecodeBase64(d, d+s.n, s.p, s.rawn); // TODO: check if b64 is valid.
  } else {
    memcpy(d, s.p, s.rawn);
  }
}

const char *xmppErrToStr(int e) {
  switch (e) {
  case XMPP_EMEM: return "XMPP_EMEM";
  case XMPP_EXML: return "XMPP_EXML";
  case XMPP_ECRYPTO: return "XMPP_ECRYPTO";
  case XMPP_EPARTIAL: return "XMPP_EPARTIAL";
  }
  return "[unknown error]";
}

struct xmppListIterator {
  int type;
  const char *p;
  size_t i, rawn;
};

static bool ComparePaddedString(const char *p, const char *s, size_t pn) {
  return true;
}

#define HasOverflowed(p, e) ((p) >= (e))

// Skip all the way until the end of the element it has just entered
void xmppParseUnknown(struct xmppParser *p) {
  int stack = 1;
  while (p->i < p->n) {
    yxml_ret_t r = yxml_parse(&p->x, p->p[p->i++]);
    switch (r) {
    case YXML_ELEMSTART:
      stack++;
      break;
    case YXML_ELEMEND:
      if (--stack == 0)
        return;
      break;
    default:
      if (r < 0)
        longjmp(p->jb, XMPP_EXML);
    }
  }
  longjmp(p->jb, XMPP_EPARTIAL);
}

// ret:
//  = 0: OK
//  = 1: end
// attribute name will be in s->x.attr
// slc will contain the attr value
// MUST be called directly after YXML_ELEMSTART
// even for a self-closing element, it will not trigger in this function.
int xmppParseAttribute(struct xmppParser *p, struct xmppXmlSlice *slc) {
  int r;
  slc->p = NULL;
  slc->n = 0;
  slc->rawn = 0;
  slc->type = XMPP_SLICE_ATTR;
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
        longjmp(p->jb, XMPP_EXML);
    }
    if (slc->p)
      slc->rawn++;
  }
  longjmp(p->jb, XMPP_EPARTIAL);
}

// MAY ONLY be called after xmppParseAttribute returns 1
// or right after ELEMSTART
// will read all the way to end of element
void xmppParseContent(struct xmppParser *p, struct xmppXmlSlice *slc) {
  int r;
  bool stop = false;
  struct xmppXmlSlice attr;
  memset(slc, 0, sizeof(*slc));
  slc->type = XMPP_SLICE_CONT;
  while (xmppParseAttribute(p, &attr)) {}
  while (p->i < p->n) {
    if (!slc->p) {
      if (p->p[p->i - 1] == '>')
        slc->p = p->p + p->i;
    }
    if (p->p[p->i] == '<') stop = true; // TODO: this is stupid
    switch ((r = yxml_parse(&p->x, p->p[p->i++]))) {
    case YXML_ELEMEND:
      return;
    case YXML_CONTENT:
      if (!slc->p) // TODO: remove this...
        slc->p = p->p + p->i - 1;
      slc->n += strlen(p->x.data);
      break;
    default:
      if (r < 0)
        longjmp(p->jb, XMPP_EXML);
    }
    if (slc->p && !stop)
      slc->rawn++;
  }
  longjmp(p->jb, XMPP_EPARTIAL);
}

// TODO: we don't need this function anymore
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

// returns 0 when end of parent element
int xmppParseElement(struct xmppParser *p) {
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
        longjmp(p->jb, XMPP_EXML);
    }
  }
  longjmp(p->jb, XMPP_EPARTIAL);
}

static int SliceToI(struct xmppXmlSlice s) {
  int v = 0;
  bool neg = s.rawn > 0 && s.p[0] == '-';
  for (int i = 0; i < s.rawn; i++) {
    if (s.p[i] < '0' || s.p[i] > '9')
      return 0;
    v = v * 10 + (s.p[i] - '0');
  }
  return neg ? -v : v;
}

static void ReadAckAnswer(struct xmppParser *p, struct xmppStanza *st) {
  struct xmppXmlSlice attr;
  int r;
  st->type = XMPP_STANZA_ACKANSWER;
  while (xmppParseAttribute(p, &attr)) {
    if (!strcmp(p->x.attr, "h"))
      st->ack = SliceToI(attr);
  }
  xmppParseUnknown(p);
}

static void ParseCommonStanzaAttributes(struct xmppParser *p, struct xmppStanza *st) {
  struct xmppXmlSlice attr;
  while (xmppParseAttribute(p, &attr)) {
    if (!strcmp(p->x.attr, "id")) {
      memcpy(&st->id, &attr, sizeof(attr));
    } else if (!strcmp(p->x.attr, "from")) {
      memcpy(&st->from, &attr, sizeof(attr));
    } else if (!strcmp(p->x.attr, "to")) {
      memcpy(&st->to, &attr, sizeof(attr));
    }
  }
}

static void ParseOptionalRequired(struct xmppParser *p, struct xmppStream *s, int flag) {
  s->features |= flag;
  while (xmppParseElement(p)) {
    if (!strcmp(p->x.elem, "optional"))
      {} //s->optionalfeatures |= flag;
    else if (!strcmp(p->x.elem, "required"))
      s->requiredfeatures |= flag;
    else
      longjmp(p->jb, XMPP_ESPEC);
    xmppParseUnknown(p);
  }
}

// Read stream and features
// Features ALWAYS come after server stream according to spec
// If server too slow, user should read more.
void xmppParseStream(struct xmppParser *p, struct xmppStream *s) {
  struct xmppXmlSlice attr;
  if (!xmppParseElement(p) || strcmp(p->x.elem, "stream:features"))
    longjmp(p->jb, XMPP_ESPEC);
  while (xmppParseElement(p)) {
    if (!strcmp(p->x.elem, "starttls")) {
      s->features |= XMPP_STREAMFEATURE_STARTTLS;
      xmppParseUnknown(p);
    } else if (!strcmp(p->x.elem, "mechanisms")) {
      while (xmppParseElement(p)) {
        struct xmppXmlSlice mech;
        if (strcmp(p->x.elem, "mechanism"))
          longjmp(p->jb, XMPP_ESPEC);
        xmppParseContent(p, &mech);
        if (StrictStrEqual("SCRAM-SHA-1", mech.p, mech.rawn))
          s->features |= XMPP_STREAMFEATURE_SCRAMSHA1;
        else if (StrictStrEqual("SCRAM-SHA-1-PLUS", mech.p, mech.rawn))
          s->features |= XMPP_STREAMFEATURE_SCRAMSHA1PLUS;
        else if (StrictStrEqual("PLAIN", mech.p, mech.rawn))
          s->features |= XMPP_STREAMFEATURE_PLAIN;
      }
    } else if (!strcmp(p->x.elem, "sm")) {
      if (!xmppParseAttribute(p, &attr) || strcmp(p->x.attr, "xmlns"))
        longjmp(p->jb, XMPP_ESPEC);
      if (StrictStrEqual("urn:xmpp:sm:3", attr.p, attr.rawn))
        ParseOptionalRequired(p, s, XMPP_STREAMFEATURE_SMACKS);
      else
        xmppParseUnknown(p);
    } else if (!strcmp(p->x.elem, "bind")) {
      ParseOptionalRequired(p, s, XMPP_STREAMFEATURE_BIND);
    } else {
      while (xmppParseElement(p)) {
        if (!strcmp(p->x.elem, "required"))
          s->hasunknownrequired = true;
        xmppParseUnknown(p);
      }
    }
  }
}

// Parse stanza (or other XML element with depth of 1) out of XML stream
// into st. We only parse the bare minimal for this library. For unknown
// stanzas, st->raw will contain the slice of the stanza that has been
// split out of the stream so that you can parse it again looking for
// specific types of stanzas. We do not parse many XEP's here, that must
// be done externally. Partly for the reason that whenever there's a
// small mistake in the parsing code or wrongly handled input the whole
// stream will be unreadable (in the current implementation that is).
// TODO: possibly refactor instream
int xmppParseStanza(struct xmppParser *p, struct xmppStanza *st, bool instream) {
  int r;
  int i = p->i;
  struct xmppXmlSlice attr, cont;
  memset(st, 0, sizeof(*st));
  yxml_init(&p->x, p->xbuf, sizeof(p->xbuf));
  if (instream) {
    for (const char *pre = "<stream:stream>"; *pre; pre++)
      yxml_parse(&p->x, *pre);
  }
  if ((r = setjmp(p->jb))) {
    memset(st, 0, sizeof(*st));
    p->i = i;
    return r;
  }
  st->raw.p = p->p+p->i;
  if (!xmppParseElement(p)) {
    st->type = XMPP_STANZA_STREAMEND;
  } else if (!strcmp(p->x.elem, "stream:stream")) {
    st->type = XMPP_STANZA_STREAM;
    ParseCommonStanzaAttributes(p, st);
    xmppParseStream(p, &st->stream);
  } else if (!strcmp(p->x.elem, "stream:error")) {
    xmppParseUnknown(p);
    if (xmppParseElement(p))
      longjmp(p->jb, XMPP_ESPEC);
  } else if (!strcmp(p->x.elem, "a")) {
    ReadAckAnswer(p, st);
  } else if (!strcmp(p->x.elem, "r")) {
    st->type = XMPP_STANZA_ACKREQUEST;
    xmppParseUnknown(p);
  } else if (!strcmp(p->x.elem, "enabled")) {
    st->type = XMPP_STANZA_SMACKSENABLED;
    while (xmppParseAttribute(p, &attr)) {
      if (!strcmp(p->x.attr, "id")) {
        memcpy(&st->smacksenabled.id, &attr, sizeof(attr));
      } else if (!strcmp(p->x.attr, "resume")) {
        st->smacksenabled.resume = StrictStrEqual("true", attr.p, attr.rawn) ||
                                   StrictStrEqual("1", attr.p, attr.rawn);
      }
    }
    xmppParseUnknown(p);
  } else if (!strcmp(p->x.elem, "proceed")) {
    st->type = XMPP_STANZA_STARTTLSPROCEED;
    xmppParseUnknown(p);
  } else if (!strcmp(p->x.elem, "failure")) { // TODO: happens for both SASL and TLS
    st->type = XMPP_STANZA_FAILURE;
    xmppParseUnknown(p);
  } else if (!strcmp(p->x.elem, "success")) {
    st->type = XMPP_STANZA_SASLSUCCESS;
    xmppParseContent(p, &st->saslsuccess);
  } else if (!strcmp(p->x.elem, "challenge")) {
    st->type = XMPP_STANZA_SASLCHALLENGE;
    xmppParseContent(p, &st->saslchallenge);
  } else if (!strcmp(p->x.elem, "iq")) {
    st->type = XMPP_STANZA_IQ;
    ParseCommonStanzaAttributes(p, st);
    while (xmppParseElement(p)) {
      if (!strcmp(p->x.elem, "bind")) {
        if (!xmppParseElement(p) || strcmp(p->x.elem, "jid"))
          longjmp(p->jb, XMPP_ESPEC);
        xmppParseContent(p, &st->bindjid);
        st->type = XMPP_STANZA_BINDJID;
        xmppParseUnknown(p);
      } else if (!strcmp(p->x.elem, "error")) {
        st->type = XMPP_STANZA_ERROR;
        xmppParseUnknown(p);
        while (xmppParseElement(p)) {}
        break;
      } else {
        xmppParseUnknown(p);
      }
    }
  } else if (!strcmp(p->x.elem, "message")) {
    st->type = XMPP_STANZA_MESSAGE;
    ParseCommonStanzaAttributes(p, st);
    while (xmppParseElement(p)) {
      if (!strcmp(p->x.elem, "body"))
        xmppParseContent(p, &st->message.body);
      else
        xmppParseUnknown(p);
    }
  } else if (!strcmp(p->x.elem, "presence")) {
    st->type = XMPP_STANZA_PRESENCE;
    ParseCommonStanzaAttributes(p, st);
    xmppParseUnknown(p);
  } else {
    xmppParseUnknown(p);
  }
  st->raw.rawn = st->raw.n = p->i - i;
  return 0;
}

static char *SafeStpCpy(char *d, char *e, const char *s) {
  while (*s && d < e)
    *d++ = *s++;
  return d;
}

static char *SafeMempCpy(char *d, char *e, char *s, size_t n) {
  if (d + n > e)
    return e;
  memcpy(d, s, n);
  return d + n;
}

// n = number of random bytes
// e - p >= n*2
// doesn't add nul byte
// TODO: use mbedtls random for compat? esp-idf does support getrandom...
static char *FillRandomHex(char *p, char *e, size_t n) {
  size_t nn = n*2;
  if (e - p < nn)
    return e;
  if (getrandom(p, n, 0) != n)
    return e;
  for (int i = nn-1; i >= 0; i--) {
    int nibble = (p[i/2] >> (!(i&1)*4)) & 0xf;
    p[i] = "0123456789ABCDEF"[nibble];
  }
  return p + nn;
}

// Assume the username has been SASLprep'ed.
static char *SanitizeSaslUsername(char *d, char *e, const char *s) {
  for (;*s && d < e;s++) {
    switch (*s) {
    case '=':
      d = SafeStpCpy(d, e, "=3D");
      break;
    case ',':
      d = SafeStpCpy(d, e, "=2C");
      break;
    default:
      *d++ = *s;
      break;
    }
  }
  return d;
}

// ret
//  = 0: success
//  < 0: XMPP_EMEM
int xmppInitSaslContext(struct xmppSaslContext *ctx, char *p, size_t n, const char *user) {
  char *e = p + n;
  memset(ctx, 0, sizeof(*ctx));
  ctx->p = p;
  ctx->n = n;
  p = SafeStpCpy(p, e, "n,,n=");
  ctx->initialmsg = 3;
  p = SanitizeSaslUsername(p, e, user);
  p = SafeStpCpy(p, e, ",r=");
  p = FillRandomHex(p, e, 32);
  p = SafeStpCpy(p, e, ",");
  ctx->serverfirstmsg = p - ctx->p;
  if (HasOverflowed(p, e))
    return XMPP_EMEM;
  ctx->state = XMPP_SASL_INITIALIZED;
  return 0;
}

static int MakeSaslPlain(struct xmppSaslContext *ctx, char *p, size_t n, const char *user, const char *pwd) {
  char *e = p + n;
  memset(ctx, 0, sizeof(*ctx));
  ctx->p = p;
  ctx->n = n;
  p = SafeMempCpy(p, e, "\0", 1);
  p = SafeStpCpy(p, e, user);
  p = SafeMempCpy(p, e, "\0", 1);
  p = SafeStpCpy(p, e, pwd);
  ctx->end = p - ctx->p;
  if (HasOverflowed(p, e))
    return XMPP_EMEM;
  return 0;
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
// - %d: integer
// - %x: xmppXmlSlice to encoded XML
int FormatXml(struct xmppXmlComposer *c, const char *fmt, ...) {
  va_list ap;
  struct xmppXmlSlice slc;
  size_t n;
  bool skip = false;
  int i;
  const char *s;
  char *d = c->p + c->n, *e = c->p + c->c;
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
      break; case 's':
        s = va_arg(ap, const char*);
        if (!skip)
          d = EncodeXmlString(d, e, s);
      break; case 'b':
        n = va_arg(ap, size_t);
        s = va_arg(ap, const char*);
        if (!skip)
          d = EncodeBase64(d, e, s, n);
      break; case 'x': // TODO: we just assume the slc.type is the same for in and output
        slc = va_arg(ap, struct xmppXmlSlice);
        if (!skip && d+slc.rawn < e) {
          memcpy(d, slc.p, slc.rawn);
          d += slc.rawn;
        }
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
  if (HasOverflowed(d, e)) {
    c->n = c->i;
    return XMPP_EMEM;
  }
  c->n = d - c->p;
  return 0;
}

#define FormatSaslPlain(c, ctx)                                        \
  FormatXml(c,                                                         \
            "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' "          \
            "mechanism='PLAIN'>%b</auth>",                             \
            (ctx)->end, (ctx)->p)

#define xmppFormatStream(c, to) FormatXml(c, \
    "<?xml version='1.0'?>" \
    "<stream:stream xmlns='jabber:client'" \
    " version='1.0' xmlns:stream='http://etherx.jabber.org/streams'" \
    " to='%s'>", to)

// For static XML we can directly call SafeStpCpy
#define xmppFormatStartTls(c) FormatXml(c, "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")

#define xmppFormatSaslInitialMessage(c, ctx) \
  FormatXml(c, "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='SCRAM-SHA-1'>%b</auth>", (ctx)->serverfirstmsg-1, (ctx)->p)

#define xmppFormatSaslResponse(c, ctx) FormatXml(c, "<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>%b</response>", (ctx)->end-(ctx)->clientfinalmsg, (ctx)->p+(ctx)->clientfinalmsg)

// TODO: use a single buf? mbedtls decode base64 probably allows overlap
// length of s not checked, it's expected that invalid input would
// end with either an unsupported base64 charactor or nul.
// s = success base64 content
int xmppVerifySaslSuccess(struct xmppSaslContext *ctx, struct xmppXmlSlice s) {
  assert(ctx->state == XMPP_SASL_CALCULATED);
  char b1[30], b2[20];
  size_t n;
  if (mbedtls_base64_decode(b1, 30, &n, s.p, s.rawn)
   || mbedtls_base64_decode(b2, 20, &n, b1+2, 28))
    return XMPP_ESPEC;
  return !!memcmp(ctx->srvsig, b2, 20);
}

static int H(char k[static 20], const char *pwd, size_t plen, const char *salt, size_t slen, int itrs) {
  int r = mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA1, pwd, plen, salt, slen, itrs, 20, k);
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

static int Sha1(char d[static 20], const char p[static 20]) {
  int r = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), p, 20, d);
  if (r != 0) {
    LogWarn("MbedTLS SHA1 error: %s", mbedtls_high_level_strerr(r));
    return 0;
  }
  return 1;
}

static void XorSha1(char d[20], const char a[20], const char b[20]) {
  for (int i = 0; i < 20; i++)
    d[i] = a[i] ^ b[i];
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
static int CalculateScramSha1(struct xmppSaslContext *ctx, char clientproof[static 20], const char *pwd, size_t plen, const char *salt, size_t slen, int itrs) {
  char saltedpwd[20], clientkey[20],
  storedkey[20], clientsig[20],
  serverkey[20];
  return H(saltedpwd, pwd, plen, salt, slen, itrs)
    && HMAC(clientkey, "Client Key", 10, saltedpwd)
    && Sha1(storedkey, clientkey)
    && HMAC(clientsig, ctx->p+ctx->initialmsg, ctx->authmsgend-ctx->initialmsg, storedkey)
    && (XorSha1(clientproof, clientkey, clientsig), 1)
    && HMAC(serverkey, "Server Key", 10, saltedpwd)
    && HMAC(ctx->srvsig, ctx->p+ctx->initialmsg, ctx->authmsgend-ctx->initialmsg, serverkey);
}

// We have to make sure this function can be called multiple times,
// either because the format function called after this one might fail
// OR the password is wrong.
// TODO: error handling
// expects xmppInitSaslContext to be successfully called with the same ctx
// c = challenge base64
// make sure pwd is all printable chars
// return something if ctx->n is too small
// return something else if corrupt data
int xmppSolveSaslChallenge(struct xmppSaslContext *ctx, struct xmppXmlSlice c, const char *pwd) {
  assert(ctx->state >= XMPP_SASL_INITIALIZED);
  size_t n;
  int itrs = 0;
  char *s, *i, *e = ctx->p+ctx->n - 1; // keep the nul
  char *r = ctx->p+ctx->serverfirstmsg;
  if (mbedtls_base64_decode(r, e-r, &n, c.p, c.rawn))
    return XMPP_ESPEC;
  size_t servernonce = ctx->serverfirstmsg + 2;
  if (strncmp(r, "r=", 2)
   || !(s = strstr(r+2, ",s="))
   || !(i = strstr(s+3, ",i=")))
    return XMPP_ESPEC;
  size_t saltb64 = s-ctx->p + 3;
  itrs = atoi(i+3);
  if (itrs == 0 || itrs > XMPP_CONFIG_MAX_SASLSCRAM1_ITERS)
    return XMPP_ESPEC;
  r += n;
  ctx->clientfinalmsg = r - ctx->p + 1;
  r = SafeStpCpy(r, e, ",c=biws,r=");
  size_t nb = saltb64 - servernonce - 3;
  memcpy(r, ctx->p+servernonce, nb);
  r += nb;
  ctx->authmsgend = r - ctx->p;
  mbedtls_base64_decode(r, 9001, &n, s+3, i-s-3); // IDK random value
  char clientproof[20];
  if (!CalculateScramSha1(ctx, clientproof, pwd, strlen(pwd), r, n, itrs))
    return XMPP_ECRYPTO;
  r = stpcpy(r, ",p=");
  mbedtls_base64_encode(r, 9001, &n, clientproof, 20); // IDK random value
  ctx->end = (r-ctx->p)+n;
  if (HasOverflowed(r, e))
    return XMPP_EMEM;
  ctx->state = XMPP_SASL_CALCULATED;
  return 0;
}

// After one or multiple stanzas have been read, the [i]ndex field will
// be pointing to either the next stanza or empty space. This function
// moves both the next stanza and the [i]ndex to the beginning of the
// buffer, overwriting all previous data.
static void MoveStanza(struct xmppParser *p) {
  if (p->i) {
    p->n = p->n - p->i;
    memmove(p->p, p->p + p->i, p->n);
    p->i = 0;
  }
}

#define xmppFormatIq(c, type, from, to, id, fmt, ...) FormatXml(c, "<iq" \
    " type='" type "'" \
    " from='%s'" \
    " to='%s'" \
    " id='%s'>" fmt "</iq>", \
    from, to, id \
    __VA_OPT__(,) __VA_ARGS__)

// TODO: better way to do this?
// res: string or NULL if you want the server to generate it
#define xmppFormatBindResource(c, res) \
  FormatXml(c, \
      "<iq id='bind' type='set'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'[/>][><resource>%s</resource></bind>]</iq>", \
      !res, !!res, res)

// XEP-0199: XMPP Ping

#define xmppFormatPing(c, to, id)                                      \
  FormatXml(c,                                                         \
            "<iq to='%s' id='ping%d' type='get'><ping "                \
            "xmlns='urn:xmpp:ping'/></iq>",                            \
            to, id)


// XEP-0030: Service Discovery

#define xmppFormatDisco(c, from, to, id) xmppFormatIq(c, "get", from, to, id, "<query xmlns='http://jabber.org/protocol/disco#info'/>")

// XEP-0198: Stream Management

#define xmppFormatAckEnable(c, resume) FormatXml(c, "<enable xmlns='urn:xmpp:sm:3'[ resume='true']/>", resume)
#define xmppFormatAckResume(c, h, previd) FormatXml(c, "<resume xmlns='urn:xmpp:sm:3' h='%d' previd='%s'/>", h, previd)
#define xmppFormatAckRequest(c) FormatXml(c, "<r xmlns='urn:xmpp:sm:3'/>")
#define xmppFormatAckAnswer(c, h) FormatXml(c, "<a xmlns='urn:xmpp:sm:3' h='%d'/>", h)

#define xmppFormatMessage(c, to, id, body) FormatXml(c, "<message to='%s' id='message%d'><body>%s</body></message>", to, id, body)

/*static void SendDisco(struct xmppClient *c) {
  int disco = c->lastdisco + 1;
  FormatXml(c->out+c->outn, c->out+sizeof(c->out), "<iq type='get' to='%s' id='disco%d'><query xmlns='http://jabber.org/protocol/disco#info'/></iq>", "localhost", disco);
  c->lastdisco = disco;
  c->actualsent++;
}*/

enum {
  CLIENTSTATE_UNINIT = 0,
  CLIENTSTATE_INIT,
  CLIENTSTATE_STREAMSENT,
  CLIENTSTATE_STARTTLS,
  CLIENTSTATE_SASLINIT,
  CLIENTSTATE_SASLPWD,
  CLIENTSTATE_SASLCHECKRESULT,
  CLIENTSTATE_SASLPLAIN,
  CLIENTSTATE_SASLRESULT,
  CLIENTSTATE_BIND,
  CLIENTSTATE_ACCEPTSTANZA,
  CLIENTSTATE_RESUME,
  CLIENTSTATE_ENDSTREAM,
};

static int SendStanzaTrail(struct xmppClient *c) {
  int r;
  if (c->features & XMPP_STREAMFEATURE_SMACKS &&
      (r = xmppFormatAckRequest(&c->builder)))
    return r;
  return XMPP_ITER_SEND;
}

int xmppSendMessage(struct xmppClient *c, const char *to,
                       const char *body) {
  int r;
  if ((r = xmppFormatMessage(&c->builder, to, 1, body)) ||
      (r = SendStanzaTrail(c)))
    return r;
  c->actualsent++;
  return 0;
}

static int SendPing(struct xmppClient *c, const char *to) {
  int r;
  int ping = c->lastping + 1;
  if ((r = xmppFormatPing(&c->builder, to, ping)) ||
      (r = SendStanzaTrail(c)))
    return r;
  c->lastping = ping;
  c->actualsent++;
  return 0;
}

int xmppSupplyPassword(struct xmppClient *c, const char *pwd) {
  int r;
  if (c->state == CLIENTSTATE_SASLPWD) {
    xmppSolveSaslChallenge(&c->saslctx, c->stanza.saslchallenge, pwd);
    if ((r = xmppFormatSaslResponse(&c->builder, &c->saslctx)))
      return r;
    c->state = CLIENTSTATE_SASLCHECKRESULT;
  } else if (c->state == CLIENTSTATE_SASLPLAIN) {
    MakeSaslPlain(&c->saslctx, c->saslbuf, sizeof(c->saslbuf), c->jid.local, pwd);
    if ((r = FormatSaslPlain(&c->builder, &c->saslctx)))
      return r;
    c->state = CLIENTSTATE_SASLRESULT;
  } else {
    return XMPP_ESTATE;
  }
  return 0;
}

static bool xmppResume(struct xmppClient *c) {
  if (!c->cansmackresume)
    return false;
  c->state = CLIENTSTATE_INIT;
  c->features &= ~(XMPP_STREAMFEATURE_STARTTLS | XMPP_STREAMFEATUREMASK_SASL);
  c->builder.n = 0;
  return true;
}

// finds the first occurance of c in s and returns the position after
// the occurance or 0 if not found.
static size_t FindNext(const char *s, char c) {
  const char *f;
  return (f = strchr(s, c)) ? f - s + 1 : 0;
}

void xmppInitClient(struct xmppClient *c, const char *jid, int opts) {
  memset(c, 0, sizeof(*c));
  c->opts = opts;
  c->state = CLIENTSTATE_INIT;
  c->parser.p = c->in;
  c->parser.c = sizeof(c->in);
  c->builder.p = c->out;
  c->builder.c = sizeof(c->out);
  size_t d = FindNext(jid, '@'), r = FindNext(jid, '/'), n = strlen(jid);
  memcpy(c->jid.local, jid, (c->jid.localn = d-1));
  memcpy(c->jid.domain, jid+d, (c->jid.domainn = r-d-1));
  memcpy(c->jid.resource, jid+r, (c->jid.resourcen = n-r));
}

// Called when error returned from Format* so that the error can be
// resolved and the stanza/stream can be reused. We can either choose to
// make a reuse flag so that the reading won't be done again OR we can
// set back the parser pointer so that the reading will be done again,
// this might be easier but requires we re-initialize the yxml context
// for every new stanza.
static int ReturnRetry(struct xmppClient *c, int r) {
  c->parser.i = 0;
  return r;
}

// When the server sends some error or failure (on the stream level), we
// want to let that know via either the Iterate return value or the
// stanza->type so the caller to Iterate can handle as appropriate, if
// there's no resolution done we want to gracefully exit by sending our
// stream ending.
// TODO: should we bzero anywhere?
int xmppEndStream(struct xmppClient *c) {
  if (!xmppIsInitialized(c))
    return 0;
  c->state = CLIENTSTATE_UNINIT;
  FormatXml(&c->builder, "</stream:stream>"); // We don't really care about the return here, if we can't sent it well *who cares* :).
  return XMPP_ITER_SEND;
}

static int ReturnStreamError(struct xmppClient *c, int r) {
  c->state = CLIENTSTATE_ENDSTREAM;
  return r;
}

// Mostly copied from xmppParseUnknown
static int SkipLargeStanza(struct xmppParser *p) {
  while (p->i < p->n) {
    yxml_ret_t r = yxml_parse(&p->x, p->p[p->i++]);
    switch (r) {
    case YXML_ELEMSTART:
      p->skippingdepth++;
      break;
    case YXML_ELEMEND:
      if (--p->skippingdepth == 1)
        return 0;
      break;
    default:
      if (r < 0)
        return XMPP_EXML;
    }
  }
  p->i = 0;
  p->n = 0;
  return XMPP_EPARTIAL;
}

static void SetupSkipping(struct xmppParser *p) {
  p->skippingdepth = 1;
  yxml_init(&p->x, p->xbuf, sizeof(p->xbuf));
}

// When SEND is returned, the complete out buffer (c->builder.p) with the
// size specified in (c->builder.n) must be sent over the network before
// another iteration is done. If c->builder.n is 0, you don't have to write
// anything. It is recommended that your send function does not block so
// that you can call Iterate again asap. You may only reallocate the in
// buffer just before or after reading from the network.
// When the provided SASL password is incorrect, the stream will be
// closed and if you want to retry you must create a new stream. We
// could reuse the same stream, but then we either have to keep track of
// the amount of attempts and other stuff because some servers will let
// us retry indefinitely and might cause an infinite loop.
// ret:
//  >= 0: XMPP_ITER_*
//   < 0: XMPP_E*
int xmppIterate(struct xmppClient *c) {
  struct xmppStanza *st = &c->stanza;
  int r = 0;
  // always return SEND if the out buffer is not returned, do not
  // try caching to avoid prematurely filling up the entire buffer. Let
  // the OS/network stack handle caching.
  if (c->state == CLIENTSTATE_UNINIT)
    return 0;
  if (c->builder.n > 0)
    return XMPP_ITER_SEND;
  if (c->parser.n && c->parser.skippingdepth) {
    if ((r = SkipLargeStanza(&c->parser)) == XMPP_EPARTIAL)
      return XMPP_ITER_RECV;
    else if (r)
      return r;
    return XMPP_ESKIP;
  }
  if (c->state == CLIENTSTATE_INIT) {
    if ((r = xmppFormatStream(&c->builder, c->jid.domain)))
      return ReturnRetry(c, r);
    c->state = CLIENTSTATE_STREAMSENT;
    return XMPP_ITER_SEND;
  }
  if (c->state == CLIENTSTATE_ENDSTREAM) {
    return xmppEndStream(c);
  }
  MoveStanza(&c->parser);
  if (c->parser.n) Log("Parsing (pos %d): \e[33m%.*s\e[0m", (int)c->parser.i, (int)(c->parser.n-c->parser.i), c->parser.p+c->parser.i);
  // TODO: if previous stanza handled only then read.
  if (!c->parser.n || (r = xmppParseStanza(&c->parser, st, c->state != CLIENTSTATE_STREAMSENT)) == XMPP_EPARTIAL) {
    if (c->parser.n == c->parser.c) {
      SetupSkipping(&c->parser);
      return XMPP_ITER_OK;
    }
    return c->isnegotiationdone ? XMPP_ITER_READY : XMPP_ITER_RECV;
  }
  if (r)
    return r;
  if (c->state == CLIENTSTATE_STREAMSENT) {
    if (st->type != XMPP_STANZA_STREAM)
      return XMPP_ESPEC;
    struct xmppStream stream;
    memcpy(&stream, &st->stream, sizeof(struct xmppStream));
    if (!(c->features & XMPP_STREAMFEATURE_STARTTLS) && !(c->opts & XMPP_OPT_FORCEUNENCRYPTED)) {
      if (stream.features & XMPP_STREAMFEATURE_STARTTLS) {
        if ((r = xmppFormatStartTls(&c->builder)))
          return ReturnRetry(c, r);
        c->state = CLIENTSTATE_STARTTLS;
        return XMPP_ITER_SEND;
      } else if (!(c->opts & XMPP_OPT_ALLOWUNENCRYPTED)) {
        return XMPP_ENEGOTIATE;
      }
    }
    if (!(c->opts & XMPP_OPT_NOAUTH) && !(c->features & XMPP_STREAMFEATUREMASK_SASL)) {
      // TODO: -PLUS
      if (stream.features & XMPP_STREAMFEATURE_SCRAMSHA1 && !(c->opts & XMPP_OPT_FORCEPLAIN)) {
        xmppInitSaslContext(&c->saslctx, c->saslbuf, sizeof(c->saslbuf), c->jid.local);
        if ((r = xmppFormatSaslInitialMessage(&c->builder, &c->saslctx)))
          return ReturnRetry(c, r);
        c->state = CLIENTSTATE_SASLINIT;
        return XMPP_ITER_SEND;
      } else if (stream.features & XMPP_STREAMFEATURE_PLAIN &&
               !(c->opts & XMPP_OPT_FORCESCRAM) &&
               (c->features & XMPP_STREAMFEATURE_STARTTLS ||
                c->opts & XMPP_OPT_ALLOWUNENCRYPTEDPLAIN)) {
        c->state = CLIENTSTATE_SASLPLAIN;
        return XMPP_ITER_GIVEPWD;
      }
      return XMPP_ENEGOTIATE;
    }
    if (!(stream.features & XMPP_STREAMFEATURE_SMACKS)) {
      c->opts |= XMPP_OPT_DISABLESMACKS;
    } else if (c->smackidn) {
      if ((r = xmppFormatAckResume(&c->builder, c->actualrecv, c->smackid)))
        return ReturnRetry(c, r);
      c->state = CLIENTSTATE_RESUME;
      return XMPP_ITER_SEND;
    }
    assert(stream.features & XMPP_STREAMFEATURE_BIND);
    if ((r = xmppFormatBindResource(&c->builder,  c->jid.resource)))
      return ReturnRetry(c, r);
    c->state = CLIENTSTATE_BIND;
    return XMPP_ITER_SEND;
  }
  if (!c->isnegotiationdone) { // TODO: remove isnegotiationdone and just use state?
    switch (c->state) {
    case CLIENTSTATE_STARTTLS:
      if (st->type == XMPP_STANZA_STARTTLSPROCEED) {
        c->features |= XMPP_STREAMFEATURE_STARTTLS;
        c->state = CLIENTSTATE_INIT;
        return XMPP_ITER_STARTTLS;
      }
      break;
    case CLIENTSTATE_SASLINIT:
      assert(st->type == XMPP_STANZA_SASLCHALLENGE);
      c->state = CLIENTSTATE_SASLPWD;
      return XMPP_ITER_GIVEPWD;
    case CLIENTSTATE_SASLCHECKRESULT:
      if (st->type == XMPP_STANZA_FAILURE)
        return ReturnStreamError(c, XMPP_EPASS);
      if (st->type != XMPP_STANZA_SASLSUCCESS)
        return ReturnStreamError(c, XMPP_ESPEC);
      assert(xmppVerifySaslSuccess(&c->saslctx, st->saslsuccess) == 0);
      memset(c->saslctx.p, 0, c->saslctx.n);
      memset(&c->saslctx, 0, sizeof(c->saslctx));
      c->features |= XMPP_STREAMFEATURE_SCRAMSHA1;
      c->state = CLIENTSTATE_INIT;
      return XMPP_ITER_OK;
    case CLIENTSTATE_SASLRESULT:
      if (st->type == XMPP_STANZA_FAILURE)
        return ReturnStreamError(c, XMPP_EPASS);
      assert(st->type == XMPP_STANZA_SASLSUCCESS);
      memset(c->saslctx.p, 0, c->saslctx.n);
      memset(&c->saslctx, 0, sizeof(c->saslctx));
      c->features |= XMPP_STREAMFEATURE_PLAIN;
      c->state = CLIENTSTATE_INIT;
      return XMPP_ITER_OK;
    case CLIENTSTATE_BIND:
      // TODO: smacks is not really part of negotiation, I think. So we must
      // take in account there might be messages sent to us before the stream
      // is enabled.
      if (st->type != XMPP_STANZA_BINDJID)
        return XMPP_ESPEC;
      // TODO: st->bindjid is might contain XML entities, have some special
      // function for checking this.
      if (memcmp(c->jid.local, st->bindjid.p, c->jid.localn) ||
          memcmp(c->jid.domain, st->bindjid.p + c->jid.localn + 1,
                 c->jid.domainn) ||
          memcmp(c->jid.resource,
                 st->bindjid.p + c->jid.localn + 1 + c->jid.domainn + 1,
                 c->jid.resourcen))
        return XMPP_EBIND;
      // TODO: check if returned bind address is either empty or the same as
      // c->jid, maybe put the new resource into c->jid.resource
      if (!(c->opts & XMPP_OPT_DISABLESMACKS)) {
        if ((r = xmppFormatAckEnable(&c->builder, true)))
          return ReturnRetry(c, r);
        c->features |= XMPP_STREAMFEATURE_SMACKS;
        c->state = CLIENTSTATE_ACCEPTSTANZA;
        c->isnegotiationdone = true;
        c->features |= XMPP_STREAMFEATURE_SMACKS; // TODO
        return XMPP_ITER_SEND;
      }
      c->state = CLIENTSTATE_ACCEPTSTANZA;
      c->isnegotiationdone = true;
      return XMPP_ITER_OK;
    case CLIENTSTATE_RESUME:
      assert(st->type == XMPP_STANZA_RESUMED);
      c->isnegotiationdone = true;
      return XMPP_ITER_OK;
    }
    return XMPP_ESTATE;
  }
  if (c->features & XMPP_STREAMFEATURE_SMACKS &&
      (st->type == XMPP_STANZA_PING || st->type == XMPP_STANZA_IQ ||
       st->type == XMPP_STANZA_MESSAGE ||
       st->type == XMPP_STANZA_PRESENCE))
      c->actualrecv++;
  switch (st->type) {
  case XMPP_STANZA_PING:
    if (!(c->opts & XMPP_OPT_HIDEPRESENCE))
      xmppFormatStanza(c, "<iq to='%x' id='%x' type='result'/>", st->from, st->id);
    else
      xmppFormatStanza(
          c,
          "<iq to='%x' id='%x' type='error'><ping "
          "xmlns='urn:xmpp:ping'/><error type='cancel'><service-unavailable "
          "xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error></iq>",
          st->from, st->id);
    return XMPP_ITER_OK;
  case XMPP_STANZA_SMACKSENABLED:
    c->features |= XMPP_STREAMFEATURE_SMACKS;
    if (st->smacksenabled.id.p) {
      assert(st->smacksenabled.id.rawn < sizeof(c->smackid));
      memcpy(c->smackid, st->smacksenabled.id.p, st->smacksenabled.id.rawn);
      if (!(c->opts & XMPP_OPT_DISABLESMACKS))
        c->cansmackresume = st->smacksenabled.resume;
    }
    return XMPP_ITER_OK;
  case XMPP_STANZA_ACKANSWER:
    return XMPP_ITER_ACK;
  case XMPP_STANZA_ACKREQUEST:
    if ((r = xmppFormatAckAnswer(&c->builder, c->actualrecv)))
      return r;
    return XMPP_ITER_SEND;
  default:
    return XMPP_ITER_STANZA;
  }
  return XMPP_ITER_OK;
}
