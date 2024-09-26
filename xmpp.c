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

static char *EncodeBase64(char *d, char *e, const char *s, size_t n) {
  if (mbedtls_base64_encode((unsigned char *)d, e-d, &n, (const unsigned char *)s, n))
    return e;
  return d+n;
}

/**
 * Returns target
 */
static int InitXmlSliceParser(yxml_t *x, const struct xmppXmlSlice *slc) {
  char prev = slc->p[0];
  // For content, prev will be '>', for attribute either ' or "
  //printf("XML %.*s\n", slc->rawn, slc->p);
  assert(prev == '>' || prev == '\'' || prev == '"');
  // TODO: we can skip the whole prefix initialization since that is
  // static. just memcpy the internal state to the struct.
  static const char attrprefix[] = "<x e=";
  static const char contprefix[] = "<x";
  const char *prefix = prev == '>' ? contprefix : attrprefix;
  while (*prefix) {
    yxml_parse(x, *prefix++);
  }
  return prev == '>' ? YXML_CONTENT : YXML_ATTRVAL;
}

bool xmppCompareXmlSlice(const char *s, const struct xmppXmlSlice *slc) {
  if (!slc->p || !s)
    return false;
  char buf[16];
  yxml_t x;
  yxml_init(&x, buf, sizeof(buf));
  int target = InitXmlSliceParser(&x, slc);
  int n = slc->rawn;
  for (int i = 0; i < n; i++) {
    // with parsing input validation has already succeeded so there is
    // no reason to check for errors again.
    if (yxml_parse(&x, slc->p[i]) == target) {
      const char *p = x.data;
      while (*p) {
        if (*p++ != *s++)
          return false;
      }
    }
  }
  return *s == '\0';
}

void xmppReadXmlSlice(char *d, const struct xmppXmlSlice *slc) {
  if (!slc->p)
    return;
  char buf[16];
  yxml_t x;
  yxml_init(&x, buf, sizeof(buf));
  int target = InitXmlSliceParser(&x, slc);
  int n = slc->rawn;
  for (int i = 0; i < n; i++) {
    // with parsing input validation has already succeeded so there is
    // no reason to check for errors again.
    if (yxml_parse(&x, slc->p[i]) == target)
      d = stpcpy(d, x.data);
  }
}

int xmppDecodeBase64XmlSlice(char *d, size_t *n, const struct xmppXmlSlice *slc) {
  assert(d && n && slc && slc->p);
  // TODO: don't hardcode +1, -2
  int r = mbedtls_base64_decode(d, *n, n, slc->p+1, slc->rawn-2);
  if (r == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL)
    return XMPP_EMEM;
  if (r == MBEDTLS_ERR_BASE64_INVALID_CHARACTER)
    return XMPP_ESPEC;
  assert(r == 0);
  return 0;
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

#define HasOverflowed(p, e) ((p) >= (e))

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

bool xmppParseAttribute(struct xmppParser *p, struct xmppXmlSlice *slc) {
  int r;
  memset(slc, 0, sizeof(*slc));
  while (1) { // hacky way to check end of attr list
    if (!slc->p && (p->p[p->i-1] == '>' || p->p[p->i-1] == '/'))
      return false;
    if (!(p->i < p->n))
      break;
    switch ((r = yxml_parse(&p->x, p->p[p->i++]))) {
    case YXML_ATTRSTART:
      // TODO: does this trigger at the right time?
      slc->p = p->p + p->i;
      break;
    case YXML_ATTREND:
      return true;
    case YXML_ATTRVAL:
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

void xmppParseContent(struct xmppParser *p, struct xmppXmlSlice *slc) {
  int r;
  bool incontent = false;
  struct xmppXmlSlice attr;
  memset(slc, 0, sizeof(*slc));
  while (xmppParseAttribute(p, &attr)) {}
  while (p->i < p->n) {
    if (!slc->p) {
      if (p->p[p->i - 1] == '>')
        incontent = true, slc->rawn = 1, slc->p = p->p + p->i - 1;
    }
    if (incontent)
      slc->rawn++;
    if (p->p[p->i] == '<')
      incontent = false;
    switch ((r = yxml_parse(&p->x, p->p[p->i++]))) {
    case YXML_ELEMEND:
      return;
    case YXML_CONTENT:
      if (!slc->p)
        longjmp(p->jb, XMPP_EXML);
      slc->n += strlen(p->x.data);
      break;
    default:
      if (r < 0)
        longjmp(p->jb, XMPP_EXML);
    }
  }
  longjmp(p->jb, XMPP_EPARTIAL);
}

bool xmppParseElement(struct xmppParser *p) {
  int r;
  while (p->i < p->n) {
    switch ((r = yxml_parse(&p->x, p->p[p->i++]))) {
    case YXML_OK:
      break;
    case YXML_ELEMSTART:
      return true; //return FindElement(s->x.elem, yxml_symlen(s->x.elem), opt);
    case YXML_ELEMEND:
      return false;
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
static void xmppParseStream(struct xmppParser *p, struct xmppStream *s) {
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
        if (xmppCompareXmlSlice("SCRAM-SHA-1", &mech))
          s->features |= XMPP_STREAMFEATURE_SCRAMSHA1;
        else if (xmppCompareXmlSlice("SCRAM-SHA-1-PLUS", &mech))
          s->features |= XMPP_STREAMFEATURE_SCRAMSHA1PLUS;
        else if (xmppCompareXmlSlice("PLAIN", &mech))
          s->features |= XMPP_STREAMFEATURE_PLAIN;
      }
    } else if (!strcmp(p->x.elem, "sm")) {
      if (!xmppParseAttribute(p, &attr) || strcmp(p->x.attr, "xmlns"))
        longjmp(p->jb, XMPP_ESPEC);
      if (xmppCompareXmlSlice("urn:xmpp:sm:3", &attr))
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
static int xmppParseStanza(struct xmppParser *p, struct xmppStanza *st, bool instream) {
  int r;
  int i = p->i;
  struct xmppXmlSlice attr, cont;
  memset(st, 0, sizeof(*st));
  yxml_init(&p->x, p->xbuf, p->xbufn);
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
        st->smacksenabled.resume = xmppCompareXmlSlice("true", &attr) ||
                                   xmppCompareXmlSlice("1", &attr);
      }
    }
    xmppParseUnknown(p);
  } else if (!strcmp(p->x.elem, "proceed")) {
    st->type = XMPP_STANZA_STARTTLSPROCEED;
    xmppParseUnknown(p);
  } else if (!strcmp(p->x.elem, "failure")) {
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
    xmppParseUnknown(p);
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

#define XMPP_SASL_INITIALIZED 1
#define XMPP_SASL_CALCULATED 2

// ret
//  = 0: success
//  < 0: XMPP_EMEM
static int InitSaslContext(struct xmppSaslContext *ctx, const char *user) {
  assert(ctx->p && ctx->n);
  char *p = ctx->p;
  size_t n = ctx->n;
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

static int MakeSaslPlain(struct xmppSaslContext *ctx, const char *user, const char *pwd) {
  assert(ctx->p && ctx->n);
  char *p = ctx->p;
  size_t n = ctx->n;
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

/**
 * Escape XML string into buffer.
 *
 * If s is nul-terminated, n should be INT_MAX.
 *
 * @param d destination buffer
 * @param e end of destination buffer
 * @param s source buffer containing unescaped XML
 * @param n maximum number of bytes in source buffer to escape
 */
static char *EncodeXmlString(char *d, char *e, const char *s, int n) {
  for (int i = 0; i < n && s[i] && d < e; i++) {
    switch (s[i]) {
    break; case '"': d = SafeStpCpy(d, e, "&quot;");
    break; case '\'': d = SafeStpCpy(d, e, "&apos;");
    break; case '&': d = SafeStpCpy(d, e, "&amp;");
    break; case '<': d = SafeStpCpy(d, e, "&lt;");
    break; case '>': d = SafeStpCpy(d, e, "&gt;");
    break; default:
      *d++ = s[i];
      break;
    }
  }
  return d;
}

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

void xmppAppendXml(struct xmppBuilder *c, const char *fmt, ...) {
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
          d = EncodeXmlString(d, e, s, INT_MAX);
      break; case 'b':
        n = va_arg(ap, int);
        s = va_arg(ap, const char*);
        if (!skip)
          d = EncodeBase64(d, e, s, n);
      break; case 'n':
        n = va_arg(ap, int);
        s = va_arg(ap, const char*);
        if (!skip)
          d = EncodeXmlString(d, e, s, n);
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
  c->n = d - c->p;
}

void xmppStartStanza(struct xmppBuilder *builder) {
  builder->n = builder->i;
}

int xmppFlush(struct xmppClient *c, bool isstanza) {
  if (isstanza && (c->features & XMPP_STREAMFEATURE_SMACKS))
    xmppAppendXml(&c->builder, "<r xmlns='urn:xmpp:sm:3'/>");
  if (c->parser.n >= c->parser.c) {
    c->builder.n = c->builder.i;
    return XMPP_EMEM;
  }
  c->builder.i = c->builder.n;
  if (isstanza && (c->features & XMPP_STREAMFEATURE_SMACKS))
    c->actualsent++;
  return 0;
}

// same as xmppFormatStanza but with xmppFlush isstanza = false instead of true
#define BuildComplete(client, fmt, ...)                                \
  (xmppAppendXml(&(client)->builder, fmt __VA_OPT__(, ) __VA_ARGS__),  \
   xmppFlush((c), false))

// res: string or NULL if you want the server to generate it
#define xmppFormatBindResource(c, res)                                 \
  BuildComplete(c,                                                     \
                "<iq id='bind' type='set'><bind "                      \
                "xmlns='urn:ietf:params:xml:ns:xmpp-bind'[/"           \
                ">][><resource>%s</resource></bind>]</iq>",            \
                !(res), !!(res), (res))

// XEP-0198: Stream Management

#define xmppFormatAckEnable(client, resume) BuildComplete(client, "<enable xmlns='urn:xmpp:sm:3'[ resume='true']/>", resume)
#define xmppFormatAckResume(client, h, previd) BuildComplete(client, "<resume xmlns='urn:xmpp:sm:3' h='%d' previd='%s'/>", h, previd)
#define xmppFormatAckRequest(client) BuildComplete(client, "<r xmlns='urn:xmpp:sm:3'/>")
#define xmppFormatAckAnswer(client, h) BuildComplete(client, "<a xmlns='urn:xmpp:sm:3' h='%d'/>", h)

#define FormatSaslPlain(client, ctx)                                        \
  BuildComplete(client,                                                         \
            "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' "          \
            "mechanism='PLAIN'>%b</auth>",                             \
            (ctx)->end, (ctx)->p)

#define xmppFormatStream(client, to) BuildComplete(client, \
    "<?xml version='1.0'?>" \
    "<stream:stream xmlns='jabber:client'" \
    " version='1.0' xmlns:stream='http://etherx.jabber.org/streams'" \
    " to='%s'>", to)

// For static XML we can directly call SafeStpCpy
#define xmppFormatStartTls(client) BuildComplete(client, "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")

#define xmppFormatSaslInitialMessage(client, ctx) \
  BuildComplete(c, "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='SCRAM-SHA-1'>%b</auth>", (ctx)->serverfirstmsg-1, (ctx)->p)

#define xmppFormatSaslResponse(client, ctx) BuildComplete(client, "<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>%b</response>", (ctx)->end-(ctx)->clientfinalmsg, (ctx)->p+(ctx)->clientfinalmsg)

/**
 * @param slc is base64 inside <success>
 */
static int VerifySaslSuccess(struct xmppSaslContext *ctx, struct xmppXmlSlice *slc) {
  assert(ctx->state == XMPP_SASL_CALCULATED);
  char b1[30], b2[20];
  size_t n = 30;
  // TODO: don't haredcode slc->p+1 and slc->rawn-2, use xmppReadXmlSlice
  if (xmppDecodeBase64XmlSlice(b1, &n, slc)
   || mbedtls_base64_decode(b2, 20, &n, b1+2, 28))
    return XMPP_ESPEC;
  return !!memcmp(ctx->srvsig, b2, 20);
}

static int H(char k[static 20], const char *pwd, size_t plen, const char *salt, size_t slen, int itrs) {
  int r = mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA1, pwd, plen, salt, slen, itrs, 20, k);
  if (r != 0) {
    return 0;
  }
  return 1;
}

static int HMAC(char d[static 20], const char *p, size_t n, const char k[static 20]) {
  int r = mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), k, 20, p, n, d);
  if (r != 0) {
    return 0;
  }
  return 1;
}

static int Sha1(char d[static 20], const char p[static 20]) {
  int r = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), p, 20, d);
  if (r != 0) {
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

/**
 * Solve SASL SCRAM challenge using a password.
 *
 * This function can be called multiple times without messing up the
 * state in ctx.
 *
 * @param ctx must be initialized using InitSaslContext()
 * @param c is the content of <challenge> in base64
 */
static int SolveSaslChallenge(struct xmppSaslContext *ctx, struct xmppXmlSlice c, const char *pwd) {
  assert(ctx->state >= XMPP_SASL_INITIALIZED);
  assert(c.p && pwd);
  int itrs = 0;
  char *s, *i, *e = ctx->p+ctx->n - 1; // keep the nul
  char *r = ctx->p+ctx->serverfirstmsg;
  // TODO: don't haredcode c.p+1 and c.rawn-2, use xmppReadXmlSlice
  size_t n = e-r;
  if (xmppDecodeBase64XmlSlice(r, &n, &c))
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
  if (HasOverflowed(r+nb, e))
    return XMPP_EMEM;
  memcpy(r, ctx->p+servernonce, nb);
  r += nb;
  ctx->authmsgend = r - ctx->p;
  if (mbedtls_base64_decode(r, e-r, &n, s+3, i-s-3))
    return XMPP_ESPEC;
  char clientproof[20];
  if (!CalculateScramSha1(ctx, clientproof, pwd, strlen(pwd), r, n, itrs))
    return XMPP_ECRYPTO;
  r = SafeStpCpy(r, e, ",p=");
  if (HasOverflowed(r, e))
    return XMPP_EMEM;
  if (mbedtls_base64_encode(r, e-r, &n, clientproof, 20))
    return XMPP_ESPEC;
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

int xmppSupplyPassword(struct xmppClient *c, const char *pwd) {
  int r;
  if (c->state == CLIENTSTATE_SASLPWD) {
    SolveSaslChallenge(&c->saslctx, c->stanza.saslchallenge, pwd);
    if ((r = xmppFormatSaslResponse(c, &c->saslctx)))
      return r;
    c->state = CLIENTSTATE_SASLCHECKRESULT;
  } else if (c->state == CLIENTSTATE_SASLPLAIN) {
    MakeSaslPlain(&c->saslctx, c->jid.localp, pwd);
    if ((r = FormatSaslPlain(c, &c->saslctx)))
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

void xmppParseJid(struct xmppJid *jid, char *p, size_t n, const char *s) {
  assert(n > 0);
  memset(jid, 0, sizeof(struct xmppJid));
  strncpy(p, s, n);
  jid->c = n;
  jid->localp = p;
  for (;*p; p++) {
    if (*p == '@') {
      *p++ = 0;
      break;
    }
  }
  jid->domainp = p;
  for (;*p; p++) {
    if (*p == '/') {
      *p++ = 0;
      break;
    }
  }
  jid->resourcep = p;
}

void xmppGetReceiveBuffer(const struct xmppClient *client, char **buf,
                          size_t *maxsz, bool *istls) {
  if (buf)
    *buf = client->parser.p + client->parser.n;
  if (maxsz)
    *maxsz = client->parser.c - client->parser.n;
  if (istls)
    *istls = !!(client->features & XMPP_STREAMFEATURE_STARTTLS);
}

void xmppAddAmountReceived(struct xmppClient *client, size_t amount) {
  client->parser.n += amount;
  assert(client->parser.n <= client->parser.c);
}

void xmppGetSendBuffer(const struct xmppClient *client, char **buf,
                       size_t *sz, bool *istls) {
  if (buf)
    *buf = client->builder.p;
  if (sz)
    *sz = client->builder.n;
  if (istls)
    *istls = !!(client->features & XMPP_STREAMFEATURE_STARTTLS);
}

void xmppAddAmountSent(struct xmppClient *client, size_t amount) {
  assert(amount <= client->builder.n);
  client->builder.n -= amount;
  client->builder.i = client->builder.n;
  memmove(client->builder.p, client->builder.p + amount,
          client->builder.n);
  // TODO: remove
  memset(client->builder.p + client->builder.n, 0,
         client->builder.c - client->builder.n);
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
// xmppIterate
static int EndStream(struct xmppClient *c) {
  c->state = CLIENTSTATE_UNINIT;
  return BuildComplete(c, "</stream:stream>") ? XMPP_ITER_OK
                                                    : XMPP_ITER_SEND;
}

static int ReturnStreamError(struct xmppClient *c, int r) {
  c->state = CLIENTSTATE_ENDSTREAM;
  return r;
}

void xmppEndStream(struct xmppClient *c) {
  if (xmppIsInitialized(c))
    c->state = CLIENTSTATE_ENDSTREAM;
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
  yxml_init(&p->x, p->xbuf, p->xbufn);
}

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
    if ((r = xmppFormatStream(c, c->jid.domainp)))
      return ReturnRetry(c, r);
    c->state = CLIENTSTATE_STREAMSENT;
    return XMPP_ITER_SEND;
  }
  if (c->state == CLIENTSTATE_ENDSTREAM) {
    return EndStream(c);
  }
  MoveStanza(&c->parser);
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
        if ((r = xmppFormatStartTls(c)))
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
        InitSaslContext(&c->saslctx, c->jid.localp);
        if ((r = xmppFormatSaslInitialMessage(c, &c->saslctx)))
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
      if ((r = xmppFormatAckResume(c, c->actualrecv, c->smackid)))
        return ReturnRetry(c, r);
      c->state = CLIENTSTATE_RESUME;
      return XMPP_ITER_SEND;
    }
    assert(stream.features & XMPP_STREAMFEATURE_BIND);
    if ((r = xmppFormatBindResource(c,  c->jid.resourcep)))
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
      assert(VerifySaslSuccess(&c->saslctx, &st->saslsuccess) == 0);
      memset(c->saslctx.p, 0, c->saslctx.n);
      //memset(&c->saslctx, 0, sizeof(c->saslctx));
      c->features |= XMPP_STREAMFEATURE_SCRAMSHA1;
      c->state = CLIENTSTATE_INIT;
      return XMPP_ITER_OK;
    case CLIENTSTATE_SASLRESULT:
      if (st->type == XMPP_STANZA_FAILURE)
        return ReturnStreamError(c, XMPP_EPASS);
      assert(st->type == XMPP_STANZA_SASLSUCCESS);
      memset(c->saslctx.p, 0, c->saslctx.n);
      //memset(&c->saslctx, 0, sizeof(c->saslctx));
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
      //if (memcmp(c->jid.local, st->bindjid.p, c->jid.localn) ||
      //    memcmp(c->jid.domain, st->bindjid.p + c->jid.localn + 1,
      //           c->jid.domainn) ||
      //    memcmp(c->jid.resourcep,
      //           st->bindjid.p + c->jid.localn + 1 + c->jid.domainn + 1,
      //           c->jid.resourcen_))
      //  return XMPP_EBIND;
      // TODO: check if returned bind address is either empty or the same as
      // c->jid, maybe put the new resource into c->jid.resource
      if (!(c->opts & XMPP_OPT_DISABLESMACKS)) {
        if ((r = xmppFormatAckEnable(c, true)))
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
      (st->type == XMPP_STANZA_IQ ||
       st->type == XMPP_STANZA_MESSAGE ||
       st->type == XMPP_STANZA_PRESENCE))
      c->actualrecv++;
  switch (st->type) {
  case XMPP_STANZA_SMACKSENABLED:
    c->features |= XMPP_STREAMFEATURE_SMACKS;
    if (st->smacksenabled.id.p) {
      assert(st->smacksenabled.id.rawn < c->smackidc);
      memcpy(c->smackid, st->smacksenabled.id.p, st->smacksenabled.id.rawn);
      if (!(c->opts & XMPP_OPT_DISABLESMACKS))
        c->cansmackresume = st->smacksenabled.resume;
    }
    return XMPP_ITER_OK;
  case XMPP_STANZA_ACKANSWER:
    return XMPP_ITER_ACK;
  case XMPP_STANZA_ACKREQUEST:
    if ((r = xmppFormatAckAnswer(c, c->actualrecv)))
      return r;
    return XMPP_ITER_SEND;
  default:
    return XMPP_ITER_STANZA;
  }
  return XMPP_ITER_OK;
}
