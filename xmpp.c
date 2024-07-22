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


// RFC 6122 2.1
#define XMPP_CONFIG_MAX_JID_SIZE 3071

// RFC 6120 13.12
// If a stanza exceeds this size, we either give a stanza or stream
// error or ignore the stanza.
#define XMPP_CONFIG_MAX_STANZA_SIZE 10000

// XEP-0198 5
#define XMPP_CONFIG_MAX_SMACKID_SIZE 4000

#define XMPP_CONFIG_MAX_YXMLBUF_SIZE 2000

#define XMPP_CONFIG_MAX_SASLSCRAM1_ITERS 10000

// https://sans-io.readthedocs.io/
// starttls reference with MbedTLS: https://github.com/espressif/esp-idf/blob/master/examples/protocols/smtp_client/main/smtp_client_example_main.c

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

// if (s.p && (d = calloc(s.n+1))) xmppReadXmlSlice(d, s);
// TODO: have specific impl for this?
// TODO: we can skip the whole prefix initialization since that is
// static. just memcpy the internal state to the struct.
void xmppReadXmlSlice(char *d, struct xmppXmlSlice s) {
  if (s.type == XMPP_SLICE_ATTR || s.type == XMPP_SLICE_CONT) {
    static const char attrprefix[] = "<x e='";
    static const char contprefix[] = "<x>";
    char buf[16];
    int i;
    yxml_t x;
    yxml_init(&x, buf, sizeof(buf));
    int target = s.type == XMPP_SLICE_ATTR ? YXML_ATTRVAL : YXML_CONTENT;
    const char *prefix = s.type == XMPP_SLICE_ATTR ? attrprefix : contprefix;
    size_t n = s.type == XMPP_SLICE_ATTR ? sizeof(attrprefix)-1 : sizeof(contprefix)-1;
    for (i = 0; i < n; i++) {
      yxml_parse(&x, prefix[i]);
    }
    for (i = 0; i < s.rawn; i++) {
      // with parsing input validation has already succeeded so there is
      // no reason to check for errors again.
      if (yxml_parse(&x, s.p[i]) == target)
        d = stpcpy(d, x.data);
    }
    if (s.type == XMPP_SLICE_ATTR) {
      if (yxml_parse(&x, '\'') == YXML_ATTRVAL)
        d = stpcpy(d, x.data);
    }
  } else if (s.type == XMPP_SLICE_B64) {
    DecodeBase64(d, d+s.n, s.p, s.rawn); // TODO: check if b64 is valid.
  } else {
    memcpy(d, s.p, s.rawn);
  }
}

// The buffer used is too small. For Format functions this will be the size of the output buffer. For SASL related functions this will be the buffer given to xmppInitSaslContext.
#define XMPP_EMEM -1
// Some input from the input buffer is either malformed XML or does not follow the XMPP specification.
#define XMPP_EXML -2
// MbedTls cryptography-related functions failed. (Could also be failed malloc done by MbedTls)
#define XMPP_ECRYPTO -3
// The input buffer end with an incomplete stanza.
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

#define XMPP_SASL_INITIALIZED 1
#define XMPP_SASL_CALCULATED 2

#define XMPP_SASL_CHALLENGE 1
#define XMPP_SASL_SUCCESS   2

#define XMPP_STREAMFEATURE_STARTTLS (1 << 0)
#define XMPP_STREAMFEATURE_BIND (1 << 1)
#define XMPP_STREAMFEATURE_SCRAMSHA1 (1 << 2)
#define XMPP_STREAMFEATURE_SCRAMSHA1PLUS (1 << 3)
#define XMPP_STREAMFEATURE_PLAIN (1 << 4)
#define XMPP_STREAMFEATURE_SMACKS (1 << 5)

#define XMPP_STREAMFEATUREMASK_SASL                                    \
  (XMPP_STREAMFEATURE_SCRAMSHA1 | XMPP_STREAMFEATURE_SCRAMSHA1PLUS |   \
   XMPP_STREAMFEATURE_PLAIN)

#define XMPP_DISCO_DONE (1 << 0)
#define XMPP_DISCO_REGISTER (1 << 1)

#define XMPP_STANZA_EMPTY 0
#define XMPP_STANZA_MESSAGE 1
#define XMPP_STANZA_PRESENCE 2
#define XMPP_STANZA_IQ 3
#define XMPP_STANZA_STREAMFEATURES 4
#define XMPP_STANZA_BINDJID 5
#define XMPP_STANZA_SMACKSENABLED 6
#define XMPP_STANZA_STARTTLSPROCEED 7
// server can't send ack request
//#define XMPP_STANZA_ACKREQUEST 7
#define XMPP_STANZA_ACKANSWER 8
#define XMPP_STANZA_SASLSUCCESS 9
#define XMPP_STANZA_SASLCHALLENGE 10
#define XMPP_STANZA_DISCOREQ 11
#define XMPP_STANZA_DISCORESP 12
#define XMPP_STANZA_PING 13

#define XMPP_FAILURE_ABORTED                (1 << 0)
#define XMPP_FAILURE_ACCOUNT_DISABLED       (1 << 1)
#define XMPP_FAILURE_CREDENTIALS_EXPIRED    (1 << 2)
#define XMPP_FAILURE_ENCRYPTION_REQUIRED    (1 << 3)
#define XMPP_FAILURE_INCORRECT_ENCODING     (1 << 4)
#define XMPP_FAILURE_INVALID_AUTHZID        (1 << 5)
#define XMPP_FAILURE_INVALID_MECHANISM      (1 << 6)
#define XMPP_FAILURE_MALFORMED_REQUEST      (1 << 7)
#define XMPP_FAILURE_MECHANISM_TOO_WEAK     (1 << 8)
#define XMPP_FAILURE_NOT_AUTHORIZED         (1 << 9)
#define XMPP_FAILURE_TEMPORARY_AUTH_FAILURE (1 << 10)


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
  struct xmppXmlSlice id;
  bool resume;
};

struct xmppFailure {
  int reasons;
  struct xmppXmlSlice text;
};

// XML stanza transformed into a C structure.
// type = XMPP_STANZA_*
// The associated field is as follows:
//  type = XMPP_STANZA_FAILURE, field = failure
//  type = XMPP_STANZA_BINDJID, field = bindjid
//  etc.
struct xmppStanza {
  int type;
  struct xmppXmlSlice id, from, to;
  union {
    struct xmppFailure failure;
    struct xmppXmlSlice saslchallenge;
    struct xmppXmlSlice saslsuccess;
    struct xmppMessage message;
    struct xmppError error;
    struct xmppXmlSlice bindjid;
    struct xmppSmacksEnabled smacksenabled;
    int ack;
  };
};

struct xmppListIterator {
  int type;
  const char *p;
  size_t i, rawn;
};

static bool ComparePaddedString(const char *p, const char *s, size_t pn) {
  return true;
}

#define HasOverflowed(p, e) ((p) >= (e))

// TODO: remove unneeded parts of yxml, dozens of LOC can be removed
// because XMPP only allows subset of XML and the usage here is usecase
// specific. We would also benefit from adding the following states to
// yxml_ret_t: YXML_ATTRSEND (when either / or > is encountered
// inside an element to notify that there will be no more attributes) &
// YXML_CONTENTSTOP (when < is encountered) & possible also
// YXML_CONTENTSTART (when > is encountered).
struct xmppParser {
  yxml_t x;
  char xbuf[XMPP_CONFIG_MAX_YXMLBUF_SIZE];
  jmp_buf jb;
  size_t i, n, c;
  char *p;
};

struct xmppStream {
  struct xmppXmlSlice from, to, id;
  int features;
  int optionalfeatures;
  int requiredfeatures;
  bool hasunknownrequired; // TODO: make this an error?
};

// full  domain      resource    end
// v     v           v           v
// admin@example.com/someresource
// full buffer is at the end, because might some header definition
// change the size for different compilation units, accessing other
// field members will not be invalid.
struct Jid {
  size_t domain, resource, end;
  char full[XMPP_CONFIG_MAX_JID_SIZE+1];
};

// TODO: replace struct Jid with this.
struct BetterJid {
  size_t localn, domainn, resourcen;
  char local[1024], domain[1024], resource[1024];
};

// i = current end pos of xml
// n = size of buffer in p
struct xmppXmlComposer {
  char *p;
  size_t n, c;
};

// p is a buffer allocated by a parent as heap or static
// n is length of said buffer
// have max size be influenced by prosody's impl?
// buffer will contain n,, + authmessage + ,p= + clientproofb64
// https://wiki.xmpp.org/web/SASL_Authentication_and_SCRAM#In_detail
// feel free to realloc p if malloc'ed: ctx.p = realloc(ctx.p, (ctx.n*=2))
struct xmppSaslContext {
  int state;
  char *p;
  size_t n;
  size_t initialmsg;
  size_t serverfirstmsg;
  size_t clientfinalmsg;
  size_t authmsgend;
  size_t end;
  char srvsig[20];
};

// stanza is valid after XMPP_ITER_STANZA and until the next call of
// xmppIterate.
struct xmppClient {
  struct BetterJid jid;
  char smackid[XMPP_CONFIG_MAX_SMACKID_SIZE],
      in[XMPP_CONFIG_MAX_STANZA_SIZE], out[XMPP_CONFIG_MAX_STANZA_SIZE];
  size_t smackidn;
  char saslbuf[2000];
  struct xmppSaslContext saslctx;
  struct xmppStanza stanza;
  struct xmppParser parser;
  struct xmppXmlComposer comp;
  int opts;
  bool isnegotiationdone;
  int state;
  int disco;
  int features;
  int actualsent, actualrecv;
  int sentacks, recvacks;
  int lastdisco, lastping;
  bool disablesmack, disabledisco, enablereceipts;
  bool cansmackresume;
};

// Skip all the way until the end of the element it has just entered
static void SkipUnknownXml(struct xmppParser *p) {
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
static int ParseAttribute(struct xmppParser *p, struct xmppXmlSlice *slc) {
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

// MAY ONLY be called after ParseAttribute returns 1
// or right after ELEMSTART
// will read all the way to end of element
static void GetXmlContent(struct xmppParser *p, struct xmppXmlSlice *slc) {
  int r;
  bool stop = false;
  struct xmppXmlSlice attr;
  memset(slc, 0, sizeof(*slc));
  while (ParseAttribute(p, &attr)) {}
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
static int ParseElement(struct xmppParser *p) { //, const char *opt) {
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
  while (ParseAttribute(p, &attr)) {
    if (!strcmp(p->x.attr, "h"))
      st->ack = SliceToI(attr);
  }
  SkipUnknownXml(p);
}

// TODO: have new yxml state per stanza, this is only because if a stanza is partial
// we want to ignore it and let the user decide if it needs to get more data from server
// and read it again, the yxml would be messed up for reading again
// maybe this is not needed.
// But right now if we want to correctly detect </stream:stream>, the new yxml state should
// start with <stream:stream>
int xmppParseStanza(struct xmppParser *p, struct xmppStanza *st) {
  int r;
  int i = p->i;
  struct xmppXmlSlice attr, cont;
  memset(st, 0, sizeof(*st));
  // TODO: put back the initialization of stream:stream
  if ((r = setjmp(p->jb))) {
    memset(st, 0, sizeof(*st));
    p->i = i;
    return r;
  }
  if (!ParseElement(p))
    longjmp(p->jb, XMPP_EXML);
  if (!strcmp(p->x.elem, "iq")) st->type = XMPP_STANZA_IQ;
  else if (!strcmp(p->x.elem, "a")) {
    ReadAckAnswer(p, st);
    return 0;
  } else if (!strcmp(p->x.elem, "enabled")) {
    st->type = XMPP_STANZA_SMACKSENABLED;
    while (ParseAttribute(p, &attr)) {
      if (!strcmp(p->x.attr, "id")) {
        memcpy(&st->smacksenabled.id, &attr, sizeof(attr));
      } else if (!strcmp(p->x.attr, "resume")) {
        st->smacksenabled.resume = !strncmp(attr.p, "true", attr.rawn)
          || !strncmp(attr.p, "1", attr.rawn);
      }
    }
    SkipUnknownXml(p);
    return 0;
  } else if (!strcmp(p->x.elem, "proceed")) {
    st->type = XMPP_STANZA_STARTTLSPROCEED;
    SkipUnknownXml(p);
    return 0;
  } else if (!strcmp(p->x.elem, "failure")) { // TODO: happens for both SASL and TLS
    while (ParseElement(p)) {
      if (!strcmp(p->x.elem, "text"))
        GetXmlContent(p, &st->failure.text);
#define X(xmlname, enumname) \
      else if (!strcmp(p->x.elem, #xmlname))  \
        st->failure.reasons |= XMPP_FAILURE_##enumname;
      // TODO: should we do all of this or the most common ones? or we can
      // store the error name in a XmlSlice.
      X(aborted, ABORTED)
      X(account-disabled, ACCOUNT_DISABLED)
      X(credentials-expired, CREDENTIALS_EXPIRED)
      X(encryption-required, ENCRYPTION_REQUIRED)
      X(incorrect-encoding, INCORRECT_ENCODING)
      X(invalid-authzid, INVALID_AUTHZID)
      X(invalid-mechanism, INVALID_MECHANISM)
      X(malformed-request, MALFORMED_REQUEST)
      X(mechanism-too-weak, MECHANISM_TOO_WEAK)
      X(not-authorized, NOT_AUTHORIZED)
      X(temporary-auth-failure, TEMPORARY_AUTH_FAILURE)
#undef X
      SkipUnknownXml(p);
    }
    return 0;
  } else if (!strcmp(p->x.elem, "success")) {
    st->type = XMPP_STANZA_SASLSUCCESS;
    GetXmlContent(p, &st->saslsuccess);
    return 0;
  } else if (!strcmp(p->x.elem, "challenge")) {
    st->type = XMPP_STANZA_SASLCHALLENGE;
    GetXmlContent(p, &st->saslchallenge);
    return 0;
  }
  while (ParseAttribute(p, &attr)) {
    if (!strcmp(p->x.attr, "id")) {
      memcpy(&st->id, &attr, sizeof(attr));
    } else if (!strcmp(p->x.attr, "from")) {
      memcpy(&st->from, &attr, sizeof(attr));
    } else if (!strcmp(p->x.attr, "to")) {
      memcpy(&st->to, &attr, sizeof(attr));
    }
  }
  if (!ParseElement(p))
    return 0;
  if (st->type == XMPP_STANZA_IQ && !strcmp(p->x.elem, "bind")) {
    if (!ParseElement(p) || strcmp(p->x.elem, "jid"))
      longjmp(p->jb, XMPP_EXML);
    GetXmlContent(p, &st->bindjid);
    st->type = XMPP_STANZA_BINDJID;
    SkipUnknownXml(p);
  }
  SkipUnknownXml(p);
  return 0;
}

static void ParseOptionalRequired(struct xmppParser *p, struct xmppStream *s, int flag) {
  s->features |= flag;
  while (ParseElement(p)) {
    if (!strcmp(p->x.elem, "optional"))
      s->optionalfeatures |= flag;
    else if (!strcmp(p->x.elem, "required"))
      s->requiredfeatures |= flag;
    else
      longjmp(p->jb, XMPP_EXML);
    SkipUnknownXml(p);
  }
}

// Read stream and features
// Features ALWAYS come after server stream according to spec
// If server too slow, user should read more.
int xmppParseStream(struct xmppParser *p, struct xmppStream *s) {
  struct xmppXmlSlice attr;
  int r;
  int i = p->i;
  yxml_init(&p->x, p->xbuf, sizeof(p->xbuf));
  memset(s, 0, sizeof(*s));
  if ((r = setjmp(p->jb))) {
    memset(s, 0, sizeof(*s));
    p->i = i;
    return r;
  }
  if (!ParseElement(p) || strcmp(p->x.elem, "stream:stream"))
    longjmp(p->jb, XMPP_EXML);
  while (ParseAttribute(p, &attr)) {
    if (!strcmp(p->x.attr, "id")) {
      memcpy(&s->id, &attr, sizeof(attr));
    } else if (!strcmp(p->x.attr, "from")) {
      memcpy(&s->from, &attr, sizeof(attr));
    } else if (!strcmp(p->x.attr, "to")) {
      memcpy(&s->to, &attr, sizeof(attr));
    }
  }
  if (!ParseElement(p) || strcmp(p->x.elem, "stream:features"))
    longjmp(p->jb, XMPP_EXML);
  while (ParseElement(p)) {
    if (!strcmp(p->x.elem, "starttls")) {
      s->features |= XMPP_STREAMFEATURE_STARTTLS;
      SkipUnknownXml(p);
    } else if (!strcmp(p->x.elem, "mechanisms")) {
      while (ParseElement(p)) {
        struct xmppXmlSlice mech;
        if (strcmp(p->x.elem, "mechanism"))
          longjmp(p->jb, XMPP_EXML);
        GetXmlContent(p, &mech);
        if (!strncmp(mech.p, "SCRAM-SHA-1", mech.n)) // TODO: mech.rawn
          s->features |= XMPP_STREAMFEATURE_SCRAMSHA1;
        else if (!strncmp(mech.p, "SCRAM-SHA-1-PLUS", mech.n)) // TODO: mech.rawn
          s->features |= XMPP_STREAMFEATURE_SCRAMSHA1PLUS;
        else if (!strncmp(mech.p, "PLAIN", mech.n)) // TODO: mech.rawn
          s->features |= XMPP_STREAMFEATURE_PLAIN;
      }
    } else if (!strcmp(p->x.elem, "sm")) {
      if (!ParseAttribute(p, &attr) || strcmp(p->x.attr, "xmlns"))
        longjmp(p->jb, XMPP_EXML);
      if (!strncmp(attr.p, "urn:xmpp:sm:3", attr.rawn))
        ParseOptionalRequired(p, s, XMPP_STREAMFEATURE_SMACKS);
      else
        SkipUnknownXml(p);
    } else if (!strcmp(p->x.elem, "bind")) {
      ParseOptionalRequired(p, s, XMPP_STREAMFEATURE_BIND);
    } else {
      while (ParseElement(p)) {
        if (!strcmp(p->x.elem, "required"))
          s->hasunknownrequired = true;
        SkipUnknownXml(p);
      }
    }
  }
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
static int FormatXml(struct xmppXmlComposer *c, const char *fmt, ...) {
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
  c->n = d - c->p;
  return HasOverflowed(d, e);
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
    return XMPP_EXML;
  return !!memcmp(ctx->srvsig, b2, 20);
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
static int CalculateScramSha1(struct xmppSaslContext *ctx, char clientproof[static 20], const char *pwd, size_t plen, const char *salt, size_t slen, int itrs) {
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
    return XMPP_EXML;
  size_t servernonce = ctx->serverfirstmsg + 2;
  if (strncmp(r, "r=", 2)
   || !(s = strstr(r+2, ",s="))
   || !(i = strstr(s+3, ",i=")))
    return XMPP_EXML;
  size_t saltb64 = s-ctx->p + 3;
  itrs = atoi(i+3);
  if (itrs == 0 || itrs > XMPP_CONFIG_MAX_SASLSCRAM1_ITERS)
    return XMPP_EXML;
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
  p->n = p->n - p->i;
  memmove(p->p, p->p + p->i, p->n);
  p->i = 0;
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

// Nothing should be done, make another call to xmppIterate.
#define XMPP_ITER_OK 0
// A stanza was read. You can access the stanza in c->stanza, it will be valid up until the next call of Iterate.
#define XMPP_ITER_STANZA   1
// Data should be sent and received.
// TODO: rename to TRANSFER or NET
#define XMPP_ITER_SEND 2
// TLS handshake must be done now.
#define XMPP_ITER_STARTTLS 3
// Stream negotation has completed, you can now send and receive
// stanzas. After ready is returned, you may send new stanzas. When data
// is available you should read it.
#define XMPP_ITER_READY 4

// returned when SASL negotiation starts, xmppSupplyPassword will perform the SASL calculations. To strengthen security, the password is not stored in plaintext inside the xmppClient, also after calling said function, the buffer in the `pwd` argument should be zero'd.
#define XMPP_ITER_GIVEPWD 5

#define XMPP_ITER_RECV 6

#define XMPP_ITER_SASLFAIL -10

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
  CLIENTSTATE_SASLRESPONSE,
  CLIENTSTATE_SASLCHECKRESULT,
  CLIENTSTATE_SASLPLAIN,
  CLIENTSTATE_SASLRESULT,
  CLIENTSTATE_BIND,
  CLIENTSTATE_ACCEPTSTANZA,
  CLIENTSTATE_SMACKS,
};

// Always emit stanzas (TLS and SASL negotiation not included).
#define XMPP_OPT_EMITSTANZA (1 << 0) 
// Security related:
// By default all connections MUST go over TLS. For SASL, SCRAM is preferred but PLAIN is allowed.
// TLS optional, SCRAM forced.
#define XMPP_OPT_ALLOWUNENCRYPTED (1 << 1)
// No TLS, SCRAM still forced.
#define XMPP_OPT_FORCEUNENCRYPTED (1 << 2)
// Force SCRAM, even over TLS.
#define XMPP_OPT_FORCESCRAM (1 << 3)
// Danger zone!!!
// Allow PLAIN SASL, even without TLS.
#define XMPP_OPT_ALLOWUNENCRYPTEDPLAIN (1 << 4)
// Always force PLAIN SASL.
#define XMPP_OPT_FORCEPLAIN (1 << 5)

static void SendMessage(struct xmppClient *c, const char *to, const char *body) {
  xmppFormatMessage(&c->comp, to, 1, body);
  if (c->features & XMPP_STREAMFEATURE_SMACKS) {
    xmppFormatAckRequest(&c->comp);
  }
  c->actualsent++;
}

static void SendPing(struct xmppClient *c, const char *to) {
  int ping = c->lastping + 1;
  xmppFormatPing(&c->comp, to, ping);
  c->lastping = ping;
  c->actualsent++;
}

// Coindcidentally the only function that allocates on the heap.
static void xmppSupplyPassword(struct xmppClient *c, const char *pwd, size_t n) {
  if (c->state == CLIENTSTATE_SASLPWD) {
    xmppSolveSaslChallenge(&c->saslctx, c->stanza.saslchallenge, pwd);
    xmppFormatSaslResponse(&c->comp, &c->saslctx);
    c->state = CLIENTSTATE_SASLCHECKRESULT;
  } else if (c->state == CLIENTSTATE_SASLPLAIN) {
    MakeSaslPlain(&c->saslctx, c->saslbuf, sizeof(c->saslbuf), c->jid.local, pwd);
    FormatSaslPlain(&c->comp, &c->saslctx);
    c->state = CLIENTSTATE_SASLRESULT;
  } else {
    assert(false);
  }
}

// finds the first occurance of c in s and returns the position after
// the occurance or 0 if not found.
static size_t FindNext(const char *s, char c) {
  const char *f;
  return (f = strchr(s, c)) ? f - s + 1 : 0;
}

static void xmppInitClient(struct xmppClient *c, const char *jid, int opts) {
  memset(c, 0, sizeof(*c));
  c->opts = opts;
  c->state = CLIENTSTATE_INIT;
  c->parser.p = c->in;
  c->parser.c = sizeof(c->in);
  c->comp.p = c->out;
  c->comp.c = sizeof(c->out);
  size_t d = FindNext(jid, '@'), r = FindNext(jid, '/'), n = strlen(jid);
  memcpy(c->jid.local, jid, (c->jid.localn = d-1));
  memcpy(c->jid.domain, jid+d, (c->jid.domainn = r-d-1));
  memcpy(c->jid.resource, jid+r, (c->jid.resourcen = n-r));
}

// bool isstanza -> send ack
static int ReturnSend(int r) {
  return XMPP_ITER_SEND;
}

// When SEND is returned, the complete out buffer (c->comp.p) with the
// size specified in (c->comp.n) must be sent over the network before
// another iteration is done. If c->comp.n is 0, you don't have to write
// anything. It is recommended that your send function does not block so
// that you can call Iterate again asap. You may only reallocate the in
// buffer just before or after reading from the network.
// ret:
//  XMPP_ITER_*
static int xmppIterate(struct xmppClient *c) {
  struct xmppStanza *st = &c->stanza;
  struct xmppStream stream;
  int r;
  // always return SEND if the out buffer is not returned, do not
  // try caching to avoid prematurely filling up the entire buffer. Let
  // the OS/network stack handle caching.
  if (c->comp.n > 0)
    return XMPP_ITER_SEND;
  if (c->state == CLIENTSTATE_INIT) {
      c->state = CLIENTSTATE_STREAMSENT;
      return ReturnSend(xmppFormatStream(&c->comp, c->jid.domain));
  }
  if (c->state == CLIENTSTATE_STREAMSENT) {
    if (c->parser.i == c->parser.n || (r = xmppParseStream(&c->parser, &stream)) == XMPP_EPARTIAL) {
      MoveStanza(&c->parser);
      return XMPP_ITER_RECV;
    }
    assert(r == 0);
    if (stream.features & XMPP_STREAMFEATURE_STARTTLS && !(c->features & XMPP_STREAMFEATURE_STARTTLS)) {
      c->state = CLIENTSTATE_STARTTLS;
      return ReturnSend(xmppFormatStartTls(&c->comp));
    }
    if (stream.features & XMPP_STREAMFEATURE_SCRAMSHA1 && !(c->opts & XMPP_OPT_FORCEPLAIN)) {
      xmppInitSaslContext(&c->saslctx, c->saslbuf, sizeof(c->saslbuf), c->jid.local);
      c->state = CLIENTSTATE_SASLINIT;
      xmppFormatSaslInitialMessage(&c->comp, &c->saslctx);
      return XMPP_ITER_SEND;
    } else if (stream.features & XMPP_STREAMFEATURE_PLAIN) {
      c->state = CLIENTSTATE_SASLPLAIN;
      return XMPP_ITER_GIVEPWD;
    }
    if (stream.features & XMPP_STREAMFEATURE_SMACKS)
      c->features |= XMPP_STREAMFEATURE_SMACKS;
    assert(stream.features & XMPP_STREAMFEATURE_BIND);
    c->state = CLIENTSTATE_BIND;
    return ReturnSend(xmppFormatBindResource(&c->comp,  c->jid.resource));
  }
  Log("Parsing (pos %d): \e[33m%.*s\e[0m", (int)c->parser.i, (int)(c->parser.n-c->parser.i), c->parser.p+c->parser.i);
  if (c->parser.i == c->parser.n || (r = xmppParseStanza(&c->parser, st)) == XMPP_EPARTIAL) {
    MoveStanza(&c->parser); // TODO: Here we are aggressive with memmoving the stanzas, we could be more lax.
    return c->isnegotiationdone ? XMPP_ITER_READY : XMPP_ITER_RECV;
  }
  assert(r == 0);
  c->actualrecv++;
  if (!c->isnegotiationdone) {
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
      assert(st->type == XMPP_STANZA_SASLSUCCESS);
      assert(xmppVerifySaslSuccess(&c->saslctx, st->saslsuccess) == 0);
      memset(c->saslctx.p, 0, c->saslctx.n);
      memset(&c->saslctx, 0, sizeof(c->saslctx));
      c->state = CLIENTSTATE_INIT;
      return XMPP_ITER_OK;
    case CLIENTSTATE_SASLRESULT:
      assert(st->type == XMPP_STANZA_SASLSUCCESS);
      memset(c->saslctx.p, 0, c->saslctx.n);
      memset(&c->saslctx, 0, sizeof(c->saslctx));
      c->state = CLIENTSTATE_INIT;
      return XMPP_ITER_OK;
    case CLIENTSTATE_BIND:
      // TODO: check if returned bind address is either empty or the same as c->jid
      if (c->features & XMPP_STREAMFEATURE_SMACKS) {
        c->state = CLIENTSTATE_SMACKS;
        return ReturnSend(xmppFormatAckEnable(&c->comp, true));
      }
      c->state = CLIENTSTATE_ACCEPTSTANZA;
      c->isnegotiationdone = true;
      return XMPP_ITER_READY;
    case CLIENTSTATE_SMACKS:
      c->state = CLIENTSTATE_ACCEPTSTANZA;
      c->isnegotiationdone = true;
      return XMPP_ITER_READY;
    }
    assert(false);
  }
  if (c->features & XMPP_STREAMFEATURE_SMACKS)
    c->actualrecv++;
  switch (st->type) {
  case XMPP_STANZA_PING:
    FormatXml(&c->comp, "<iq to='%x' id='%x' type='result'/>", st->from, st->id);
    c->actualsent++;
    return XMPP_ITER_OK;
  case XMPP_STANZA_SMACKSENABLED:
    if (st->smacksenabled.id.p) {
      assert(st->smacksenabled.id.rawn <= sizeof(c->smackid));
      memcpy(c->smackid, st->smacksenabled.id.p, st->smacksenabled.id.rawn);
      c->cansmackresume = st->smacksenabled.resume;
    }
    break;
  case XMPP_STANZA_ACKANSWER:
    // return XMPP_ITER_UPTODATE
    //assert(st->ack == c->actualsent);
    Log("Ack succeeded!");
    break;
  default:
    return XMPP_ITER_STANZA;
  }
  //assert(false);
  return XMPP_ITER_READY;
}

#ifdef XMPP_RUNTEST
// TODO: move this to test.c and #include "xmpp.c"

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
  xmppInitClient(&client, "admin@localhost/resource", XMPP_OPT_FORCEPLAIN);
  bool sent = false;
  int r;
  for (;;) {
    switch ((r = xmppIterate(&client))) {
    case XMPP_ITER_SEND:
      Log("Out: \e[32m%.*s\e[0m", (int)client.comp.n, client.comp.p);
      SendAll();
      break;
    case XMPP_ITER_READY:
    // poll(recv, msg)
    // if msg then SendMsg(client, msg) break end
      if (!sent) {
        SendMessage(&client, "admin@localhost", "Hello!");
        xmppFormatPing(&client.comp, "localhost", 1);
        xmppFormatAckRequest(&client.comp);
        client.actualsent++;
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
      while ((r = mbedtls_ssl_handshake(&ssl)) != 0)
        assert(r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE);
      assert(mbedtls_ssl_get_verify_result(&ssl) == 0);
      break;
    case XMPP_ITER_GIVEPWD:
      xmppSupplyPassword(&client, "adminpass", 9);
      break;
    case XMPP_ITER_STANZA:
      break;
    case XMPP_ITER_OK:
    default:
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
  assert(xmppParseStream(&p, &str) == 0);
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

//static int sock;
//
//static void IterateUntil(int ex) {
//  int r = xmppIterate(&client);
//  if (r == ex)
//    return;
//"<?xml version='1.0'?><stream:stream xmlns='jabber:client' version='1.0' xmlns:stream='http://etherx.jabber.org/streams' to='localhost'>"
//"<?xml version='1.0'?><stream:stream from='localhost' xml:lang='en' id='22c26b93-d844-47a5-a4ba-b8731c558245' version='1.0' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'><stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>SCRAM-SHA-1</mechanism></mechanisms><register xmlns='urn:xmpp:invite'/><register xmlns='urn:xmpp:ibr-token:0'/><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/><register xmlns='http://jabber.org/features/iq-register'/></stream:features>"
//"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
//"<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
//"<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"
//"<?xml version='1.0'?><stream:stream xmlns='jabber:client' version='1.0' xmlns:stream='http://etherx.jabber.org/streams' to='localhost'>"
//"<?xml version='1.0'?><stream:stream from='localhost' xml:lang='en' id='25414acb-6c9d-4fc0-a489-169d9a680ce8' version='1.0' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'><stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>SCRAM-SHA-1</mechanism><mechanism>SCRAM-SHA-1-PLUS</mechanism><mechanism>PLAIN</mechanism></mechanisms><register xmlns='urn:xmpp:invite'/><register xmlns='urn:xmpp:ibr-token:0'/><register xmlns='http://jabber.org/features/iq-register'/></stream:features>"
//"<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='SCRAM-SHA-1'>biwsbj1hZG1pbixyPTIwOEI5QjNGNTk0MTAyQTBEN0RDQTg5QzU1MjVGQ0FENTVEQTY4MkU1Njc2MTVFMzA4MDlGREZFMTE3NEJBMzU=</auth>"

//}
//
//static void Test() {
//  ExpectUntil("<stream:stream>");
//  Send("<stream:stream>");
//}


int main() {
  puts("Starting tests");
  TestClient();
  TestXml();
  puts("All tests passed");
  return 0;
}


#endif
