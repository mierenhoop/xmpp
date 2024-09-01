#ifndef XMPP_H_
#define XMPP_H_

#include <stddef.h>
#include <stdbool.h>
#include <setjmp.h>

#include "yxml.h"

// https://xmpp.org/rfcs/rfc6120.html#:~:text=A%20deployed%20server%27s%20maximum%20stanza%20size%20MUST%20NOT%20be%20smaller%20than%2010000%20bytes
#define XMPP_CONFIG_INBUF_SIZE 50000
#define XMPP_CONFIG_OUTBUF_SIZE 50000
// https://xmpp.org/rfcs/rfc6120.html#:~:text=xs%3AmaxLength%20value%3D%27-,3071,-%27/%3E%0A%20%20%20%20%3C/xs%3Arestriction%3E%0A%20%20%3C/xs
#define XMPP_CONFIG_MAX_JID_SIZE 3071
// https://xmpp.org/extensions/attic/xep-0198-1.6.1.html#:~:text=The%20SM%2DID%20SHOULD%20NOT%20be%20longer%20than%204000%20bytes.
// TODO: note server-specific common sizes (4000 is overkill)
#define XMPP_CONFIG_MAX_SMACKID_SIZE 4000
#define XMPP_CONFIG_MAX_SASLBUF_SIZE 2000
#define XMPP_CONFIG_YXMLBUF_SIZE 2000
#define XMPP_CONFIG_MAX_SASLSCRAM1_ITERS 10000

struct StaticData {
  char in[XMPP_CONFIG_INBUF_SIZE], out[XMPP_CONFIG_OUTBUF_SIZE], saslbuf[XMPP_CONFIG_MAX_SASLBUF_SIZE], xbuf[XMPP_CONFIG_YXMLBUF_SIZE], smackid[XMPP_CONFIG_MAX_SMACKID_SIZE], jid[XMPP_CONFIG_MAX_JID_SIZE+1];
};

#define XMPP_SLICE_XML  0
#define XMPP_SLICE_ATTR 1
#define XMPP_SLICE_CONT 2
#define XMPP_SLICE_B64  3

// TODO: we can remove the type field and each type to a separate struct
// type = XMPP_SLICE_*
// p can be null!
struct xmppXmlSlice {
  int type;
  char *p;
  size_t n, rawn; // TODO: n -> realn, rawn -> n
};

void xmppReadXmlSlice(char *d, struct xmppXmlSlice *s);

// The buffer used is too small. For Format functions this will be the size of the output buffer. For SASL related functions this will be the buffer given to xmppInitSaslContext.
#define XMPP_EMEM -1
// Some input from the input buffer is malformed XML.
#define XMPP_EXML -2
// MbedTls cryptography-related functions failed. (Could also be failed malloc done by MbedTls)
#define XMPP_ECRYPTO -3
// The input buffer end with an incomplete stanza.
#define XMPP_EPARTIAL -4
#define XMPP_ESASLBUF -5
#define XMPP_ENEGOTIATE -6
#define XMPP_ESTATE -7
#define XMPP_EPASS -8
// XML does not follow XMPP spec.
#define XMPP_ESPEC -9
// Resource binding at specified address has not succeeded.
#define XMPP_EBIND -10
#define XMPP_ESKIP -11

// Always emit stanzas (TLS and SASL negotiation not included).
#define XMPP_OPT_EMITSTANZA (1 << 0) 
// Security related:
// By default all connections MUST go over TLS. For SASL, SCRAM is preferred but PLAIN is allowed.
// TLS optional, SCRAM forced.
#define XMPP_OPT_ALLOWUNENCRYPTED (1 << 1)
// No TLS, SCRAM forced.
#define XMPP_OPT_FORCEUNENCRYPTED (1 << 2)
// Force SCRAM, even over TLS.
#define XMPP_OPT_FORCESCRAM (1 << 3)
// Danger zone!!!
// Allow PLAIN SASL, even without TLS.
#define XMPP_OPT_ALLOWUNENCRYPTEDPLAIN (1 << 4)
// Always force PLAIN SASL.
#define XMPP_OPT_FORCEPLAIN (1 << 5)
// End danger zone.
#define XMPP_OPT_DISABLESMACKS (1 << 6)
#define XMPP_OPT_DISABLERESUME (1 << 7)
// Hide presence from other servers/clients by sending
// service-unavailable and not responding to message delivery receipts.
#define XMPP_OPT_HIDEPRESENCE (1 << 8)
// Don't authenticate (for e.g. In-Band Registration).
#define XMPP_OPT_NOAUTH (1 << 9)

// Don't call xmppIterate again.
#define XMPP_ITER_STREAMEND 0
// A stanza was read. You can access the stanza in c->stanza, it will be valid up until the next call of Iterate.
#define XMPP_ITER_STANZA   1
// Data should be sent and received.
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
#define XMPP_ITER_NEGOTIATIONDONE  7
// Nothing should be done, make another call to xmppIterate.
#define XMPP_ITER_OK 8
#define XMPP_ITER_ACK 9

#define XMPP_SASL_INITIALIZED 1
#define XMPP_SASL_CALCULATED 2

#define XMPP_STREAMFEATURE_STARTTLS (1 << 0)
#define XMPP_STREAMFEATURE_BIND (1 << 1)
#define XMPP_STREAMFEATURE_SCRAMSHA1 (1 << 2)
#define XMPP_STREAMFEATURE_SCRAMSHA1PLUS (1 << 3)
#define XMPP_STREAMFEATURE_PLAIN (1 << 4)
#define XMPP_STREAMFEATURE_SMACKS (1 << 5)

#define XMPP_STREAMFEATUREMASK_SASL                                    \
  (XMPP_STREAMFEATURE_SCRAMSHA1 | XMPP_STREAMFEATURE_SCRAMSHA1PLUS |   \
   XMPP_STREAMFEATURE_PLAIN)

#define XMPP_STANZA_EMPTY 0
#define XMPP_STANZA_MESSAGE 1
#define XMPP_STANZA_PRESENCE 2
#define XMPP_STANZA_IQ 3
#define XMPP_STANZA_STREAMFEATURES 4
#define XMPP_STANZA_BINDJID 5
#define XMPP_STANZA_SMACKSENABLED 6
#define XMPP_STANZA_STARTTLSPROCEED 7
#define XMPP_STANZA_ACKANSWER 8
#define XMPP_STANZA_SASLSUCCESS 9
#define XMPP_STANZA_SASLCHALLENGE 10
#define XMPP_STANZA_RESUMED 14
#define XMPP_STANZA_ACKREQUEST 15
#define XMPP_STANZA_FAILURE 16
#define XMPP_STANZA_STREAMEND 17
#define XMPP_STANZA_ERROR 18
#define XMPP_STANZA_STREAM 19

// TODO: remove this
// Any of the child elements can be null.
// We only support a single body, subject, etc. This deviates from the spec.
// It will only read the first instance.
struct xmppMessage {
  struct xmppXmlSlice body, thread, treadparent, subject;
};

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

struct xmppStream {
  int features;
  //int optionalfeatures;
  int requiredfeatures;
  bool hasunknownrequired; // TODO: make this an error?
};

// XML stanza transformed into a C structure.
// raw = full stanza xml
// type = XMPP_STANZA_*
// The associated field is as follows:
//  type = XMPP_STANZA_FAILURE, field = failure
//  type = XMPP_STANZA_BINDJID, field = bindjid
//  etc.
// TODO: implement the above using a modified XML parser.
struct xmppStanza {
  int type;
  struct xmppXmlSlice raw;
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
    struct xmppStream stream;
  };
};

struct xmppJid {
  char *localp, *domainp, *resourcep;
  size_t c;
};

// p is a buffer allocated by a parent as heap or static
// n is length of said buffer
// have max size be influenced by prosody's impl?
// buffer will contain n,, + authmessage + ,p= + clientproofb64
// https://wiki.xmpp.org/web/SASL_Authentication_and_SCRAM#In_detail
// feel free to realloc p if malloc'ed: ctx.p = realloc(ctx.p, (ctx.n*=2))
struct xmppSaslContext {
  int state; // TODO: we might not need this
  char *p;
  size_t n;
  size_t initialmsg;
  size_t serverfirstmsg;
  size_t clientfinalmsg;
  size_t authmsgend;
  size_t end;
  char srvsig[20];
};

// TODO: remove unneeded parts of yxml, dozens of LOC can be removed
// because XMPP only allows subset of XML and the usage here is usecase
// specific. We would also benefit from adding the following states to
// yxml_ret_t: YXML_ATTRSEND (when either / or > is encountered
// inside an element to notify that there will be no more attributes) &
// YXML_CONTENTSTOP (when < is encountered) & possible also
// YXML_CONTENTSTART (when > is encountered).
// skippingdepth: when entering skipping mode (the entire buffer is
// filled without complete stanza), skippingdepth is set to one and
// skipping will start. It is then incremented/decremented according to
// the XML depth until skippingdepth == 0.
//
// When using xmppParser by itself, you must:
// - Initialize x using yxml_init.
// - Call setjmp(jb) before calling xmppParse*. Extracting the setjmp
// into a function will be undefined behaviour.
// - Set p and n to the pointer and length of the XML data respectively.
// All other fields should be zeroed.
struct xmppParser {
  yxml_t x;
  char *xbuf;
  size_t xbufn;
  jmp_buf jb;
  size_t i, n, c;
  char *p;
  int skippingdepth;
};

// i = start of current stanza
// n = size of buffer in p
// c = capacity of buffer in p
struct xmppBuilder {
  char *p;
  size_t i, n, c;
};

// stanza is valid after XMPP_ITER_STANZA and until the next call of
// xmppIterate.
struct xmppClient {
  struct xmppJid jid;
  char *smackid;
  size_t smackidn, smackidc;
  struct xmppSaslContext saslctx;
  struct xmppStanza stanza;
  struct xmppParser parser;
  struct xmppBuilder builder;
  int opts;
  bool isnegotiationdone;
  int state;
  int features;
  int actualsent, actualrecv;
  int sentacks, recvacks;
  bool disablesmack;
  bool cansmackresume;
};

bool StrictStrEqual(const char *c, const char *u, size_t n);

// Only call when XMPP_ITER_ACK
#define xmppIsSynchronized(c) ((c)->stanza.type == XMPP_STANZA_ACKANSWER && (c)->stanza.ack == (c)->actualsent)

#define xmppFormatStanza(c, fmt, ...) (xmppStartStanza(&(c)->builder), xmppAppendXml(&(c)->builder, fmt __VA_OPT__(,) __VA_ARGS__), xmppFlush((c), true))

// TODO: rename to something like xmppAppendXml
void xmppAppendXml(struct xmppBuilder *c, const char *fmt, ...);

static inline void xmppStartStanza(struct xmppBuilder *builder) {
  builder->n = builder->i;
}

static inline int xmppFlush(struct xmppClient *c, bool isstanza) {
  if (isstanza && (c->features & XMPP_STREAMFEATURE_SMACKS))
    xmppAppendXml(&c->builder, "<r xmlns='urn:xmpp:sm:3'/>");
  if (c->parser.n >= c->parser.c) {
    return XMPP_EMEM;
  }
  c->builder.i = c->builder.n;
  if (isstanza && (c->features & XMPP_STREAMFEATURE_SMACKS))
    c->actualsent++;
  return 0;
}

void xmppParseJid(struct xmppJid *jid, char *p, size_t n, const char *s);

/**
 * Initialize XMPP client before iteration.
 *
 * @param jid of the user initiating the XMPP session
 * @param opts zero or more XMPP_OPT_* |'ed
 */
static inline void xmppInitClient(struct xmppClient *c, struct StaticData *d, const char *jid, int opts) {
  memset(c, 0, sizeof(*c));
  c->parser.p = d->in;
  c->parser.c = sizeof(d->in);
  c->parser.xbuf = d->xbuf;
  c->parser.xbufn = sizeof(d->xbuf);
  c->builder.p = d->out;
  c->builder.c = sizeof(d->out);
  c->saslctx.p = d->saslbuf;
  c->saslctx.n = sizeof(d->saslbuf);
  c->smackid = d->smackid;
  c->smackidc = sizeof(d->smackid);
  // TODO: what should we do when we want to register, thus have no JID
  // yet? Only pass the domain?
  xmppParseJid(&c->jid, d->jid, sizeof(d->jid), jid);
  c->opts = opts;
  c->state = 1; // CLIENTSTATE_INIT
}

#define xmppIsInitialized(c) (!!(c)->state)

int xmppIterate(struct xmppClient *c);
int xmppSupplyPassword(struct xmppClient *c, const char *pwd);
void xmppEndStream(struct xmppClient *c);

void xmppParseUnknown(struct xmppParser *p);
bool xmppParseAttribute(struct xmppParser *p, struct xmppXmlSlice *slc);
void xmppParseContent(struct xmppParser *p, struct xmppXmlSlice *slc);
bool xmppParseElement(struct xmppParser *p);

#endif
