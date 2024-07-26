#ifndef XMPP_H_
#define XMPP_H_

#include <stddef.h>
#include <stdbool.h>
#include <setjmp.h>

#include "yxml.h"

#define XMPP_CONFIG_MAX_JID_SIZE 3071
#define XMPP_CONFIG_MAX_STANZA_SIZE 10000
#define XMPP_CONFIG_MAX_SMACKID_SIZE 4000
#define XMPP_CONFIG_MAX_YXMLBUF_SIZE 2000
#define XMPP_CONFIG_MAX_SASLSCRAM1_ITERS 10000

#define XMPP_SLICE_XML  0
#define XMPP_SLICE_ATTR 1
#define XMPP_SLICE_CONT 2
#define XMPP_SLICE_B64  3

// type = XMPP_SLICE_*
// p can be null!
struct xmppXmlSlice {
  int type;
  const char *p;
  size_t n, rawn; // TODO: n -> realn, rawn -> n
};

// The buffer used is too small. For Format functions this will be the size of the output buffer. For SASL related functions this will be the buffer given to xmppInitSaslContext.
#define XMPP_EMEM -1
// Some input from the input buffer is either malformed XML or does not follow the XMPP specification.
#define XMPP_EXML -2
// MbedTls cryptography-related functions failed. (Could also be failed malloc done by MbedTls)
#define XMPP_ECRYPTO -3
// The input buffer end with an incomplete stanza.
#define XMPP_EPARTIAL -4
#define XMPP_ESASLBUF -5
#define XMPP_ENEGOTIATE -6
#define XMPP_ESTATE -7

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

// Nothing should be done, make another call to xmppIterate.
#define XMPP_ITER_OK 0
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
#define XMPP_STANZA_ACKANSWER 8
#define XMPP_STANZA_SASLSUCCESS 9
#define XMPP_STANZA_SASLCHALLENGE 10
#define XMPP_STANZA_DISCOREQ 11
#define XMPP_STANZA_DISCORESP 12
#define XMPP_STANZA_PING 13
#define XMPP_STANZA_RESUMED 14
#define XMPP_STANZA_ACKREQUEST 15

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
  };
};

struct xmppJid {
  size_t localn, domainn, resourcen;
  char local[1024], domain[1024], resource[1024];
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

// i = current end pos of xml
// n = size of buffer in p
// c = capacity of buffer in p
struct xmppXmlComposer {
  char *p;
  size_t n, c;
};

// stanza is valid after XMPP_ITER_STANZA and until the next call of
// xmppIterate.
struct xmppClient {
  struct xmppJid jid;
  char smackid[XMPP_CONFIG_MAX_SMACKID_SIZE+1],
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

static inline int xmppIncrementAck(struct xmppClient *c, int r) {
  if (r)
    return r;
  c->actualsent++;
  return 0;
}

#define xmppFormatStanza(c, fmt, ...) xmppIncrementAck(c, FormatXml(&(c)->comp, fmt "[<r xmlns='urn:xmpp:sm:3'/>]" __VA_OPT__(,)  __VA_ARGS__, ((c)->features & XMPP_STREAMFEATURE_SMACKS)))

int FormatXml(struct xmppXmlComposer *c, const char *fmt, ...);

struct StaticData {
  const char in[1], out[1], sasl[1];
};

void xmppInitClient(struct xmppClient *c, const char *jid, int opts);

static inline void xmppInitStatic(struct xmppClient *c, struct StaticData *d) {
}

int xmppIterate(struct xmppClient *c);
int xmppSupplyPassword(struct xmppClient *c, const char *pwd);
int xmppSendMessage(struct xmppClient *c, const char *to, const char *body);
#endif
