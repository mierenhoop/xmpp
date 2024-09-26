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
// In the case of Prosody, this is always 12 bytes (9 bytes non
// base64-encoded). Even setting this value to 34 would be very
// generous.
#define XMPP_CONFIG_MAX_SMACKID_SIZE 4000
#define XMPP_CONFIG_MAX_SASLBUF_SIZE 2000
#define XMPP_CONFIG_YXMLBUF_SIZE 2000
#define XMPP_CONFIG_MAX_SASLSCRAM1_ITERS 10000

struct StaticData {
  char in[XMPP_CONFIG_INBUF_SIZE], out[XMPP_CONFIG_OUTBUF_SIZE], saslbuf[XMPP_CONFIG_MAX_SASLBUF_SIZE], xbuf[XMPP_CONFIG_YXMLBUF_SIZE], smackid[XMPP_CONFIG_MAX_SMACKID_SIZE], jid[XMPP_CONFIG_MAX_JID_SIZE+1];
};

// p can be null!
struct xmppXmlSlice {
  char *p;
  size_t n, rawn; // TODO: n -> realn, rawn -> n
};

/**
 * Decode a raw XML slice into buffer.
 *
 * Example usage:
 *
 *   char *GetId(struct xmppStanza *stanza) {
 *     char *d = NULL;
 *     if (stanza->id.p && (d = calloc(stanza->id.n + 1)))
 *       xmppReadXmlSlice(d, stanza->id);
 *     return d;
 *   }
 *
 * @param d is the destination buffer
 * @param s is the slice
 */
void xmppReadXmlSlice(char *d, const struct xmppXmlSlice *s);

int xmppDecodeBase64XmlSlice(char *d, size_t *n, const struct xmppXmlSlice *slc);

bool xmppCompareXmlSlice(const char *s, const struct xmppXmlSlice *slc);

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


enum {
  /** Don't call xmppIterate() again */
  XMPP_ITER_STREAMEND = 0,
  /** No action has to be performed, call xmppIterate() again */
  XMPP_ITER_OK,
  /** Data should be sent, @see xmppGetSendBuffer() */
  XMPP_ITER_SEND,
  /** Data should be read, @see xmppGetReceiveBuffer() */
  XMPP_ITER_RECV,
  /** A TLS handshake must be done now */
  XMPP_ITER_STARTTLS,
  /** You should now give the password to advance the SASL negotiation,
     @see xmppSupplyPassword() */
  XMPP_ITER_GIVEPWD,
  /** Stream negotation is complete. You may send new stanzas, but when
     data is available you should read it first. */
  XMPP_ITER_READY,
  /** A stanza was read. You can access the stanza in client->stanza, it
     will be valid up until the next call of Iterate. */
  XMPP_ITER_STANZA,
  /** Our ack request has been answered, you may look at
     client->stanza.ack to see how far the server has caught up. */
  XMPP_ITER_ACK,
};

#define XMPP_STREAMFEATURE_STARTTLS (1 << 0)
#define XMPP_STREAMFEATURE_BIND (1 << 1)
#define XMPP_STREAMFEATURE_SCRAMSHA1 (1 << 2)
#define XMPP_STREAMFEATURE_SCRAMSHA1PLUS (1 << 3)
#define XMPP_STREAMFEATURE_PLAIN (1 << 4)
#define XMPP_STREAMFEATURE_SMACKS (1 << 5)

#define XMPP_STREAMFEATUREMASK_SASL                                    \
  (XMPP_STREAMFEATURE_SCRAMSHA1 | XMPP_STREAMFEATURE_SCRAMSHA1PLUS |   \
   XMPP_STREAMFEATURE_PLAIN)

enum {
  XMPP_STANZA_EMPTY = 0,
  XMPP_STANZA_STREAM,
  XMPP_STANZA_STREAMFEATURES,
  XMPP_STANZA_STARTTLSPROCEED,
  XMPP_STANZA_SASLCHALLENGE,
  XMPP_STANZA_SASLSUCCESS,
  XMPP_STANZA_FAILURE,
  XMPP_STANZA_BINDJID,
  XMPP_STANZA_SMACKSENABLED,
  XMPP_STANZA_RESUMED,
  XMPP_STANZA_ACKREQUEST,
  XMPP_STANZA_ACKANSWER,
  XMPP_STANZA_PRESENCE,
  XMPP_STANZA_MESSAGE,
  XMPP_STANZA_IQ,
  XMPP_STANZA_ERROR,
  XMPP_STANZA_STREAMEND,
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
struct xmppStanza {
  int type;
  struct xmppXmlSlice raw;
  struct xmppXmlSlice id, from, to;
  union {
    struct xmppFailure failure;
    struct xmppXmlSlice saslchallenge;
    struct xmppXmlSlice saslsuccess;
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

// Only call when XMPP_ITER_ACK
#define xmppIsSynchronized(c) ((c)->stanza.type == XMPP_STANZA_ACKANSWER && (c)->stanza.ack == (c)->actualsent)

/**
 * Utility macro for creating and flushing a new stanza
 *
 * @return 0 if successful or XMPP_EMEM if there is not enough capacity
 * @see xmppFlush
 */
#define xmppFormatStanza(c, fmt, ...)                                  \
  (xmppStartStanza(&(c)->builder),                                     \
   xmppAppendXml(&(c)->builder, fmt __VA_OPT__(, ) __VA_ARGS__),       \
   xmppFlush((c), true))

/**
 * Appends a formatted XML string to the builder.
 *
 * @param c is the builder which is already initialized
 * @param fmt is a printf-like format string that only supports the
 * following specifiers:
 * - %s: pointer to nul-string which will be generously escaped (for
 *   attribute and content) TODO: make this %z
 * - %b: base64 representation of raw binary data, the first parameter 
 *   is the length and the second is a pointer to the data
 * - %d: integer (int)
 * - %n: length and pointer to string which will be escaped
 */
void xmppAppendXml(struct xmppBuilder *c, const char *fmt, ...);

/**
 * Setup builder for creating a new stanza
 *
 * Reverts back to last start if no flush was performed.
 */
void xmppStartStanza(struct xmppBuilder *builder);

/**
 * Flush all XML appended after the last start
 *
 * If there is not enough capacity to fit all the previously appended
 * XML, XMPP_EMEM will be returned and the internal buffer will remove
 * all XML after the last xmppStartStanza call.
 *
 * @param isstanza should always be true
 * @return 0 if successful or XMPP_EMEM if there is not enough capacity
 */
int xmppFlush(struct xmppClient *c, bool isstanza);

/**
 * Parse JID string into the xmppJid structure.
 *
 * The structure will be dependent on the lifetime of the buffer
 * specified by p and n.
 *
 * @param jid destination
 * @param p pointer to buffer
 * @param n size of buffer
 * @param s jid in string format
 */
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

// TODO: have these function take Parser and Builder respectively and
// have a separate function for IsTls?

/**
 * Get buffer and maximimum size for receiving data.
 *
 * @param buf (out) buffer in which data will be read, may be NULL
 * @param maxsz (out) maximum amount of data that can be read in buf, may be NULL
 * @param istls (out) is true if data must be received over TLS, may be NULL
 */
void xmppGetReceiveBuffer(const struct xmppClient *client, char **buf,
                          size_t *maxsz, bool *istls);

/**
 * Notify the client that data has been received.
 *
 * @param amount must be less than or equal to the maximum size returned
 * by xmppGetReceiveBuffer
 * @see xmppGetReceiveBuffer()
 */
void xmppAddAmountReceived(struct xmppClient *client, size_t amount);

/**
 * Get buffer and size for data that must be sent.
 *
 * The only logical time this function should be used is after
 * xmppIterate returns XMPP_ITER_SEND. If not all data has been sent in
 * this call, xmppIterate will return XMPP_ITER_SEND again.
 *
 * @param buf (out) buffer in which contains data which needs
 * to be sent, may be NULL
 * @param sz (out) amount of data that must be sent in buf, may be NULL
 * @param istls (out) is true if data must be sent over TLS, may be NULL
 * @see xmppAddAmountSent()
 */
void xmppGetSendBuffer(const struct xmppClient *client, char **buf, size_t *sz, bool *istls);

/**
 * Notify the client that data has been sent.
 *
 * @param amount must be less than or equal to the size returned by
 * xmppGetSendBuffer
 * @see xmppGetSendBuffer()
 */
void xmppAddAmountSent(struct xmppClient *client, size_t amount);

#define xmppIsInitialized(c) (!!(c)->state)

/**
 * Iterate the XMPP client
 *
 * You may only reallocate the in
 * buffer just before or after reading from the network.
 * When the provided SASL password is incorrect, the stream will be
 * closed and if you want to retry you must create a new stream. We
 * could reuse the same stream, but then we either have to keep track of
 * the amount of attempts and other stuff because some servers will let
 * us retry indefinitely and might cause an infinite loop.
 *
 * @return
 *   XMPP_ITER_SEND: the complete out buffer (c->builder.p) with the
 * size specified in (c->builder.n) must be sent over the network before
 * another iteration is done. If c->builder.n is 0, you don't have to
 * write anything. It is recommended that your send function does not
 * block so that you can call Iterate again.
 *   XMPP_E*: and error has occured, you may fix it and call xmppIterate
 *   again.
 */
int xmppIterate(struct xmppClient *c);

/**
 * Supply user's password while negotiating SASL.
 *
 * This function must be used after xmppIterate returns
 * XMPP_ITER_GIVEPWD. It may be called again after an error was
 * returned and that error will potentially be resolved.
 *
 * @return 0 when successful, XMPP_ESTATE when not called after
 * XMPP_ITER_GIVEPWD or XMPP_EMEM or XMPP_ESASLBUF or XMPP_ECRYPTO
 */
int xmppSupplyPassword(struct xmppClient *c, const char *pwd);

/**
 * Gracefully end the XMPP stream.
 *
 * xmppIterate should still be called afterwards. It will return
 * XMPP_ITER_SEND and then XMPP_ITER_STREAMEND.
 */
void xmppEndStream(struct xmppClient *c);

/**
 * Parse an unknown piece of XML up to the end of the most recently
 * parsed element.
 */
void xmppParseUnknown(struct xmppParser *p);

/**
 * Parse an XML attribute into a slice.
 *
 * May only be used after xmppParseElement returns true.
 *
 * @return true if there are more attributes remaining and false if
 * there will be no more attributes
 */
bool xmppParseAttribute(struct xmppParser *p, struct xmppXmlSlice *slc);

/**
 * Parse XML content into a slice.
 *
 * May be used after xmppParseAttribute or after xmppParseElement
 * returns true.
 */
void xmppParseContent(struct xmppParser *p, struct xmppXmlSlice *slc);

/**
 * Parse an XML element.
 *
 * @return true if a new element was parsed or false if the most
 * recently parsed element is closed.
 */
bool xmppParseElement(struct xmppParser *p);

#endif
