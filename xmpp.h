#ifndef XMPP_H_
#define XMPP_H_

#include <stddef.h>
#include <stdbool.h>

#define xmppSaslInitialized 1

#define xmppMaxJidSize 3071
#define xmppMinMaxStanzaSize 10000

#define XMPP_ERR_CORRUPT (-1)

// TODO: make isattr an enum which could be either an attribute value,
// content or a slice of XML elements.
// isattr ? attr : content
// p can be null!
struct xmppXmlSlice {
  bool isattr;
  const char *p;
  size_t n, rawn; // TODO: n -> realn, rawn -> n
};

// p is a buffer allocated by a parent as heap or static
// n is length of said buffer
// have max size be influenced by prosody's impl?
// buffer will contain n,, + authmessage + ,p= + clientproofb64
// https://wiki.xmpp.org/web/SASL_Authentication_and_SCRAM#In_detail
// feel free to realloc p if malloc'ed: ctx.p = realloc(ctx.p, (ctx.n*=2))
struct xmppSaslContext {
  int fsm;
  char *p;
  size_t n;
  size_t initialmsg;
  size_t serverfirstmsg;
  size_t clientfinalmsg;
  size_t authmsgend;
  size_t clientfinalmsgend;
  char srvsig[20];
};

//void xmppInitSaslContext(struct xmppSaslContext *ctx, char *p, size_t n, const char *user);
//char *xmppFormatSaslInitialMessage(char *p, char *e, struct xmppSaslContext *ctx);
//int xmppSolveSaslChallenge(struct xmppSaslContext *ctx, struct xmppXmlSlice c, const char *pwd);
//char *xmppFormatSaslResponse(char *p, char *e, struct xmppSaslContext *ctx);
//int xmppVerifySaslSuccess(struct xmppSaslContext *ctx, struct xmppXmlSlice s);

#endif
