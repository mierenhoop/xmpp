#ifndef XMPP_H_
#define XMPP_H_

#include <stddef.h>
#include <stdbool.h>

// TODO: make isattr an enum which could be either an attribute value,
// content or a slice of XML elements.
// isattr ? attr : content
// p can be null!
struct xmppXmlSlice {
  bool isattr;
  const char *p;
  size_t n, rawn; // TODO: n -> realn, rawn -> n
};

//void xmppInitSaslContext(struct xmppSaslContext *ctx, char *p, size_t n, const char *user);
//char *xmppFormatSaslInitialMessage(char *p, char *e, struct xmppSaslContext *ctx);
//int xmppSolveSaslChallenge(struct xmppSaslContext *ctx, struct xmppXmlSlice c, const char *pwd);
//char *xmppFormatSaslResponse(char *p, char *e, struct xmppSaslContext *ctx);
//int xmppVerifySaslSuccess(struct xmppSaslContext *ctx, struct xmppXmlSlice s);

#endif
