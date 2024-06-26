#include <stdio.h>
#include <string.h>

#include "xmpp.h"

// minimum maximum stanza size = 10000
static char buffer[xmppMinMaxStanzaSize+1], buffer2[1000];
int main() {
  char *bufe = buffer + sizeof(buffer);
  struct xmppSaslContext ctx;
  xmppInitSaslContext(&ctx, buffer2, sizeof(buffer2), "user");
  xmppFormatSaslInitialMessage(buffer, bufe, &ctx);
  printf("initial: %s\n", buffer);
  const char *challenge =  "cj1meWtvK2QybGJiRmdPTlJ2OXFreGRhd0wzcmZjTkhZSlkxWlZ2V1ZzN2oscz1RU1hDUitRNnNlazhiZjkyLGk9NDA5Ng==";
  struct xmppXmlSlice c = { .p = challenge, .rawn = strlen(challenge) };
  printf("sasl: %d\n", xmppSolveSaslChallenge(&ctx, c, "pencil"));
  xmppFormatSaslResponse(buffer, &ctx);
  puts(buffer);
  memcpy(ctx.srvsig, "\xae\x61\x7d\xa6\xa5\x7c\x4b\xbb\x2e\x02\x86\x56\x8d\xae\x1d\x25\x19\x05\xb0\xa4", 20);
  c.p =  "dj1ybUY5cHFWOFM3c3VBb1pXamE0ZEpSa0ZzS1E9";
  c.rawn = strlen(c.p);
  printf("%d\n", xmppVerifySaslSuccess(&ctx, c));
}
