#include <mbedtls/pkcs5.h>
#include <mbedtls/base64.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/random.h>

// mbedtls random source
// https://github.com/Mbed-TLS/mbedtls/blob/2a674bd9ce4758dff0d18f4ac8b6da4419efc504/library/entropy.c#L48
// ESP: https://github.com/espressif/esp-idf/blob/0479494e7abe5aef71393fba2e184b3a78ea488f/components/mbedtls/port/esp_hardware.c#L19

#define xmppSaslInitialized 1

#define xmppMaxJidSize 3071
#define xmppMinMaxStanzaSize 10000

// gets the length of the stanza, sees if stanza is complete
// or is larger than max stanza size
// gets length of content stuffs specific to stanza type
// also store pointer offsets of content or attr strings
// maybe mutate original xml?
struct StanzaParser {
  // yxml_t
  int depth;
};

// p can be null!
struct xmppAttrSlice {
  const char *p;
  size_t n, rawn;
};

struct xmppContentSlice {
  const char *p;
  size_t n, rawn;
};

// if (s.p && (d = malloc(s.n))) xmppReadAttrSlice(d, s);
// TODO: have specific impl for this?
void xmppReadAttrSlice(char *d, struct xmppAttrSlice s) {
  //yxml_t x;
}

struct xmppMessage {
  struct xmppAttrSlice from, to, id;
};

struct xmppStanza {
  int type; // iq/message/presence
  struct xmppAttrSlice id, from, to;
  union {
  };
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
  size_t initialmsg, username, clientnonce;
  size_t serverfirstmsg, servernonce, saltb64;
  size_t clientfinalmsg;
  size_t authmsgend;
  size_t clientproofb64;
  size_t clientfinalmsgend;
  char srvsig[20];
};

// n = number of random bytes
// p should be at least twice as big
// doesn't add nul byte
// TODO: use mbedtls random for compat?
// TODO: make this more performant
// char *FillRandomHex(char *p, char *e)
void FillRandomHex(char *p, size_t n) {
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
  memset(ctx, sizeof(ctx), 0);
  ctx->p = p;
  ctx->n = n;
  p = stpcpy(p, "n,,n=");
  ctx->initialmsg = 3;
  ctx->username = p - ctx->p;
  p = SanitizeSaslUsername(p, user);
  p = stpcpy(p, ",r=");
  ctx->clientnonce = p - ctx->p;
  p = stpcpy(p, "fyko+d2lbbFgONRv9qkxdawL"); // for testing
  //FillRandomHex(p, 32);
  //p += 64;
  ctx->fsm = xmppSaslInitialized;
  *p++ = ',';
  ctx->serverfirstmsg = p - ctx->p;
}

void xmppFormatSaslInitialMessage(char *p, struct xmppSaslContext *ctx) {
  size_t n;
  p = stpcpy(p, "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='SCRAM-SHA-1'>");
  mbedtls_base64_encode(p, 9001, &n, ctx->p, ctx->serverfirstmsg-1); // IDK random value
  stpcpy(p + n, "</auth>");
}

void xmppFormatSaslResponse(char *p, struct xmppSaslContext *ctx) {
  size_t n;
  p = stpcpy(p, "<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>");
  mbedtls_base64_encode(p, 9001, &n, ctx->p+ctx->clientfinalmsg, ctx->clientfinalmsgend-ctx->clientfinalmsg); // IDK random values
  p = stpcpy(p + n, "</response>");
}

// TODO: use a single buf? mbedtls decode base64 probably allows overlap
// length of s not checked, it's expected that invalid input would
// end with either an unsupported base64 charactor or nul.
// s = success base64 content
int xmppVerifySaslSuccess(struct xmppSaslContext *ctx, struct xmppContentSlice s) {
  char b1[30], b2[20];
  size_t n;
  if (mbedtls_base64_decode(b1, 30, &n, s.p, 40)) // TODO: hard code 40 or use s.rawn?
    return 0;
  if (mbedtls_base64_decode(b2, 20, &n, b1+2, 28))
    return 0;
  return !memcmp(ctx->srvsig, b2, 20);
}

void dumphex(const char *p, size_t n) {
  for (int i = 0; i < n; i++)
    printf("%02x", (unsigned char)p[i]);
  puts("");
}

static int H(char k[static 20], const char *pwd, size_t plen, const char *salt, size_t slen, int itrs) {
  mbedtls_md_context_t sha_context;
  mbedtls_md_init(&sha_context);
  printf("H setup: %d\n", mbedtls_md_setup(&sha_context, mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), 1));
  printf("H compute: %d\n", mbedtls_pkcs5_pbkdf2_hmac(&sha_context, pwd, plen, salt, slen, itrs, 20, k));
  mbedtls_md_free(&sha_context);
}

static void HMAC(char d[static 20], const char *p, size_t n, const char k[static 20]) {
  printf("hmac: %d\n", mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), k, 20, p, n, d));
}

static void SHA1(char d[static 20], const char p[static 20]) {
  printf("sha1: %d\n", mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), p, 20, d));
}

static void calculate(struct xmppSaslContext *ctx, char clientproof[static 20], const char *pwd, size_t plen, const char *salt, size_t slen, int itrs) {
  char saltedpwd[20], clientkey[20],
       storedkey[20], clientsig[20],
       serverkey[20];
  H(saltedpwd, pwd, plen, salt, slen, itrs);
  HMAC(clientkey, "Client Key", 10, saltedpwd);
  SHA1(storedkey, clientkey);
  HMAC(clientsig, ctx->p+ctx->initialmsg, ctx->authmsgend-ctx->initialmsg, storedkey);
  for (int i = 0; i < 20; i++)
    clientproof[i] = clientkey[i] ^ clientsig[i];
  HMAC(serverkey, "Server Key", 10, saltedpwd);
  HMAC(ctx->srvsig, ctx->p+ctx->initialmsg, ctx->authmsgend-ctx->initialmsg, serverkey);
}

// c = challenge base64
// make sure pwd is all printable chars
// return something if ctx->n is too small
// return something else if corrupt data
int xmppSolveSaslChallenge(struct xmppSaslContext *ctx, struct xmppContentSlice c, const char *pwd) {
  // assert ctx-fsm == xmppSaslInitialized
  size_t n;
  int itrs = 0;
  char *r = ctx->p+ctx->serverfirstmsg;
  mbedtls_base64_decode(r, 9001, &n, c.p, c.rawn); // IDK random value
  ctx->servernonce = ctx->serverfirstmsg + 2;
  if (strncmp(r, "r=", 2))
    return 1;
  char *s, *i;
  if (!(s = strstr(r+2, ",s="))
   || !(i = strstr(s+3, ",i=")))
    return 1;
  ctx->saltb64 = s-ctx->p + 3;
  itrs = atoi(i+3);
  if (itrs == 0 || itrs > 0xffffff) // errorrrrr, or MAX_ITRS
    return 1;
  r += n;
  *r++ = ',';
  ctx->clientfinalmsg = r - ctx->p;
  r = stpcpy(r, "c=biws,r=");
  size_t nb = ctx->saltb64 - ctx->servernonce - 3;
  memcpy(r, ctx->p+ctx->servernonce, nb);
  r += nb;
  ctx->authmsgend = r - ctx->p;
  mbedtls_base64_decode(r, 9001, &n, s+3, i-s-3); // IDK random value
  char clientproof[20];
  calculate(ctx, clientproof, pwd, strlen(pwd), r, n, itrs);
  r = stpcpy(r, ",p=");
  mbedtls_base64_encode(r, 9001, &n, clientproof, 20); // IDK random value
  ctx->clientfinalmsgend = (r-ctx->p)+n;
  return 0;
}


// minimum maximum stanza size = 10000
static char buffer[xmppMinMaxStanzaSize+1], buffer2[1000];
int main() {
  struct xmppSaslContext ctx;
  xmppInitSaslContext(&ctx, buffer2, sizeof(buffer2), "user");
  xmppFormatSaslInitialMessage(buffer, &ctx);
  printf("initial: %s\n", buffer);
  const char *challenge =  "cj1meWtvK2QybGJiRmdPTlJ2OXFreGRhd0wzcmZjTkhZSlkxWlZ2V1ZzN2oscz1RU1hDUitRNnNlazhiZjkyLGk9NDA5Ng==";
  struct xmppContentSlice c = { .p = challenge, .rawn = strlen(challenge) };
  printf("sasl: %d\n", xmppSolveSaslChallenge(&ctx, c, "pencil"));
  xmppFormatSaslResponse(buffer, &ctx);
  puts(buffer);
  //memcpy(ctx.srvsig, "\xae\x61\x7d\xa6\xa5\x7c\x4b\xbb\x2e\x02\x86\x56\x8d\xae\x1d\x25\x19\x05\xb0\xa4", 20);
  //printf("%d\n", xmppVerifySaslSuccess(&ctx, "dj1ybUY5cHFWOFM3c3VBb1pXamE0ZEpSa0ZzS1E9"));
}
