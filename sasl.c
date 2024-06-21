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

// p is a buffer allocated by a parent as heap or static
// n is length of said buffer
// buffer will contain n,, + authmessage + temp stuff
// https://wiki.xmpp.org/web/SASL_Authentication_and_SCRAM#In_detail
// feel free to realloc p if malloc'ed
struct xmppSaslContext {
  int fsm;
  char *p;
  size_t n;
  size_t r, s, i;
  char srvsig[20];
};

// n = number of random bytes
// p should be at least twice as big
// doesn't add nul byte
// TODO: use mbedtls random for compat?
// TODO: make this more performant
void FillRandomHex(char *p, size_t n) {
  char b[3];
  getrandom(p, n, 0); // TODO: check error
  while (n--) {
    sprintf(b, "%02x", (unsigned char)p[n]);
    memcpy(p + n*2, b, 2);
  }
}

// TODO: check for ctx->n or SafeStpCpy
void xmppInitSaslContext(struct xmppSaslContext *ctx, char *p, size_t n, const char *user) {
  memset(ctx, sizeof(ctx), 0);
  ctx->p = p;
  ctx->n = n;
  p = stpcpy(p, "n,,n=");
  p = stpcpy(p, user); // TODO: tr username '=' -> '=3D', ',' -> '=2C'
  p = stpcpy(p, ",r=");
  FillRandomHex(p, 32);
  p += 64;
  ctx->fsm = xmppSaslInitialized;
  *p++ = ',';
  ctx->r = p - ctx->p;
}

void xmppFormatSaslInitialMessage(char *p, struct xmppSaslContext *ctx) {
  size_t n;
  p = stpcpy(p, "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='SCRAM-SHA-1'>");
  mbedtls_base64_encode(p, 9001, &n, ctx->p, ctx->r-1); // IDK random value
  stpcpy(p + n, "</auth>");
}

// c = challenge base64, nc = len
// make sure pwd is all printable chars
void xmppSolveSaslChallenge(struct xmppSaslContext *ctx, const char *c, size_t nc, const char *pwd) {
  // assert ctx-fsm == xmppSaslInitialized
  size_t n;
  char *r = ctx->p+ctx->r;
  mbedtls_base64_decode(r, 9001, &n, c, nc); // IDK random value
  for (int i = 0; i < n; i++) {
    if (r[i] == ',') {
      switch (r[i+1]) {
      case 's':
        ctx->s = ctx->r + i + 1;
        break;
      case 'i':
        ctx->i = ctx->r + i + 1;
        break;
      }
    }
  }
  int itrs = atoi(ctx->p+ctx->i+2);
}

void xmppFormatSaslResponse(char *p, struct xmppSaslContect *ctx) {
  p = stpcpy(p, "<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>");
  mbedtls_base64_encode(p, 9001, &n, ctx->p+2, 9001); // IDK random values
  p = stpcpy(p, "</response>");
}

// TODO: use a single buf? mbedtls decode base64 probably allows overlap
// length of s not checked, it's expected that invalid input would
// end with either an unsupported base64 charactor or nul.
// s = success base64 content
int xmppVerifySaslSuccess(struct xmppSaslContext *ctx, const char *s) {
  char b1[30], b2[20];
  size_t n;
  if (mbedtls_base64_decode(b1, 30, &n, s, 40))
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

void H(char k[static 20], const char *pwd, size_t plen, const char *salt, size_t slen, int itrs) {
  mbedtls_md_context_t sha_context;
  mbedtls_md_init(&sha_context);
  printf("H setup: %d\n", mbedtls_md_setup(&sha_context, mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), 1));
  printf("H compute: %d\n", mbedtls_pkcs5_pbkdf2_hmac(&sha_context, pwd, plen, salt, slen, itrs, 20, k));
  mbedtls_md_free(&sha_context);
}

void HMAC(char d[static 20], const char *p, size_t n, const char k[static 20]) {
  printf("md hmac: %d\n", mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), k, 20, p, n, d));
}

void SHA1(char d[static 20], const char p[static 20]) {
  printf("md: %d\n", mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), p, 20, d));
}

void calculate(struct xmppSaslContext *ctx) {
  char saltedpwd[20], clientkey[20],
       storedkey[20], clientsig[20],
       clientproof[20],
       serverkey[20];
  char authmsg[400];
  const char *pwd = "pencil";
  const char *salt = "\x41\x25\xc2\x47\xe4\x3a\xb1\xe9\x3c\x6d\xff\x76";
  int slen = 12;
  int itrs = 4096;
  H(saltedpwd, pwd, strlen(pwd), salt, slen, itrs);
  HMAC(clientkey, "Client Key", 10, saltedpwd);
  SHA1(storedkey, clientkey);
  strcpy(authmsg, "n=user,r=fyko+d2lbbFgONRv9qkxdawL,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096,c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j");
  HMAC(clientsig, authmsg, strlen(authmsg), storedkey);
  for (int i = 0; i < 20; i++)
    clientproof[i] = clientkey[i] ^ clientsig[i];
  HMAC(serverkey, "Server Key", 10, saltedpwd);
  HMAC(ctx->srvsig, authmsg, strlen(authmsg), serverkey);
}

static char buffer[10000], buffer2[1000];
int main() {
  struct xmppSaslContext ctx;
  xmppInitSaslContext(&ctx, buffer2, sizeof(buffer2), "joe");
  memcpy(ctx.srvsig, "\xae\x61\x7d\xa6\xa5\x7c\x4b\xbb\x2e\x02\x86\x56\x8d\xae\x1d\x25\x19\x05\xb0\xa4", 20);
  printf("%d\n", xmppVerifySaslSuccess(&ctx, "dj1ybUY5cHFWOFM3c3VBb1pXamE0ZEpSa0ZzS1E9"));
  //xmppFormatSaslInitialMessage(buffer, &ctx);
  //puts(buffer);
}
