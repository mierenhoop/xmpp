#include <mbedtls/pkcs5.h>
#include <stdio.h>
#include <string.h>

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
}

void HMAC(char d[static 20], const char *p, size_t n, const char k[static 20]) {
  printf("md hmac: %d\n", mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), k, 20, p, n, d));
}

void SHA1(char d[static 20], const char p[static 20]) {
  printf("md: %d\n", mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), p, 20, d));
}

int main() {
  char saltedpwd[20], clientkey[20],
       storedkey[20], clientsig[20],
       clientproof[20],
       serverkey[20], serversig[20];
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
  HMAC(serversig, authmsg, strlen(authmsg), serverkey);
}
