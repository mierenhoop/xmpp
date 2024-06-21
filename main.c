#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <stdarg.h>

#include "yxml.h"

#define MAX_BUF 100000

static char rxbuf[MAX_BUF];
static size_t rxbufidx;
static size_t rxbuflen;
static char txbuf[MAX_BUF];

static yxml_t yxml;
static char yxmlbuf[1000];

// SASLprep, don't fully implement it, just take a logical subset
static bool IsPasswordValid(const char *s) {
  for (;*s;s++) {
    if (!isprint(*s))
      return false;
  }
  return true;
}

static char *SafeStpCpy(char *d, char *e, char *s) {
  while (*s && d < e)
    *d++ = *s++;
  return d;
}

static char *EncodeXmlString(char *d, char *e, const char *s) {
  for (;*s && d < e; s++) {
    switch (*s) {
    case '"':
      d = SafeStpCpy(d, e, "&quot;");
      break;
    case '\'':
      d = SafeStpCpy(d, e, "&apos;");
      break;
    case '&':
      d = SafeStpCpy(d, e, "&amp;");
      break;
    case '<':
      d = SafeStpCpy(d, e, "&lt;");
      break;
    case '>':
      d = SafeStpCpy(d, e, "&gt;");
      break;
    default:
      *d++ = *s;
      break;
    }
  }
  return d;
}

// TODO: if buffer fully filled, then probably overflowed, so just return error
static void FormatXml(char *d, size_t n, const char *fmt, ...) {
  va_list ap;
  const char *e = d + n;
  va_start(ap, fmt);
  for (; *fmt && d < e; fmt++) {
    if (*fmt == '%')
      d = EncodeXmlString(d, e, va_arg(ap, const char*));
    else
      *d++ = *fmt;
  }
  va_end(ap);
  if (d < e)
    *d++ = 0;
}

// pwd: Password
// sn: Server Nonce
static void EncryptFromClient(const char *pwd, const char *sn) {
  char buf[200], *p;
  p = stpcpy(buf, "c=biws,r=");
  spycpy(p, sn);
  mbedtls_pbkdf2(ctx, pwd, strlen(pwd), );
}

//static void ExpectTag(const char *tag) {
//  for (; rxbufidx < rxbuflen; rxbufidx++) {
//    switch (yxml_parse(&yxml, rxbuf[rxbufidx])) {
//    case YXML_OK:
//    case YXML_ATTRSTART:
//    case YXML_ATTRVAL:
//    case YXML_ATTREND:
//      break;
//    case YXML_ELEMSTART:
//      if (!strcmp(yxml.elem, tag))
//        goto outer;
//    default:
//      puts("WRONG!!!");
//      return;
//    }
//  }
//outer:
//  puts("All good");
//}

int main() {
  FormatXml(txbuf, "<?xml version='1.0'?>"
      "<stream:stream xmlns='jabber:client'"
      " version='1.0' xmlns:stream='http://etherx.jabber.org/streams'"
      " from='%' to='%' xml:lang='en'>", "joe@localhost", "localhost");

  puts(txbuf);

  strcpy(rxbuf, "<?xml version='1.0'?>"
      "<stream:stream xmlns='jabber:client' id='6af3375c-2170-4c70-8c54-cb5815fba7e2'"
      " from='localhost' xml:lang='en'"
      " xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"
      "<stream:features><register xmlns='http://jabber.org/features/iq-register'/>"
      "<mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
      "<mechanism>SCRAM-SHA-1</mechanism></mechanisms>"
      "<register xmlns='urn:xmpp:invite'/><register xmlns='urn:xmpp:ibr-token:0'/>"
      "</stream:features>");
  rxbuflen = strlen(rxbuf);
  yxml_init(&yxml, yxmlbuf, sizeof(yxmlbuf));

  ExpectTag("stream:stream");
  ExpectTag("stream:features");
  switch (ExpectTag("a:stream:features b:something-else")) {
  case 'a':
    break;
  case 'b':
    break;
  }
}
